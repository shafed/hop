package agent

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/policy"
)

// xray — то, что связке нужно от движка. Интерфейс, а не *engine.Engine,
// по одной причине: поднять настоящий Xray стоит секунд, а проверяется в шагах
// 3 и 4 регистра не Xray, а наша арифметика владения инстансами.
//
// `*engine.Engine` удовлетворяет ему как есть.
type xray interface {
	DialTCP(ctx context.Context, nodeID, addr string) (net.Conn, error)
	DialUDP(ctx context.Context, nodeID string) (net.PacketConn, error)
	Close() error
}

// xrayFactory поднимает инстанс на набор узлов. Отказ дозвона до узла уходит в
// onFailure — и это единственный путь до health.ReportFailure (§6.15, D10).
type xrayFactory func(nodes []engine.Node, onFailure func(*engine.DialError)) (xray, error)

// realXray — фабрика поверх настоящего движка.
func realXray(nodes []engine.Node, onFailure func(*engine.DialError)) (xray, error) {
	return engine.NewWithConfig(engine.Config{Nodes: nodes, OnFailure: onFailure})
}

// instance — один инстанс Xray и счётчик выданных им незакрытых соединений.
//
// Счётчик нужен дренажу (Р32): инстанс держат, пока через него кто-то говорит,
// но не дольше потолка §5.8. Один таймер без счётчика держал бы полные тридцать
// секунд и там, где последнее соединение закрылось на второй; один счётчик без
// таймера не кончился бы никогда на соединении, которое никто не закрывает.
type instance struct {
	x    xray
	fp   string // отпечаток набора узлов, см. fingerprint
	live atomic.Int64
	// idle закрывается, когда live впервые доходит до нуля после того, как
	// инстанс отправлен в дренаж.
	idle     chan struct{}
	idleOnce sync.Once
	draining atomic.Bool
}

func (in *instance) acquire() { in.live.Add(1) }

func (in *instance) release() {
	if in.live.Add(-1) == 0 && in.draining.Load() {
		in.idleOnce.Do(func() { close(in.idle) })
	}
}

// startDrain помечает инстанс дренируемым. Проверка счётчика сразу после
// пометки обязательна: последнее соединение могло закрыться между swap и этой
// строкой, и тогда закрывать idle было бы уже некому.
func (in *instance) startDrain() {
	in.draining.Store(true)
	if in.live.Load() == 0 {
		in.idleOnce.Do(func() { close(in.idle) })
	}
}

// holder — текущий инстанс плюс те, что дренируются.
//
// Смысл всей конструкции — §5.5: обновление подписки не является причиной
// `dead`, значит рвать из-за него соединения нельзя. Новые дозвоны идут в новый
// инстанс, старые доживают в своём.
type holder struct {
	clk   clock.Clock
	newFn xrayFactory
	onErr func(*engine.DialError)

	mu       sync.RWMutex
	cur      *instance
	draining map[*instance]struct{}

	rebuilds atomic.Uint64
	// rebuilt закрывается и пересоздаётся на каждой пересборке — по нему ждёт
	// WaitRebuild. Канал, а не sync.Cond: ждущему нужен и таймаут теста.
	rebuiltMu sync.Mutex
	rebuilt   chan struct{}

	drainWG sync.WaitGroup
	closed  atomic.Bool
}

func newHolder(clk clock.Clock, newFn xrayFactory, onErr func(*engine.DialError)) *holder {
	return &holder{
		clk:      clk,
		newFn:    newFn,
		onErr:    onErr,
		draining: make(map[*instance]struct{}),
		rebuilt:  make(chan struct{}),
	}
}

// swap ставит инстанс на новый набор узлов и отправляет прежний в дренаж.
//
// Набор, совпавший с текущим, не пересобирает ничего: автообновление подписки
// по таймеру иначе пересобирало бы Xray каждый тик, ничего при этом не меняя, —
// самый дешёвый способ незаметно нарушить §5.5 (W22).
func (h *holder) swap(nodes []engine.Node) error {
	if h.closed.Load() {
		return fmt.Errorf("agent: движок уже закрыт")
	}
	fp := fingerprint(nodes)

	h.mu.RLock()
	same := h.cur != nil && h.cur.fp == fp
	h.mu.RUnlock()
	if same {
		return nil
	}

	x, err := h.newFn(nodes, h.onErr)
	if err != nil {
		return fmt.Errorf("agent: инстанс Xray не собрался: %w", err)
	}
	next := &instance{x: x, fp: fp, idle: make(chan struct{})}

	h.mu.Lock()
	prev := h.cur
	h.cur = next
	if prev != nil {
		h.draining[prev] = struct{}{}
	}
	h.mu.Unlock()

	if prev != nil {
		if !policy.XrayDrain.On() {
			// xray_drain выключена — прежний инстанс закрывается здесь же,
			// синхронно, и соединения через него рвутся на обновлении подписки
			// вопреки §5.5. Именно синхронно, а не горутиной: «дренажа нет»
			// должно означать «к возврату из swap всё уже кончено», иначе
			// охраняющая проверка зеленеет по расписанию планировщика, а не по
			// существу. Краснит W18, W20, W21.
			h.finishDrain(prev)
		} else {
			// Таймер заводится здесь, синхронно, а не внутри горутины дренажа:
			// иначе потолок §5.8 отсчитывается не от смены набора, а от того
			// момента, когда планировщик доберётся до горутины. На настоящих
			// часах это незаметная неточность, на фейковых — неопределённость.
			h.drainWG.Add(1)
			go h.drain(prev, h.clk.After(drainTimeout))
		}
	}

	h.rebuilds.Add(1)
	h.rebuiltMu.Lock()
	close(h.rebuilt)
	h.rebuilt = make(chan struct{})
	h.rebuiltMu.Unlock()
	return nil
}

// drain держит прежний инстанс, пока через него кто-то говорит, но не дольше
// потолка §5.8. Оба исхода законны, и разница между ними видна только в том,
// оборвалось ли чьё-то соединение.
func (h *holder) drain(in *instance, ceiling <-chan time.Time) {
	defer h.drainWG.Done()

	in.startDrain()
	select {
	case <-in.idle:
	case <-ceiling:
	}
	h.finishDrain(in)
}

// finishDrain закрывает инстанс и снимает его с учёта.
func (h *holder) finishDrain(in *instance) {
	_ = in.x.Close()

	h.mu.Lock()
	delete(h.draining, in)
	h.mu.Unlock()
}

// current отдаёт инстанс, которому принадлежат новые дозвоны.
func (h *holder) current() *instance {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cur
}

func (h *holder) rebuildCount() uint64 { return h.rebuilds.Load() }

// liveInstances — сколько инстансов держится одновременно. Нужно W23.
func (h *holder) liveInstances() int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	n := len(h.draining)
	if h.cur != nil {
		n++
	}
	return n
}

// waitRebuild ждёт, пока число пересборок не достигнет n.
//
// Без него У4 проверяется сном, а сон в тесте — либо флейк, либо потерянная
// секунда на каждом прогоне (§2 регистра).
func (h *holder) waitRebuild(n uint64) {
	for {
		if h.rebuilds.Load() >= n {
			return
		}
		h.rebuiltMu.Lock()
		ch := h.rebuilt
		h.rebuiltMu.Unlock()

		if h.rebuilds.Load() >= n {
			return
		}
		<-ch
	}
}

func (h *holder) close() {
	if h.closed.Swap(true) {
		return
	}
	h.mu.Lock()
	cur := h.cur
	h.cur = nil
	drain := make([]*instance, 0, len(h.draining))
	for in := range h.draining {
		drain = append(drain, in)
	}
	h.mu.Unlock()

	// Close не дренирует: снятие агента — это и есть разрыв всего, и ждать
	// тридцать секунд на выходе было бы хуже, чем оборвать.
	for _, in := range drain {
		in.idleOnce.Do(func() { close(in.idle) })
	}
	h.drainWG.Wait()
	if cur != nil {
		_ = cur.x.Close()
	}
}

// countedConn — соединение, которое сообщает инстансу о своём закрытии.
type countedConn struct {
	net.Conn
	in   *instance
	once sync.Once
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.in.release)
	return err
}

// countedPacketConn — то же для UDP.
type countedPacketConn struct {
	net.PacketConn
	in   *instance
	once sync.Once
}

func (c *countedPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.once.Do(c.in.release)
	return err
}

// fingerprint — отпечаток набора узлов.
//
// Считается по всему, что влияет на построенный outbound, и не зависит ни от
// порядка узлов, ни от порядка ключей в params: обе перестановки законны и
// пересборкой быть не должны. Порядок узлов в подписке — дело `node_order`
// (Р8 регистра стора), а не движка.
func fingerprint(nodes []engine.Node) string {
	parts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		keys := make([]string, 0, len(n.Params))
		for k := range n.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var b []byte
		b = append(b, n.ID...)
		b = append(b, 0, byte('|'))
		b = append(b, n.Protocol...)
		b = append(b, 0)
		b = append(b, n.Server...)
		b = append(b, 0)
		b = append(b, strconv.Itoa(n.Port)...)
		b = append(b, 0)
		b = append(b, n.Transport...)
		b = append(b, 0)
		b = append(b, n.Security...)
		for _, k := range keys {
			b = append(b, 0)
			b = append(b, k...)
			b = append(b, '=')
			b = append(b, n.Params[k]...)
		}
		parts = append(parts, string(b))
	}
	sort.Strings(parts)

	h := sha256.New()
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(parts)))
	h.Write(n[:])
	for _, p := range parts {
		binary.LittleEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write([]byte(p))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
