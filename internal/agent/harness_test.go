package agent

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/packet"
	"github.com/shafed/hop/internal/packettest"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/tunnel"
)

// Стенд связки. Настоящих Xray и TUN здесь нет намеренно: шаги 3–6 регистра
// проверяют арифметику владения и порядок реакций, а не Xray. Сквозной путь
// через настоящий VLESS — отдельные тесты, они дороже на два порядка.

// fakeTransport — сервис за интерфейсом.
type fakeTransport struct {
	mu       sync.Mutex
	dev      *packettest.FakeDevice
	phase    tunnel.Phase
	acquired int
	released int
	lost     chan struct{}
	failNext error
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{phase: tunnel.Down, lost: make(chan struct{})}
}

func (f *fakeTransport) Acquire(tunnel.Params) (packet.PacketDevice, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return nil, err
	}
	f.acquired++
	f.dev = packettest.NewFake(1400)
	f.phase = tunnel.Up
	return f.dev, nil
}

func (f *fakeTransport) Release() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released++
	f.phase = tunnel.Down
	if f.dev != nil {
		f.dev.Close()
		f.dev = nil
	}
	return nil
}

func (f *fakeTransport) Phase() (tunnel.Phase, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.phase, nil
}

func (f *fakeTransport) Lost() <-chan struct{} { return f.lost }

func (f *fakeTransport) die() { close(f.lost) }

func (f *fakeTransport) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.acquired, f.released
}

// fakeXray — инстанс движка. Считает выданные соединения и умеет сказать, был
// ли закрыт: на этом держатся W20, W21 и W23.
type fakeXray struct {
	nodes  []engine.Node
	closed atomic.Bool
	dials  atomic.Int64

	mu    sync.Mutex
	conns []net.Conn
}

func (f *fakeXray) DialTCP(_ context.Context, _, _ string) (net.Conn, error) {
	if f.closed.Load() {
		return nil, errors.New("fakeXray: инстанс закрыт")
	}
	f.dials.Add(1)
	c, peer := net.Pipe()
	// Дальний конец держится открытым, иначе запись в c упрётся в закрытую
	// трубу и «соединение живо» перестанет быть наблюдаемым.
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
		}
	}()
	f.mu.Lock()
	f.conns = append(f.conns, c)
	f.mu.Unlock()
	return c, nil
}

func (f *fakeXray) DialUDP(_ context.Context, _ string) (net.PacketConn, error) {
	if f.closed.Load() {
		return nil, errors.New("fakeXray: инстанс закрыт")
	}
	f.dials.Add(1)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	return pc, err
}

// Close закрывает и выданные соединения: смерть инстанса Xray уносит их с
// собой, и проверка §5.5 должна смотреть на соединение, а не на флаг.
func (f *fakeXray) Close() error {
	f.closed.Store(true)
	f.mu.Lock()
	conns := f.conns
	f.conns = nil
	f.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	return nil
}

// xrayLog — все поднятые инстансы по порядку.
type xrayLog struct {
	mu   sync.Mutex
	made []*fakeXray
}

func (l *xrayLog) factory() xrayFactory {
	return func(nodes []engine.Node, _ func(*engine.DialError)) (xray, error) {
		x := &fakeXray{nodes: nodes}
		l.mu.Lock()
		l.made = append(l.made, x)
		l.mu.Unlock()
		return x, nil
	}
}

func (l *xrayLog) at(i int) *fakeXray {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i < 0 || i >= len(l.made) {
		return nil
	}
	return l.made[i]
}

func (l *xrayLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.made)
}

// scriptProber — исход пробы задаётся тестом на узел.
type scriptProber struct {
	mu  sync.Mutex
	res map[string]health.Result
	def health.Result
}

func newScriptProber() *scriptProber {
	return &scriptProber{
		res: map[string]health.Result{},
		def: health.Result{RTT: 10 * time.Millisecond},
	}
}

func (p *scriptProber) set(nodeID string, r health.Result) {
	p.mu.Lock()
	p.res[nodeID] = r
	p.mu.Unlock()
}

func (p *scriptProber) Probe(_ context.Context, nodeID string) health.Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r, ok := p.res[nodeID]; ok {
		return r
	}
	return p.def
}

// countingResolver — резолвер, считающий сбросы кэша. Нужен W13.
type countingResolver struct {
	servfailResolver
	onFlush func()
}

func (r *countingResolver) Flush() {
	r.servfailResolver.Flush()
	if r.onFlush != nil {
		r.onFlush()
	}
}

// rig — собранный стенд.
type rig struct {
	t     *testing.T
	a     *Agent
	tr    *fakeTransport
	hm    *health.Manager
	st    *store.Store
	clk   *clock.Fake
	xrays *xrayLog
	prob  *scriptProber
	res   *countingResolver
	inter atomic.Int64
}

// newRig собирает связку на фейках. nodes — id узлов, все supported.
func newRig(t *testing.T, nodes ...string) *rig {
	t.Helper()

	clk := clock.NewFake(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	st, err := store.Open(t.TempDir(), clk)
	if err != nil {
		t.Fatalf("стор не открылся: %v", err)
	}

	prob := newScriptProber()
	r := &rig{t: t, tr: newFakeTransport(), st: st, clk: clk,
		xrays: &xrayLog{}, prob: prob, res: &countingResolver{}}

	// Живость заводится пустой, а узлы кладутся в стор: путь из стора в
	// живость — настоящий (`Up` его и проходит), и стенд, засевающий живость
	// напрямую, проверял бы конструкцию, которой в продукте нет.
	r.hm = health.New(health.Config{
		Clock:     clk,
		Prober:    prob,
		Interrupt: func() int { return int(r.inter.Add(1)) },
	})

	a, err := New(Config{
		Store:    st,
		Health:   r.hm,
		Trans:    r.tr,
		Clock:    clk,
		Resolver: r.res,
		NewXray:  r.xrays.factory(),
		Params:   tunnel.Params{Name: "hop0", MTU: 1400, Addr: "10.255.0.1/24", Table: 8420},
	})
	if err != nil {
		t.Fatalf("связка не собралась: %v", err)
	}
	r.a = a
	t.Cleanup(func() { _ = a.Close() })

	if len(nodes) > 0 {
		r.seedStore("g1", nodes...)
		// Живость получает их тем же путём, что в продукте: через связку.
		if err := a.ReloadNodes(); err != nil {
			t.Fatalf("узлы не доехали из стора в живость: %v", err)
		}
	}
	return r
}

// seedStore кладёт узлы в стор — для тестов, идущих через ReloadNodes.
func (r *rig) seedStore(groupID string, ids ...string) {
	r.t.Helper()

	nodes := make([]store.Node, 0, len(ids))
	order := make([]string, 0, len(ids))
	for _, id := range ids {
		nodes = append(nodes, store.Node{
			ID: id, GroupID: groupID, Protocol: "vless",
			Server: id + ".example", Port: 443, Transport: "raw",
			Security: "none", Supported: true,
			Params: map[string]string{"uuid": "u-" + id},
		})
		order = append(order, id)
	}
	if err := r.st.Apply(groupID, store.Merged{
		Added: order, Nodes: nodes, Order: order,
	}); err != nil {
		r.t.Fatalf("стор не принял узлы: %v", err)
	}
}

// watchdog — потолок ожидания раунда. Без него несостоявшийся раунд вешает
// прогон вместо того, чтобы покраснеть; ровно тот же приём в стенде этапа 5.
const watchdog = 10 * time.Second

// waitRound ждёт завершения раунда n и падает, а не виснет.
func (r *rig) waitRound(n uint64) {
	r.t.Helper()

	done := make(chan struct{})
	go func() { r.hm.WaitRound(n); close(done) }()
	select {
	case <-done:
	case <-time.After(watchdog): //hop:realtime
		r.t.Fatalf("раунд %d не наступил", n)
	}
}

// start запускает связку и дожидается стартового обхода.
//
// Дожидается обязательно: Start назначает все узлы на now, поэтому первый
// раунд идёт немедленно и в своей горутине. Проверка состояния без этого
// ожидания сравнивает снимок с гонкой, а не с ожиданием.
func (r *rig) start() {
	r.t.Helper()
	r.a.Start()
	r.waitRound(1)
}

// runRound двигает часы и ждёт очередного раунда. Порядок — как в стенде
// этапа 5: номер снимается до сдвига часов.
func (r *rig) runRound() {
	r.t.Helper()
	before := r.hm.Snapshot().Round
	// Шаг — по ярусу кандидатов, а не активного узла: узел, ещё не ставший
	// активным, назначается на 60 с (§6.5), и сдвиг на 20 с его пробу не
	// доводит. Больший шаг может задеть несколько ярусов сразу — это законно,
	// ждём мы «хотя бы следующий раунд», а не ровно один.
	r.clk.Advance(health.DefaultCandidateInterval)
	r.waitRound(before + 1)
}

// killAll гоняет раунды, пока перечисленные узлы не станут dead.
//
// По состоянию, а не по числу раундов: умерший узел уезжает в хвост §6.5
// (1800 с), и после этого сдвиг на ярус кандидатов раунда уже не вызывает —
// счётчик раундов повис бы, а проверка состояния кончается вовремя. Приём взят
// из стенда этапа 5, где он ровно за этим и появился.
func (r *rig) killAll(ids ...string) {
	r.t.Helper()

	for i := 0; i < 3*len(ids)+3; i++ {
		allDead := true
		for _, id := range ids {
			h, ok := r.hm.Snapshot().Node(id)
			if !ok || h.State != health.Dead {
				allDead = false
			}
		}
		if allDead {
			return
		}
		r.runRound()
	}
	r.t.Fatalf("узлы %v не умерли за отведённые раунды", ids)
}
