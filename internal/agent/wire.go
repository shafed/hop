package agent

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/packet"
	"github.com/shafed/hop/internal/policy"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/tunnel"
)

// Transport — то, что связка знает о привилегированном сервисе.
//
// Интерфейс, а не *ipc.Client, ради одной вещи: превращение ответа сервиса в
// PacketDevice — платформенный код (дескриптор на Unix, труба на Windows), и
// втащив его сюда, связка перестала бы проверяться на трёх ОС без прав. Здесь
// остаётся то, что от платформы не зависит.
type Transport interface {
	// Acquire поднимает туннель и отдаёт устройство.
	Acquire(p tunnel.Params) (packet.PacketDevice, error)
	// Release снимает туннель.
	Release() error
	// Phase — фаза сервиса (§2, tunnel_phase).
	Phase() (tunnel.Phase, error)
	// Lost закрывается, когда связь с сервисом потеряна. Смерть сервиса
	// покрыта T29 и должна быть заметна агенту (Р34).
	Lost() <-chan struct{}
}

// Config — всё, чем связка владеет.
type Config struct {
	Store  *store.Store
	Health *health.Manager
	Trans  Transport
	Params tunnel.Params
	Clock  clock.Clock
	Log    *slog.Logger

	// Resolver — этап 6. nil означает заглушку Р31: SERVFAIL, а не молчание.
	Resolver Resolver
	// Bypass — куда уходит то, что выпущено мимо туннеля (§6.10). Этап 8.
	Bypass netstack.BypassSink
	// NewXray — фабрика инстансов. nil означает настоящий Xray; тесты шагов 3
	// и 4 подставляют фейк, потому что проверяется в них не Xray.
	NewXray xrayFactory
}

// Agent — связка (§3.4).
type Agent struct {
	cfg    Config
	clk    clock.Clock
	log    *slog.Logger
	hm     *health.Manager
	st     *store.Store
	ring   *eventRing
	react  *reactionLog
	engine *holder
	res    Resolver

	mu      sync.Mutex
	up      bool
	bypass  bool
	tphase  tunnel.Phase
	detach  string
	dev     packet.PacketDevice
	stack   *netstack.Stack
	last    health.SwitchEvent
	stackWG sync.WaitGroup

	wg     sync.WaitGroup
	done   chan struct{}
	closed bool
}

// New собирает связку. Ничего не поднимает: Up.
func New(cfg Config) (*Agent, error) {
	if cfg.Store == nil || cfg.Health == nil || cfg.Trans == nil {
		return nil, fmt.Errorf("agent: нужны стор, живость и транспорт")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.NewXray == nil {
		cfg.NewXray = realXray
	}
	res := cfg.Resolver
	if res == nil {
		res = &servfailResolver{}
	}

	a := &Agent{
		cfg:    cfg,
		clk:    cfg.Clock,
		log:    cfg.Log,
		hm:     cfg.Health,
		st:     cfg.Store,
		ring:   newEventRing(),
		react:  &reactionLog{},
		res:    res,
		tphase: tunnel.Down,
		done:   make(chan struct{}),
	}
	// Отказ дозвона до узла приезжает сюда и уходит в живость — через
	// DialError.Report, единственный call-site ReportFailure (§6.15, D10).
	a.engine = newHolder(cfg.Clock, cfg.NewXray, func(de *engine.DialError) {
		de.Report(a.hm)
	})
	return a, nil
}

// Up поднимает туннель и датаплейн.
//
// Синхронна: вернулась — снимок уже новый. То же правило, что у
// health.Manager, и по той же причине: иначе тест ждёт цикл, а пользователь
// получает `status`, отставший от собственной команды.
func (a *Agent) Up() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return fmt.Errorf("agent: закрыт")
	}
	if a.up {
		a.mu.Unlock()
		return nil
	}
	a.mu.Unlock()

	if err := a.reloadNodes(); err != nil {
		return err
	}

	dev, err := a.cfg.Trans.Acquire(a.cfg.Params)
	if err != nil {
		return fmt.Errorf("agent: туннель не поднялся: %w", err)
	}

	stack, err := netstack.New(netstack.Config{
		Device:   dev,
		Dialer:   newDialer(a.hm, a.engine),
		Resolver: a.res,
		Bypass:   a.cfg.Bypass,
		Clock:    a.clk,
		Healthy:  a.hm.Healthy,
	})
	if err != nil {
		_ = a.cfg.Trans.Release()
		return fmt.Errorf("agent: стек не собрался: %w", err)
	}

	a.mu.Lock()
	a.dev, a.stack, a.up = dev, stack, true
	a.detach = ""
	a.mu.Unlock()

	a.stackWG.Add(1)
	go func() {
		defer a.stackWG.Done()
		if err := stack.Run(); err != nil {
			a.log.Error("стек остановился", "err", err)
		}
	}()

	a.refreshPhase()
	return nil
}

// Down снимает датаплейн и туннель. Живость при этом продолжает работать:
// `hop nodes` обязан отвечать и без поднятого туннеля.
func (a *Agent) Down() error {
	a.mu.Lock()
	if !a.up {
		a.mu.Unlock()
		return nil
	}
	stack := a.stack
	a.stack, a.dev, a.up = nil, nil, false
	a.mu.Unlock()

	if stack != nil {
		stack.Close()
	}
	// Release закрывает и устройство: PacketDevice (§3.2) умеет читать, писать
	// и назвать MTU, и не умеет закрываться — им владеет тот, кто его выдал.
	err := a.cfg.Trans.Release()
	a.stackWG.Wait()

	a.refreshPhase()
	return err
}

// Bypass включает и выключает обход (§1/С6).
//
// Включение снимает туннель (Р35): маршруты возвращаются к снапшоту, и трафик
// уходит ядром напрямую. Альтернатива — оставить интерфейс и гнать всё в
// bypass-сокет — означала бы, что весь трафик машины идёт через NAT
// пользовательского процесса (§6.8), который для этого не строился.
func (a *Agent) Bypass(on bool) error {
	a.mu.Lock()
	if a.bypass == on {
		a.mu.Unlock()
		return nil
	}
	a.bypass = on
	a.mu.Unlock()

	if !policy.BypassTeardown.On() {
		// bypass_teardown выключена — туннель остаётся поднятым, и «выпустить
		// трафик напрямую» перестаёт что-либо выпускать: маршруты по-прежнему
		// ведут в туннель. Краснит W25 и W26.
		a.refreshPhase()
		return nil
	}

	var err error
	if on {
		err = a.Down()
	} else {
		err = a.Up()
	}
	a.refreshPhase()
	return err
}

// Pin, Auto — проводка §1/С3 наружу. Живость решает сама; связка только
// пересчитывает фазу, потому что фиксация мёртвого узла меняет её.
func (a *Agent) Pin(nodeID string) error {
	if err := a.hm.Pin(nodeID); err != nil {
		return err
	}
	a.refreshPhase()
	return nil
}

func (a *Agent) Auto(on bool) {
	a.hm.Auto(on)
	a.refreshPhase()
}

// NetworkChanged — форс-проверка на событиях сети (§6.6).
func (a *Agent) NetworkChanged() {
	a.hm.NetworkChanged()
	a.refreshPhase()
}

// ReloadNodes перечитывает узлы из стора: подписка обновилась.
//
// Пересобирает инстанс Xray, если набор изменился, и передаёт новый набор
// живости, которая сохраняет историю оставшихся (§5.8). Порядок именно такой:
// сперва движок — чтобы к моменту, когда живость начнёт пробовать новый узел,
// у него уже был outbound.
func (a *Agent) ReloadNodes() error {
	if err := a.reloadNodes(); err != nil {
		return err
	}
	a.refreshPhase()
	return nil
}

func (a *Agent) reloadNodes() error {
	nodes := a.supportedNodes()

	en := make([]engine.Node, 0, len(nodes))
	hn := make([]health.Node, 0, len(nodes))
	for _, n := range nodes {
		en = append(en, n.ToEngine())
		hn = append(hn, n.ToHealth())
	}

	if err := a.engine.swap(en); err != nil {
		return err
	}
	a.hm.SetNodes(hn)
	return nil
}

// supportedNodes — узлы всех групп, годные для выбора.
//
// Неподдержанные (§6.11) отбрасываются здесь, а не в движке: движок обязан
// падать громко на узле, который до него дошёл, — ошибка там означает ошибку
// того, кто выставил `supported`.
func (a *Agent) supportedNodes() []store.Node {
	var out []store.Node
	for _, g := range a.st.Groups() {
		for _, n := range a.st.Nodes(g.ID) {
			if n.Supported {
				out = append(out, n)
			}
		}
	}
	return out
}

// Start запускает фоновые петли: события живости, сохранение среза, надзор за
// сервисом.
func (a *Agent) Start() {
	a.hm.Start()

	a.wg.Add(3)
	go a.pumpEvents()
	go a.persistHealth()
	go a.watchService()
}

// pumpEvents — реакции на переключение в зафиксированном порядке (Р33).
func (a *Agent) pumpEvents() {
	defer a.wg.Done()

	evs := a.hm.Events()
	for {
		select {
		case <-a.done:
			return
		case ev, ok := <-evs:
			if !ok {
				return
			}
			a.onSwitch(ev)
		}
	}
}

// onSwitch — четыре следствия переключения, и порядок между ними — контракт.
//
//  1. сброс кэша резолвера
//  2. разрыв соединений — только при reason: dead, его делает сама живость
//  3. запись события в кольцо
//  4. сохранение last_switch и среза живости
//
// Первое перед третьим обязательно: клиент, реагирующий на событие повторным
// резолвом, при обратном порядке получит адрес, добытый через мёртвый узел, и
// §5.7(в) окажется выполнен формально. Четвёртое последним: диск не должен
// стоять на пути у первых трёх.
func (a *Agent) onSwitch(ev health.SwitchEvent) {
	a.react.begin()

	ordered := policy.SwitchOrder.On()

	flush := func() {
		if f, ok := a.res.(FlushableResolver); ok {
			f.Flush()
		}
		a.react.mark(reactFlush)
	}
	emit := func() {
		a.ring.push(ev)
		a.react.mark(reactEvent)
	}

	if ordered {
		flush()
	}

	// Разрыв соединений делает живость (§5.5, Interrupt в её конфиге), и к
	// этому моменту он уже случился: событие приходит после. Отмечаем факт,
	// чтобы порядок был наблюдаем целиком.
	if ev.Reason == health.ReasonDead {
		a.react.mark(reactInterrupt)
	}

	emit()

	if !ordered {
		// switch_order выключена — кэш сбрасывается после того, как событие
		// ушло подписчику. Краснит W11 и W13.
		flush()
	}

	a.mu.Lock()
	a.last = ev
	a.mu.Unlock()

	a.persistNow()
	a.react.mark(reactPersist)
	a.refreshPhase()
}

// persistHealth — тикер сохранения среза живости (Р36).
func (a *Agent) persistHealth() {
	defer a.wg.Done()

	t := a.clk.NewTicker(healthPersistEvery)
	defer t.Stop()

	for {
		select {
		case <-a.done:
			return
		case <-t.C():
			a.persistNow()
		}
	}
}

func (a *Agent) persistNow() {
	snap := a.hm.Snapshot()
	a.st.PutHealth(snap.Nodes)
}

// watchService — надзор за сервисом (Р34).
//
// Обрыв управляющего соединения означает, что сервиса не стало: устройство
// мертво, туннеля нет. Агент снимает стек, уходит в failing и показывает
// причину — но не выходит: выход означал бы, что автозапуск §6.13 поднимает
// его в цикле, пока сервис не вернётся, и каждый круг стоит нового процесса.
func (a *Agent) watchService() {
	defer a.wg.Done()

	select {
	case <-a.done:
		return
	case <-a.cfg.Trans.Lost():
	}

	a.mu.Lock()
	a.detach = "связь с сервисом потеряна"
	stack := a.stack
	a.stack, a.dev, a.up = nil, nil, false
	a.mu.Unlock()

	if stack != nil {
		stack.Close()
	}
	// Release здесь почти наверняка откажет — сервиса нет, — и это законно:
	// вместе с ним ушло и устройство, и маршруты (T29).
	_ = a.cfg.Trans.Release()
	a.log.Warn("сервис пропал, туннель снят", "phase", "failing")
	a.refreshPhase()
}

// refreshPhase пересчитывает фазу туннеля по сервису. Фаза трафика считается
// на лету в Snapshot: она — функция от живости, и кэшировать её значило бы
// заводить второй источник правды.
func (a *Agent) refreshPhase() {
	ph := tunnel.Down
	if p, err := a.cfg.Trans.Phase(); err == nil {
		ph = p
	}
	a.mu.Lock()
	a.tphase = ph
	a.mu.Unlock()
}

// trafficPhase — §2. Чистая функция от трёх наблюдений, а не от полей: иначе
// фаза стала бы вторым источником правды о живости и разъехалась бы с первым.
//
// Живость спрашивается **до** взятия замка агента: у неё свой замок, и брать
// два в разном порядке в разных местах — заготовка взаимной блокировки.
func trafficPhase(bypass, up, healthy bool, active string) TrafficPhase {
	switch {
	case bypass:
		return PhaseBypass
	case !up:
		return PhaseFailing
	case active != "":
		return PhaseProxied
	case healthy:
		// Healthy() без активного узла — это стартовое окно §5.6: ни один узел
		// ещё не проверен. Незнание, а не отказ, и показывать их одинаково
		// нельзя.
		return PhaseWaiting
	default:
		return PhaseFailing
	}
}

// Snapshot — всё наблюдаемое состояние одним значением (§2 регистра).
func (a *Agent) Snapshot() Snapshot {
	hs := a.hm.Snapshot()
	healthy := a.hm.Healthy()

	a.mu.Lock()
	s := Snapshot{
		Tunnel:   a.tphase,
		Traffic:  trafficPhase(a.bypass, a.up, healthy, hs.Active),
		Active:   hs.Active,
		Last:     a.last,
		Auto:     hs.Auto,
		Rebuilds: a.engine.rebuildCount(),
		Detached: a.detach,
		Nodes:    hs.Nodes,
	}
	a.mu.Unlock()

	if !policy.PhaseSplit.On() {
		// phase_split выключена — одна фаза вместо двух, как было до §2/D14:
		// фаза трафика затирает фазу туннеля, и «туннель поднят, живых узлов
		// нет» перестаёт быть выразимым. Краснит W24 и W32.
		if s.Traffic == PhaseFailing || s.Traffic == PhaseBypass {
			s.Tunnel = tunnel.Phase(s.Traffic)
		}
		s.Traffic = ""
	}
	return s
}

// Events отдаёт накопленное кольцо и подписку на будущее — одним вызовом
// (§2 регистра): двумя было бы окно, в котором событие уже не в истории и ещё
// не в канале.
func (a *Agent) Events(buf int) ([]health.SwitchEvent, <-chan health.SwitchEvent) {
	return a.ring.subscribe(buf)
}

func (a *Agent) Unsubscribe(c <-chan health.SwitchEvent) { a.ring.unsubscribe(c) }

// History — только накопленное.
func (a *Agent) History() []health.SwitchEvent { return a.ring.history() }

// WaitRebuild ждёт n-й пересборки инстанса Xray.
func (a *Agent) WaitRebuild(n uint64) { a.engine.waitRebuild(n) }

// Reactions — порядок реакций на последнее переключение (Р33, W11).
func (a *Agent) Reactions() []string {
	rs := a.react.order()
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.String())
	}
	return out
}

// Close снимает всё. Дренаж на выходе не ждётся: снятие агента и есть разрыв
// всего, а тридцать секунд ожидания на выходе хуже обрыва.
func (a *Agent) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	close(a.done)
	a.mu.Unlock()

	err := a.Down()

	a.hm.Close()
	a.wg.Wait()
	a.engine.close()
	a.ring.closeAll()

	if ferr := a.st.Flush(); ferr != nil && err == nil {
		err = ferr
	}
	return err
}

// Активный узел связке отдаёт живость, а не наоборот: picker удовлетворяет
// *health.Manager, и диалер обращается прямо к нему.
var _ picker = (*health.Manager)(nil)
