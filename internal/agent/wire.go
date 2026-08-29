package agent

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/shafed/hop/internal/bypass"
	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/packet"
	"github.com/shafed/hop/internal/policy"
	"github.com/shafed/hop/internal/resolver"
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
	// Physical resolves the physical default interface for sockets Xray opens
	// to nodes (§6.8). It is consulted for every new socket.
	Physical engine.InterfaceFunc

	// Resolver — подставить готовый резолвер вместо собираемого связкой.
	// Тесты этапа С подставляют сюда заглушку; в продукте поле пустое, и
	// связка собирает настоящий резолвер §5.7 сама.
	Resolver Resolver
	// DNSUpstreams — §5.7. Пусто означает стартовые 1.1.1.1:53 и 8.8.8.8:53.
	DNSUpstreams []netip.AddrPort
	// DialDirect — путь мимо туннеля (§6.8): им ходят bootstrap и
	// перехваченный DNS в фазе bypass. Даётся снаружи, потому что привязка
	// сокета к физическому интерфейсу — платформенный код, живущий в
	// internal/outbound. nil означает, что настоящий резолвер не собирается:
	// без прямого пути bootstrap даёт петлю §5.7(а).
	DialDirect resolver.DialDirectFunc
	// Routing — списки §6.10, из которых netstack берёт вердикт bypass/block.
	// nil означает умолчания §6.10; исключения §5.6 остаются в силе при любом
	// непустом списке (netstack.DefaultRouting, resolveRouting). Ровно как
	// DNSUpstreams: поле конфигурации связки есть, CLI и диск до него ещё не
	// доросли.
	Routing *netstack.Routing
	// Bypass — куда уходит то, что выпущено мимо туннеля (§6.10). Этап 8.
	Bypass netstack.BypassSink
	// BypassControl — привязка сокетов bypass к физическому интерфейсу (§6.8).
	// nil означает, что настоящий приёмник не собирается и вердикт bypass
	// остаётся дропом; в продукте сюда приходит outbound.Selector.Control.
	// Config.Bypass старше: он остаётся подстановкой для тестов, ровно как
	// Config.Resolver старше собираемого связкой резолвера.
	BypassControl bypass.ControlFunc
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

	// dns — настоящий резолвер §5.7, если связка его собрала. Отдельно от res:
	// res — то, что видит netstack, а по dns связка кормит подписку и ждёт
	// подтверждения сброса.
	dns       *resolver.Resolver
	boot      *resolver.Bootstrap
	dnsEvents chan health.SwitchEvent
	dnsAcked  chan struct{}

	mu     sync.Mutex
	up     bool
	bypass bool
	tphase tunnel.Phase
	detach string
	dev    packet.PacketDevice
	stack  *netstack.Stack
	// bypassNAT — настоящий приёмник bypass §6.10, собранный связкой (когда
	// Config.Bypass пуст, а Config.BypassControl задан). Живёт ровно как
	// стек: заводится в Up, закрывается там же, где стек — в Down и
	// watchService, — переживший Down приёмник унёс бы с собой сокеты,
	// привязанные к прежнему физическому интерфейсу.
	bypassNAT *bypass.NAT
	last      health.SwitchEvent
	stackWG   sync.WaitGroup

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
		cfg.NewXray = func(nodes []engine.Node, onFailure func(*engine.DialError)) (xray, error) {
			return engine.NewWithConfig(engine.Config{
				Nodes: nodes, OnFailure: onFailure, Physical: cfg.Physical,
			})
		}
	}

	a := &Agent{
		cfg:    cfg,
		clk:    cfg.Clock,
		log:    cfg.Log,
		hm:     cfg.Health,
		st:     cfg.Store,
		ring:   newEventRing(),
		react:  &reactionLog{},
		tphase: tunnel.Down,
		done:   make(chan struct{}),
	}
	// Отказ дозвона до узла приезжает сюда и уходит в живость — через
	// DialError.Report, единственный call-site ReportFailure (§6.15, D10).
	a.engine = newHolder(cfg.Clock, cfg.NewXray, func(de *engine.DialError) {
		de.Report(a.hm)
	})

	if err := a.buildResolver(); err != nil {
		return nil, err
	}
	return a, nil
}

// Стартовые апстримы §5.7. Настраиваются, но умолчание названо в спеке.
var defaultUpstreams = []netip.AddrPort{
	netip.MustParseAddrPort("1.1.1.1:53"),
	netip.MustParseAddrPort("8.8.8.8:53"),
}

// buildResolver собирает перехваченный DNS §5.7.
//
// Три провода, и каждый ведёт в своё место. Путь наверх — через активный узел,
// тем же движком, что носит трафик. Прямой путь — мимо туннеля, и его связка
// не строит сама: привязка сокета к физическому интерфейсу платформенна и
// живёт в internal/outbound. Фаза — функцией, а не битом Healthy: waiting,
// failing и bypass суть три разных ответа резолвера, и свести их к одному биту
// нельзя.
//
// Подписка на события отдаётся резолверу, а сброс кэша делает он сам (§5.7).
// Связка только дожидается подтверждения — Р33 требует, чтобы кэш был выкинут
// раньше, чем событие ушло наружу.
func (a *Agent) buildResolver() error {
	if a.cfg.Resolver != nil {
		a.res = a.cfg.Resolver
		return nil
	}
	if a.cfg.DialDirect == nil {
		// Прямого пути нет — настоящий резолвер собирать нельзя: bootstrap без
		// него даёт петлю §5.7(а), а тихо ходить за именами узлов через
		// туннель хуже, чем честно отказывать (Р31 заглушки).
		a.res = &servfailResolver{}
		return nil
	}

	ups := a.cfg.DNSUpstreams
	if len(ups) == 0 {
		ups = defaultUpstreams
	}

	d := newDialer(a.hm, a.engine)
	a.dnsEvents = make(chan health.SwitchEvent)
	a.dnsAcked = make(chan struct{}, 1)

	r, err := resolver.New(resolver.Config{
		Upstreams:  ups,
		DialUDP:    d.resolverDialUDP,
		Dial:       d.resolverDialTCP,
		DialDirect: a.cfg.DialDirect,
		Phase:      a.trafficPhaseNow,
		Events:     a.dnsEvents,
		Acked:      func() { a.dnsAcked <- struct{}{} },
		Clock:      a.clk,
	})
	if err != nil {
		return fmt.Errorf("agent: резолвер не собрался: %w", err)
	}
	b, err := resolver.NewBootstrap(resolver.BootstrapConfig{
		Upstreams:  ups,
		DialDirect: a.cfg.DialDirect,
		Clock:      a.clk,
	})
	if err != nil {
		return fmt.Errorf("agent: bootstrap не собрался: %w", err)
	}

	a.dns, a.res, a.boot = r, r, b
	return nil
}

// resolveNode подставляет узлу адрес вместо имени (§5.7а).
//
// Резолвить обязана связка, а не Xray: Xray резолвит адрес сам, отдельным
// сокетом, который через наш перехваченный :53 уходит в туннель — то есть в
// резолвер, которому для работы нужен живой узел, которого нет, пока имя не
// разрешилось. Это и есть петля §5.7(а), и разрывается она здесь.
//
// Отказ bootstrap не выбрасывает узел из набора: имя остаётся как было, и
// дозвон до него провалится штатным путём, уйдя в живость (§6.3). Выбрасывать
// значило бы, что один недоступный апстрим сокращает подписку молча.
func (a *Agent) resolveNode(n engine.Node) engine.Node {
	if a.boot == nil {
		return n
	}
	if _, err := netip.ParseAddr(n.Server); err == nil {
		// Узел задан адресом — bootstrap не спрашивается вовсе (D58).
		return n
	}

	addrs, err := a.boot.Resolve(n.Server)
	if err != nil || len(addrs) == 0 {
		a.log.Warn("имя узла не резолвится, останется именем",
			"узел", n.ID, "имя", n.Server, "err", err)
		return n
	}

	// Рукопожатие обязано пережить подстановку. engine.tlsSettings берёт
	// serverName из sni, иначе из host, иначе оставляет Xray взять адрес — и
	// вот последнее после подстановки упёрлось бы в чужой сертификат. Имя,
	// которое мы только что разрешили, и есть правильный serverName.
	if n.Security != "" && n.Security != "none" &&
		n.Param("sni") == "" && n.Param("host") == "" {
		if n.Params == nil {
			n.Params = map[string]string{}
		}
		n.Params["sni"] = n.Server
	}
	n.Server = addrs[0].String()
	return n
}

// trafficPhaseNow — фаза трафика для резолвера. Считается той же чистой
// функцией, что и в Snapshot: два ответа на один вопрос разъехались бы.
func (a *Agent) trafficPhaseNow() TrafficPhase {
	hs := a.hm.Snapshot()
	healthy := a.hm.Healthy()

	a.mu.Lock()
	defer a.mu.Unlock()
	return trafficPhase(a.bypass, a.up, healthy, hs.Active)
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

	// Настоящий приёмник bypass собирается здесь, а не в New: ему нужен
	// a.deliverBypass, а тому — стек, которого до Up ещё нет. Config.Bypass
	// остаётся старше — тесты подставляют его напрямую и настоящий приёмник
	// тогда не заводится (см. Config.BypassControl).
	var sink netstack.BypassSink = a.cfg.Bypass
	var nat *bypass.NAT
	if sink == nil && a.cfg.BypassControl != nil {
		nat, err = bypass.New(bypass.Config{
			Control: a.cfg.BypassControl,
			Reply:   a.deliverBypass,
			Clock:   a.clk,
			// Тот же селектор, что уже питает Control и сокеты Xray: NAT
			// сравнивает привязку сокета с нынешним интерфейсом и
			// переоткрывает сокет, когда тот сменился (§6.8, «следствие
			// первое»). Проброс, а не новый источник события: наблюдатель
			// rtnetlink уже есть, и Interface — его же публикуемый ответ.
			Interface: bypass.InterfaceFunc(a.cfg.Physical),
		})
		if err != nil {
			_ = a.cfg.Trans.Release()
			return fmt.Errorf("agent: bypass-NAT не собрался: %w", err)
		}
		sink = nat
	}

	stack, err := netstack.New(netstack.Config{
		Device:   dev,
		Dialer:   newDialer(a.hm, a.engine),
		Resolver: a.res,
		Bypass:   sink,
		Routing:  a.cfg.Routing,
		Clock:    a.clk,
		Healthy:  a.hm.Healthy,
	})
	if err != nil {
		if nat != nil {
			nat.Close()
		}
		_ = a.cfg.Trans.Release()
		return fmt.Errorf("agent: стек не собрался: %w", err)
	}

	a.mu.Lock()
	a.dev, a.stack, a.bypassNAT, a.up = dev, stack, nat, true
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
	nat := a.bypassNAT
	a.stack, a.dev, a.bypassNAT, a.up = nil, nil, nil, false
	a.mu.Unlock()

	if stack != nil {
		stack.Close()
	}
	if nat != nil {
		nat.Close()
	}
	// Release закрывает и устройство: PacketDevice (§3.2) умеет читать, писать
	// и назвать MTU, и не умеет закрываться — им владеет тот, кто его выдал.
	err := a.cfg.Trans.Release()
	a.stackWG.Wait()

	a.refreshPhase()
	return err
}

// InterruptConnections рвёт активные TCP-соединения текущего стека и
// возвращает их число (§5.5). Это и есть health.Config.Interrupt: живость
// зовёт его сама, ровно при reason: dead, уже после того, как Active()
// переехал на новый узел (Р30) — внутри решать «чьи» соединения рвать не
// нужно. Стека может не быть (Down, ещё не Up) — тогда рвать нечего.
func (a *Agent) InterruptConnections() int {
	a.mu.Lock()
	stack := a.stack
	a.mu.Unlock()
	if stack == nil {
		return 0
	}
	return stack.InterruptTCP()
}

// deliverBypass — обратный путь bypass-NAT в устройство (§6.10). Тот же приём
// отложенного замыкания, что у InterruptConnections: приёмнику нужен стек, а
// стеку — приёмник (bypass.Config.Reply), и разорвать цикл можно только через
// a.mu. Стека может не быть (гонка с Down) — тогда пакету деваться некуда.
func (a *Agent) deliverBypass(pkt []byte) {
	a.mu.Lock()
	stack := a.stack
	a.mu.Unlock()
	if stack != nil {
		stack.Deliver(pkt)
	}
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
		en = append(en, a.resolveNode(n.ToEngine()))
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

// flushResolver доводит событие до резолвера и дожидается, что оно обработано.
//
// Ждёт намеренно: §5.7 велит, чтобы кэш сбрасывал сам резолвер, а Р33 — чтобы
// сброс случился раньше рассылки события. Без ожидания эти два требования
// противоречат друг другу, потому что подписчик живёт в своей горутине.
// Подтверждение приходит и тогда, когда сброса не было (политика выключена):
// иначе выключенный флаг подвешивал бы связку вместо того, чтобы покраснить
// проверку.
func (a *Agent) flushResolver() {
	if a.dns == nil {
		// Заглушка или подставленный тестом резолвер: старый провод.
		if f, ok := a.res.(FlushableResolver); ok {
			f.Flush()
		}
		return
	}
	select {
	case a.dnsEvents <- health.SwitchEvent{}:
	case <-a.done:
		return
	}
	select {
	case <-a.dnsAcked:
	case <-a.done:
	}
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
	nat := a.bypassNAT
	a.stack, a.dev, a.bypassNAT, a.up = nil, nil, nil, false
	a.mu.Unlock()

	if stack != nil {
		stack.Close()
	}
	if nat != nil {
		nat.Close()
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

	// Резолверу фаза приходит функцией, то есть опрашивается. О том, что
	// опрашивать пора, знает только тот, кто фазу поменял: отсюда — сигнал.
	// Что считать краем и что при этом сбросить, решает сам резолвер (Р25).
	if a.dns != nil {
		a.dns.PhaseChanged()
	}
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

// DNSStats — срез перехваченного DNS (§5.7). Второе значение ложно, когда
// настоящий резолвер не собран: показывать нули за него значило бы врать, что
// DNS работает и просто ничего не спросили.
func (a *Agent) DNSStats() (resolver.Stats, bool) {
	if a.dns == nil {
		return resolver.Stats{}, false
	}
	return a.dns.Snapshot(), true
}

// StackStats — счётчики датаплейна (§6.9, §6.10): вердикты, NAT, приёмник
// bypass, отказы. Второе значение ложно, когда стека нет — до `Up` и после
// `Down`. Нули за неподнятый датаплейн означали бы «туннель работает, и через
// него ничего не прошло»; ровно за этим различием второе значение появилось у
// `DNSStats`.
//
// Числа живут ровно столько, сколько стек: `Up` собирает новый и начинает
// счёт заново. Обнуления «на месте» нет и быть не может — сбрасывать чужой
// счётчик по чтению значило бы, что снимок меняет наблюдаемое (тот же довод,
// по которому уборка простоя уехала из `bypass.NAT.Stats`).
//
// Отдельным вызовом, а не полем `Snapshot`, — довод в implementation-notes.md,
// «Этап 9 — счётчики стека доходят до пользователя».
func (a *Agent) StackStats() (netstack.Stats, bool) {
	// Замок отпускается до Stats(): приёмник bypass зовёт a.deliverBypass из
	// своей горутины чтения, а тот берёт a.mu. Держать a.mu поверх чужого кода
	// значило бы связать замок связки с порядком замков netstack и bypass — и
	// цена ошибки здесь не покраснение теста, а взаимная блокировка.
	a.mu.Lock()
	stack := a.stack
	a.mu.Unlock()
	if stack == nil {
		return netstack.Stats{}, false
	}
	return stack.Stats(), true
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
	if a.dns != nil {
		_ = a.dns.Close()
	}
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
