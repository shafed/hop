// Package supervisor — ядро агента: единственное место, где кирпичи §3.4
// соединены в работающий продукт.
//
//	PacketDevice → netstack → engine → узел
//	                   ↓ hijack-dns
//	                resolver ────────→ узел (§5.7б) либо мимо него (§5.7а)
//	health: пробы, окно k-из-n, гистерезис → событие переключения → сюда
//
// Своего решения у супервизора ровно одно, и его нет ни у кого из них: что
// делать при переключении (§5.5). Активный узел меняется всегда, кэш DNS
// сбрасывается всегда, а соединения рвутся только при `reason=dead`.
//
// Чего здесь нет намеренно: разговора с сервисом. Дескриптор добывает cmd/hop
// и приносит сюда готовым (§3.2), поэтому весь агент проверяется на поддельном
// PacketDevice без прав и без TUN (§8.1).
//
// Приёмника bypass-пакетов (netstack.Config.Bypass) тоже нет: исключения §5.6
// выражены правилами маршрутизации выше туннельного и в таблицу туннеля не
// заходят вовсе (§6.2). Вердикт bypass в агенте — второй рубеж на случай, если
// правило не встало, и выпускать такой пакет агенту всё равно нечем.
package supervisor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dns"
	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/node"
	"github.com/shafed/hop/internal/packet"
	"github.com/shafed/hop/internal/tunnel"
)

// Outbound — исходящее агента. В продукте это *engine.Engine.
//
// Интерфейс, а не прямой тип, по той же причине, по которой интерфейсы пробер и
// часы (§3.4): весь §5.5 обязан проверяться на подставном исходящем, без единого
// настоящего соединения и без экземпляра Xray (§8.1).
type Outbound interface {
	Start() error
	Close() error
	// SetActive — через какой узел идёт новый трафик. Открытые соединения
	// остаются в своём outbound: рвать их или нет, решает §5.5.
	SetActive(nodeID string)
	// DialVia — соединение через конкретный узел. Им ходят пробы (§6.7) и
	// перехваченный DNS (§5.7б).
	DialVia(ctx context.Context, nodeID string, dst netip.AddrPort) (net.Conn, error)
	// DialDirect — мимо всех узлов: bootstrap-резолвер (§5.7а) и фаза bypass
	// (§5.6).
	DialDirect(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	DialUDP(src netip.AddrPort) (net.PacketConn, error)
}

var _ Outbound = (*engine.Engine)(nil)

// Config — всё, от чего зависит агент.
type Config struct {
	// Device — то, что агент получил от сервиса (§3.2).
	Device packet.PacketDevice
	// Nodes — узлы из стора, включая неподдержанные: выбором они не участвуют
	// (§6.11), но движок обязан увидеть весь список, чтобы про них знать.
	Nodes []node.Node
	Clock clock.Clock

	Engine   engine.Options
	Monitor  health.MonitorConfig
	Selector health.SelectorConfig
	Schedule health.ScheduleConfig
	// Probes — пробе-таргеты §5.4; пусто — DefaultProbes.
	Probes []health.Target
	// StartupBudget — потолок стартового окна (Р5). Ноль — DefaultStartupBudget.
	StartupBudget time.Duration

	// Outbound и Prober — швы §8.1. nil означает продукт: движок Xray и пробер
	// по нескольким URL.
	Outbound Outbound
	Prober   health.Prober
}

// Status — TunnelState §2 в той части, которой владеет агент.
//
// Полей `device` и фазы `orphaned` здесь нет: они принадлежат сервису, и
// `hop status` берёт их из ipc.Client.Status(). Два источника одной строки
// расходятся молча — пусть каждый отвечает за своё.
type Status struct {
	Phase      tunnel.Phase
	ActiveNode string
	// LastSwitch — «Событие переключения» §2. Нулевое, пока переключений не
	// было.
	LastSwitch health.Switch
}

// Event — то, что уезжает клиентам (§3.3): смена узла и/или фазы туннеля.
type Event struct {
	At    time.Time
	Phase tunnel.Phase
	// Switch заполнен, когда сменился активный узел; nil — сменилась только
	// фаза (например, включён обход §5.6).
	Switch *health.Switch
}

// subBuffer — глубина канала подписчика. События редкие, а подписчик может
// быть занят.
const subBuffer = 64

// DefaultStartupBudget — потолок стартового окна Р5. Тридцати секунд хватает
// на обход подписки в 200 узлов по расписанию §6.5; дальше молчание узлов уже
// не «ещё не спросили», а отказ, и §5.6 требует его показать.
const DefaultStartupBudget = 30 * time.Second

// Supervisor — сам агент.
type Supervisor struct {
	clk   clock.Clock
	mon   *health.Monitor
	sel   *health.Selector
	sch   *health.Scheduler
	out   Outbound
	res   *dns.Resolver
	stack *netstack.Stack

	// candidates — поддержанные узлы (§6.11) в порядке стора.
	candidates []string
	switches   <-chan health.Switch

	// budget — потолок стартового окна (Р5), started — его начало, ставится
	// в Run. До Run started нулевой, и окно закрыто: healthy() у несобранного
	// агента обязан отвечать честно.
	budget  time.Duration
	started time.Time

	mu         sync.Mutex
	running    bool
	bypass     bool
	closed     bool
	lastSwitch health.Switch
	subs       []chan Event

	closeOnce sync.Once
}

// Контракт §3.4: исходящее netstack — это агент, а не движок напрямую. Развилка
// фазы bypass живёт ровно здесь (§5.6).
var _ netstack.Dialer = (*Supervisor)(nil)

// DefaultProbes — пробе-таргеты §5.4.
//
// Заданы адресами, а не именами: проба обязана уйти до всякого резолва, иначе
// на старте петля §5.7(а). Провайдера два, потому что единственный тестовый
// домен может быть заблокирован — тогда все узлы одновременно выглядят
// мёртвыми. Значения стартовые: §8.1 гоняет тесты по управляемому таргету, а не
// по этим.
func DefaultProbes() []health.Target {
	return []health.Target{
		{Addr: netip.MustParseAddrPort("1.1.1.1:80"), Host: "1.1.1.1", Path: "/cdn-cgi/trace"},
		{Addr: netip.MustParseAddrPort("17.253.144.10:80"), Host: "captive.apple.com", Path: "/hotspot-detect.html"},
	}
}

// New собирает агента. Ни одной горутины не заводит: это делает Run.
func New(cfg Config) (*Supervisor, error) {
	if cfg.Device == nil {
		return nil, errors.New("supervisor: нет устройства")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	// Нулевой конфиг — не «отключить»: нулевой tolerance превращает гистерезис
	// §6.4 в его отсутствие, а нулевой период расписания роняет тикер.
	if cfg.Selector.Tolerance <= 0 {
		cfg.Selector = health.DefaultSelectorConfig()
	}
	if cfg.Schedule.Active <= 0 {
		cfg.Schedule = health.DefaultScheduleConfig()
	}
	if cfg.StartupBudget <= 0 {
		cfg.StartupBudget = DefaultStartupBudget
	}

	mon := health.NewMonitor(cfg.Monitor, cfg.Clock)

	out := cfg.Outbound
	if out == nil {
		e, err := engine.New(cfg.Nodes, cfg.Engine, mon, cfg.Clock)
		if err != nil {
			return nil, err
		}
		out = e
	}

	s := &Supervisor{
		clk:    cfg.Clock,
		mon:    mon,
		sel:    health.NewSelector(mon, cfg.Selector, cfg.Clock),
		out:    out,
		budget: cfg.StartupBudget,
	}
	for _, n := range cfg.Nodes {
		if n.Supported {
			s.candidates = append(s.candidates, n.ID)
		}
	}

	// Апстрим DNS не настраивается: §4 оставил роутинг по доменам за v1, а
	// список серверов у резолвера свой (dns.New). DialUDP не задаётся — у
	// движка нет датаграммного исходящего на один адрес, и весь апстрим идёт
	// потоком (см. «Deviations», C3).
	res, err := dns.New(dns.Config{
		Dial:       s.dialTCP,
		DialDirect: out.DialDirect,
		Healthy:    s.healthy,
		Clock:      cfg.Clock,
	})
	if err != nil {
		return nil, err
	}
	s.res = res

	stack, err := netstack.New(netstack.Config{
		Device:   cfg.Device,
		Dialer:   s,
		Resolver: res,
		Healthy:  s.healthy,
		Clock:    cfg.Clock,
	})
	if err != nil {
		return nil, err
	}
	s.stack = stack

	prober := cfg.Prober
	if prober == nil {
		targets := cfg.Probes
		if len(targets) == 0 {
			targets = DefaultProbes()
		}
		// Проба идёт тем же outbound и тем же роутингом, что и трафик (§6.7).
		prober = health.NewURLProber(out.DialVia, targets, cfg.Clock)
	}
	s.sch = health.NewScheduler(prober, mon, s.sel, cfg.Schedule, cfg.Clock)

	// Смерть узла, увиденную трафиком (§6.15), обязан заметить выбор: трафик
	// идёт вне расписания, и ждать тика активного яруса — это держать
	// пользователя на мёртвом узле полминуты (§8.3, T9, T11).
	mon.SetOnDeath(s.sch.OnDeath)

	s.sel.SetCandidates(s.candidates)
	s.setTiers("")
	// Подписка до Run: первое переключение случается на первом же прогоне проб,
	// и потерять его нельзя — с него начинается вся жизнь агента.
	s.switches = s.sel.Subscribe()
	return s, nil
}

// Run поднимает агента и работает, пока не отменят контекст или не закроется
// устройство.
//
// Возврат по отмене контекста не ждёт, пока насос выйдет из чтения устройства:
// разбудить чтение может только владелец дескриптора, то есть тот же, кто
// принёс сюда Device.
func (s *Supervisor) Run(ctx context.Context) error {
	// Закрытие взводится до старта: движок, не поднявшийся из-за битого узла,
	// оставил бы за собой netstack и резолвер.
	defer s.Close()

	if err := s.out.Start(); err != nil {
		return err
	}
	s.mu.Lock()
	s.started = s.clk.Now()
	s.mu.Unlock()
	s.setRunning(true)

	netErr := make(chan error, 1)
	go func() { netErr <- s.stack.Run() }()
	go s.watch(ctx)
	go func() { _ = s.sch.Run(ctx) }()

	select {
	case <-ctx.Done():
		return nil
	case err := <-netErr:
		return err
	}
}

// Close снимает агента. Порядок обратный сборке: сперва замолкает датаплейн,
// потом выбор, потом движок.
func (s *Supervisor) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.setRunning(false)
		s.stack.Close()
		s.sel.Close() // закрывает s.switches, и watch расходится
		_ = s.res.Close()
		err = s.out.Close()

		s.mu.Lock()
		s.closed = true
		for _, ch := range s.subs {
			close(ch)
		}
		s.subs = nil
		s.mu.Unlock()
	})
	return err
}

// Force — форс-проверка §6.6: смена интерфейса, пробуждение из сна, правка
// таблицы маршрутизации. Прогон начинается немедленно, не дожидаясь тикера:
// смена сети означает, что вся история проб устарела одновременно.
func (s *Supervisor) Force(t health.Trigger) { s.sch.Force(t) }

// Pin — `hop up --node` (§С3): фиксация узла и выключение автовыбора.
func (s *Supervisor) Pin(nodeID string) error { return s.sel.Pin(nodeID) }

// Auto — `hop auto on|off` (§С3).
func (s *Supervisor) Auto(on bool) { s.sel.Auto(on) }

// Bypass — «осознанно выпустить трафик напрямую» (§5.6, §С6).
//
// Держится до перезапуска агента и на диск не пишется намеренно: fail-open,
// переживший перезагрузку, — это ровно то раскрытие реального IP, против
// которого написан §5.6.
func (s *Supervisor) Bypass(on bool) {
	s.mu.Lock()
	if s.bypass == on {
		s.mu.Unlock()
		return
	}
	s.bypass = on
	s.mu.Unlock()

	// Путь наружу сменился целиком, значит и адреса в кэше получены не тем
	// путём, каким пойдёт следующий запрос (§5.7в).
	s.res.Flush()
	s.emit(nil)
}

// Status — снимок для `hop status` (§С5).
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{
		Phase:      s.phaseLocked(),
		ActiveNode: s.sel.Active(),
		LastSwitch: s.lastSwitch,
	}
}

// Nodes — здоровье всех узлов для `hop nodes` (§С5), включая ни разу не
// пробованные: отсутствие истории — это тоже состояние (§2).
func (s *Supervisor) Nodes() []health.NodeHealth {
	out := make([]health.NodeHealth, 0, len(s.candidates))
	for _, id := range s.candidates {
		out = append(out, s.mon.Get(id))
	}
	return out
}

// Subscribe отдаёт поток событий (§3.3).
//
// Отписки нет: подписчик здесь один — тот, кто рассылает события клиентам, — и
// живёт он ровно столько же, сколько агент. Рассылка нескольким клиентам
// (§3.3) стоит уровнем выше, на сокете.
func (s *Supervisor) Subscribe() <-chan Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan Event, subBuffer)
	if s.closed {
		close(ch)
		return ch
	}
	s.subs = append(s.subs, ch)
	return ch
}

// DialTCP — исходящее TCP для netstack (§3.4).
func (s *Supervisor) DialTCP(dst netip.AddrPort) (net.Conn, error) {
	return s.dialTCP(context.Background(), dst)
}

// DialUDP — исходящее UDP для netstack. Прямого пути мимо узлов у него нет:
// движок отдаёт PacketConn только по тегу узла, поэтому в фазе bypass UDP не
// выпускается (см. «Deviations», C8).
func (s *Supervisor) DialUDP(src netip.AddrPort) (net.PacketConn, error) {
	return s.out.DialUDP(src)
}

// dialTCP — единственный путь исходящего TCP: и трафик netstack, и
// перехваченный DNS. В фазе bypass он идёт мимо узлов, иначе резолвер упёрся бы
// в отсутствующий живой узел ровно тогда, когда пользователь явно попросил
// выпустить трафик (§5.6).
func (s *Supervisor) dialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if s.bypassed() {
		return s.out.DialDirect(ctx, dst)
	}
	// Различие §5.6, наблюдаемое клиентом: в стартовом окне поток
	// придерживается (netstack не отвечает на SYN, клиент повторит), при
	// fail-close — отвергается RST'ом.
	//
	// Без этой ветки стартовое окно не давало ничего: healthy() возвращал
	// true, вердикт становился Proxy, диалер не находил активного узла и отдавал
	// ошибку, а netstack превращал любую ошибку дозвона в RST. То есть §5.6
	// нарушался ровно тем способом, который он сам и называет.
	if s.sel.Active() == "" && s.inStartupGrace() {
		return nil, netstack.ErrNotReady
	}
	return s.out.DialVia(ctx, s.sel.Active(), dst)
}

// healthy — «есть ли живой узел» для netstack (§3.4) и резолвера (§5.7б).
//
// Обход — это и есть единственный разрешённый fail-open (§5.6): пока он
// выключен, отсутствие живых узлов закрывает и трафик, и DNS.
func (s *Supervisor) healthy() bool {
	return s.mon.HasAlive() || s.bypassed() || s.inStartupGrace()
}

// inStartupGrace — стартовое окно Р5.
//
// Fail-close наступает, когда каждый поддержанный узел (§6.11) проверен хотя
// бы раз и ни один не жив, либо истёк бюджет — что раньше. Без этого окна
// «живых нет» неотличимо от «ещё никого не спросили»: свежий монитор пуст, и
// первый же пакет после `hop up` получал бы RST в те секунды, пока идёт
// первый обход подписки, — то есть fail-close по §5.6 срабатывал бы там, где
// отказа ещё не было.
//
// Бюджет нужен на случай, когда обход не кончается вовсе: узел за blackhole
// не отвечает и остаётся untested, а без потолка окно осталось бы открытым
// навсегда — это уже fail-open, которого §5.6 не разрешает.
func (s *Supervisor) inStartupGrace() bool {
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()

	if started.IsZero() || s.clk.Now().Sub(started) >= s.budget {
		return false
	}
	for _, id := range s.candidates {
		// Пустое окно — «об узле нет ни одного исхода», и это не то же самое,
		// что состояние Untested: узел с одной неудачей из трёх (§6.3) тоже
		// untested, но он уже ответил, и ждать его больше нечего.
		if len(s.mon.Get(id).Window) == 0 {
			return true
		}
	}
	return false
}

// watch — приёмник событий переключения.
func (s *Supervisor) watch(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case sw, ok := <-s.switches:
			if !ok {
				return
			}
			s.apply(sw)
		}
	}
}

// apply — реакция на переключение, то единственное решение, ради которого
// супервизор существует (§5.5).
func (s *Supervisor) apply(sw health.Switch) {
	// Новый трафик идёт через новый узел с этого момента; уже открытые
	// соединения остаются в своём outbound.
	s.out.SetActive(sw.To)
	// Тот же домен через другой узел резолвится в другой адрес: старая запись
	// отправила бы трафик в CDN чужого региона (§5.7в).
	s.res.OnNodeSwitch()

	if sw.Interrupts() {
		// §5.5: узел мёртв — его соединения уже мертвы, и разрыв даёт
		// приложению переподключиться за секунды вместо минут TCP-таймаута.
		// Число разорванных — часть события §2, а не лог.
		sw.InterruptedConnections = s.stack.ResetFlows()
	}

	// Ярусы §6.5: активный узел опрашивается чаще пула, и после переключения
	// это уже другой узел.
	s.setTiers(sw.To)
	s.emit(&sw)
}

// setTiers раскладывает узлы по ярусам расписания (§6.5). Лишних кандидатов
// PoolSize уводит в редкий ярус сам.
func (s *Supervisor) setTiers(active string) {
	pool := make([]string, 0, len(s.candidates))
	for _, id := range s.candidates {
		if id != active {
			pool = append(pool, id)
		}
	}
	s.sch.SetNodes(active, pool, nil)
}

// emit рассылает событие подписчикам и запоминает последнее переключение.
func (s *Supervisor) emit(sw *health.Switch) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sw != nil {
		s.lastSwitch = *sw
	}
	ev := Event{At: s.clk.Now(), Phase: s.phaseLocked(), Switch: sw}
	for _, ch := range s.subs {
		select {
		case ch <- ev:
		default:
			// Подписчик не читает свой канал. Блокировать на нём агента
			// нельзя: зависший клиент остановил бы автопереключение.
		}
	}
}

// phaseLocked — фаза §2 глазами агента.
func (s *Supervisor) phaseLocked() tunnel.Phase {
	switch {
	case !s.running:
		return tunnel.Down
	case s.bypass:
		return tunnel.Bypass
	case s.sel.Active() != "":
		return tunnel.Up
	case len(s.candidates) > 0 && len(s.mon.Snapshot()) == 0:
		// Ни одна проба ещё не закончилась: узлы не мертвы, они неизвестны, и
		// показывать «no healthy nodes» в этот момент было бы враньём. Пустой
		// стор — другое дело: там и пробовать нечего, это сразу fail-close.
		return tunnel.Starting
	default:
		return tunnel.Failing
	}
}

func (s *Supervisor) bypassed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bypass
}

func (s *Supervisor) setRunning(on bool) {
	s.mu.Lock()
	s.running = on
	s.mu.Unlock()
}
