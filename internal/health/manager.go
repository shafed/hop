package health

import (
	"context"
	"errors"
	"hash/fnv"
	"sort"
	"sync"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/policy"
)

// Стартовые значения расписания и порогов — docs/verification-autoswitch.md §4.
// Числа стартовые: T3 и A25 вправе их опровергнуть, и тогда меняются здесь.
const (
	DefaultActiveInterval    = 20 * time.Second
	DefaultCandidateInterval = 60 * time.Second
	DefaultTailInterval      = 1800 * time.Second
	DefaultProbeTimeout      = 5 * time.Second
	DefaultStartupBudget     = 30 * time.Second
	DefaultTolerance         = 50 * time.Millisecond
	DefaultPoolSize          = 5
	DefaultForceCooldown     = 1 * time.Second
	DefaultK                 = 2
	DefaultN                 = 3

	// tailJitter — разброс интервала хвоста, ±20% (§6.5 «вразнобой»).
	// Детерминирован по id узла: прогон обязан быть воспроизводим (A26).
	tailJitter = 0.2
)

// Config — всё, что модулю нужно снаружи.
type Config struct {
	Nodes  []Node
	Clock  clock.Clock
	Prober Prober

	// Interrupt рвёт активные соединения и возвращает их число. Вызывается
	// только при переключении по причине dead (§5.5, A18, A19).
	Interrupt func() int

	ActiveInterval    time.Duration
	CandidateInterval time.Duration
	TailInterval      time.Duration
	ProbeTimeout      time.Duration
	StartupBudget     time.Duration
	ForceCooldown     time.Duration
	Tolerance         time.Duration
	PoolSize          int
	K, N              int
}

// Manager — живость, выбор и переключение.
//
// Всё состояние под одним мьютексом; горутина цикла занимается только
// расписанием проб. Поэтому ReportFailure, Pin и Auto синхронны: вызов вернулся
// — состояние уже пересчитано, и тесту не нужно ждать цикл.
//
// Пробы раунда идут параллельно, а раунд ждёт их все. Зависший узел задерживает
// начало следующего раунда на таймаут пробы, но не копит горутины (A27).
type Manager struct {
	cfg    Config
	clk    clock.Clock
	prober Prober

	// Пороги, снятые с политик один раз при создании. Выключенная политика
	// меняет поведение здесь, а не в call-site (см. internal/policy).
	k, n      int
	tolerance time.Duration
	tiers     bool // probe_tiers
	traffic   bool // traffic_kills
	forced    bool // forced_probe
	reasons   bool // switch_reason

	mu      sync.Mutex
	cond    *sync.Cond
	nodes   map[string]*nodeState
	order   []string
	active  string
	auto    bool
	pinned  string
	round   uint64
	started time.Time
	lastFor time.Time // последний форс-прогон
	forceAt time.Time // назначенный форс-прогон; нулевое — нет

	events *eventQueue
	wake   chan struct{}
	done   chan struct{}
	closed bool
	loopWG sync.WaitGroup
}

// New создаёт менеджер. Цикл проб не запущен: Start.
func New(cfg Config) *Manager {
	setDefault := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	setDefault(&cfg.ActiveInterval, DefaultActiveInterval)
	setDefault(&cfg.CandidateInterval, DefaultCandidateInterval)
	setDefault(&cfg.TailInterval, DefaultTailInterval)
	setDefault(&cfg.ProbeTimeout, DefaultProbeTimeout)
	setDefault(&cfg.StartupBudget, DefaultStartupBudget)
	setDefault(&cfg.ForceCooldown, DefaultForceCooldown)
	if cfg.Tolerance <= 0 {
		cfg.Tolerance = DefaultTolerance
	}
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = DefaultPoolSize
	}
	if cfg.K <= 0 {
		cfg.K = DefaultK
	}
	if cfg.N <= 0 {
		cfg.N = DefaultN
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}

	m := &Manager{
		cfg:       cfg,
		clk:       cfg.Clock,
		prober:    cfg.Prober,
		k:         cfg.K,
		n:         cfg.N,
		tolerance: cfg.Tolerance,
		tiers:     policy.ProbeTiers.On(),
		traffic:   policy.TrafficKills.On(),
		forced:    policy.ForcedProbe.On(),
		reasons:   policy.SwitchReason.On(),
		nodes:     make(map[string]*nodeState, len(cfg.Nodes)),
		auto:      true,
		events:    newEventQueue(),
		wake:      make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	m.cond = sync.NewCond(&m.mu)

	// k_of_n выключена — узел умирает от одной неудачи, ровно как sing-box
	// в DeleteURLTestHistory. Краснит T2 и A3.
	if !policy.KOfN.On() {
		m.k = 1
	}
	// tolerance выключен — переключаемся на любое улучшение. Краснит T3.
	if !policy.Tolerance.On() {
		m.tolerance = 0
	}

	now := m.clk.Now()
	m.started = now
	for i, nd := range cfg.Nodes {
		m.nodes[nd.ID] = &nodeState{node: nd, order: i, nextProbe: now}
		m.order = append(m.order, nd.ID)
	}
	return m
}

// SetNodes меняет набор узлов, сохраняя историю тех, кто остался.
//
// Это вторая половина обещания §1/С8 и §5.8. Стор сохраняет `id` и историю проб
// на диске, но если живость при обновлении подписки заводит узлы заново, то
// окно, `rtt` и состояние обнуляются в памяти — и автопереключение начинает с
// нуля каждые несколько часов, ровно как при полной замене, от которой §5.8 и
// отказывается. Поэтому узел, оставшийся в наборе, сохраняет свой `nodeState`
// целиком; уходят только исчезнувшие.
//
// Порядок берётся из нового набора: `node_order` принадлежит провайдеру
// (Р8 регистра стора), а §6.4 делает его наблюдаемым — при равных `rtt`
// выигрывает первый по порядку.
//
// Активный узел, которого в новом наборе не стало, снимается. Событие
// переключения при этом **не** выдумывается здесь: выбор пересчитает цикл проб
// по своему обычному правилу, и причина у него будет настоящая.
func (m *Manager) SetNodes(nodes []Node) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clk.Now()
	next := make(map[string]*nodeState, len(nodes))
	order := make([]string, 0, len(nodes))

	for i, nd := range nodes {
		st, ok := m.nodes[nd.ID]
		switch {
		case !ok:
			st = &nodeState{node: nd, order: i, nextProbe: now}

		case st.node == nd && st.order == i:
			// Ничего не изменилось — самый частый случай при обновлении
			// подписки. Объект остаётся тем же, и проба, которая сейчас в
			// полёте, продолжает писать по назначению.

		default:
			// Изменилось. Живой объект **не** мутируется: `probe` читает
			// `s.node.ID` вне замка (по построению — проба идёт в сеть, держать
			// на ней замок нельзя), и запись сюда была бы гонкой. Вместо этого
			// заводится копия с той же историей; проба, оставшаяся в полёте,
			// допишет результат в осиротевший объект, и он пропадёт вместе с
			// ним. Потерянная проба стоит одного раунда, гонка — доверия ко
			// всему модулю.
			cp := *st
			cp.node = nd
			cp.order = i
			cp.inFlight = false
			// Окно клонируется: копия делит с оригиналом массив под срезом, и
			// два append по одному индексу затирали бы друг друга.
			cp.window = append([]Outcome(nil), st.window...)
			st = &cp
		}
		next[nd.ID] = st
		order = append(order, nd.ID)
	}

	m.nodes = next
	m.order = order

	if m.active != "" && next[m.active] == nil {
		m.active = ""
	}
	if m.pinned != "" && next[m.pinned] == nil {
		// Зафиксированный узел исчез из подписки. Фиксация буквальна (§1/С3),
		// поэтому автоматика сама не возвращается: пользователь выключал её
		// осознанно и включит обратно так же.
		m.pinned = ""
	}

	// Разбудить цикл: набор изменился, и назначенные пробы вместе с ним.
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Start запускает цикл проб. Первый обход подписки идёт немедленно: все узлы
// назначены на now, поэтому цикл входит в раунд, не дожидаясь тикера.
func (m *Manager) Start() {
	ready := make(chan time.Time, 1)
	ready <- m.clk.Now()
	m.loopWG.Add(1)
	go m.loop(ready)
}

// Close останавливает цикл и закрывает канал событий.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.cond.Broadcast() // ждущие WaitRound не должны висеть после Close
	m.mu.Unlock()

	close(m.done)
	m.loopWG.Wait()
	m.events.close()
}

// Events — поток событий переключения. Очередь внутри неограниченная:
// подписчик, который читает медленно, не должен терять переключения
// (docs/verification-autoswitch.md §2, требование 4).
func (m *Manager) Events() <-chan SwitchEvent { return m.events.out }

// Snapshot — весь вердикт наружу.
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Snapshot{Active: m.active, Auto: m.auto, Round: m.round}
	for _, id := range m.order {
		s.Nodes = append(s.Nodes, m.nodes[id].health(m.k))
	}
	return s
}

// Active — id узла, которому принадлежат новые соединения, или пусто.
//
// Узкий вариант Snapshot для горячего пути: связка спрашивает его на каждом
// исходящем дозвоне (Р30 регистра связки), а Snapshot копирует живость всех
// узлов подписки — на двухстах узлах это заметная работа ради одной строки.
func (m *Manager) Active() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

// Healthy — провод в netstack (§3.4, п. 3): false означает fail-close.
//
// До конца первого раунда false не возвращается (Р5): иначе на старте
// пользователь получает RST вместо ожидания в те несколько секунд, пока идёт
// первый обход подписки.
func (m *Manager) Healthy() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.auto {
		return m.pinned != "" && m.nodes[m.pinned] != nil && m.nodes[m.pinned].state(m.k) == Alive
	}
	if m.active != "" {
		return true
	}
	return m.inStartupGraceLocked()
}

// inStartupGraceLocked — стартовое окно Р5: не все узлы проверены и бюджет ещё
// не истёк.
func (m *Manager) inStartupGraceLocked() bool {
	if m.clk.Now().Sub(m.started) >= m.cfg.StartupBudget {
		return false
	}
	for _, id := range m.order {
		s := m.nodes[id]
		if s.node.Supported && !s.probed {
			return true
		}
	}
	return false
}

// ReportFailure — ошибка реального трафика (§6.15). Отказ целевого хоста сюда
// не попадает по построению: kind вне перечисления игнорируется (A7).
func (m *Manager) ReportFailure(nodeID string, kind FailureKind) {
	if !kind.valid() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.nodes[nodeID]
	if s == nil {
		return
	}
	// traffic_kills выключена — ошибки трафика не влияют на живость.
	// Краснит A5 и A29.
	if !m.traffic {
		return
	}
	s.traffic++
	s.lastErr = kind.String()
	m.selectLocked()
}

// NetworkChanged — смена интерфейса, пробуждение, изменение таблицы маршрутов
// (§6.6). Дребезг событий коалесцируется в ForceCooldown (A24).
func (m *Manager) NetworkChanged() {
	// forced_probe выключена — событие игнорируется, работает только тикер.
	// Краснит T6 и A24.
	if !m.forced {
		return
	}
	m.mu.Lock()
	now := m.clk.Now()
	earliest := m.lastFor.Add(m.cfg.ForceCooldown)
	at := now
	if !m.lastFor.IsZero() && earliest.After(now) {
		at = earliest
	}
	if m.forceAt.IsZero() || at.Before(m.forceAt) {
		m.forceAt = at
	}
	m.mu.Unlock()
	m.poke()
}

// Pin фиксирует узел: автовыбор выключается до Auto(true) (§1/С3).
// Зафиксированный узел не заменяется даже мёртвым (Р6) — пользователь получает
// fail-close и видит причину в status.
func (m *Manager) Pin(nodeID string) error {
	m.mu.Lock()
	s := m.nodes[nodeID]
	if s == nil {
		m.mu.Unlock()
		return errUnknownNode
	}
	if !s.node.Supported {
		m.mu.Unlock()
		return errUnsupportedNode
	}
	from := m.active
	m.auto, m.pinned, m.active = false, nodeID, nodeID
	if from != nodeID {
		m.emitLocked(from, nodeID, ReasonManual)
	}
	// Зафиксированный узел стал активным, значит и опрашиваться обязан как
	// активный. Без этого узел, зафиксированный из хвоста подписки, остался бы
	// на хвостовом интервале: `status` показывал бы живость получасовой
	// давности ровно для того узла, через который идёт весь трафик.
	m.retierLocked()
	m.mu.Unlock()
	m.poke()
	return nil
}

// Auto включает и выключает автовыбор (hop auto on/off).
func (m *Manager) Auto(on bool) {
	m.mu.Lock()
	m.auto = on
	if on {
		m.pinned = ""
		m.selectLocked()
	}
	m.mu.Unlock()
	m.poke()
}

// WaitRound блокирует до завершения раунда номер n. Тест ждёт счётчик, а не
// спит: без этого каждая L1-проверка превращается в гонку
// (docs/verification-autoswitch.md §2, требование 1).
func (m *Manager) WaitRound(n uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for m.round < n && !m.closed {
		m.cond.Wait()
	}
}

// --- цикл проб ---------------------------------------------------------

func (m *Manager) loop(next <-chan time.Time) {
	defer m.loopWG.Done()
	for {
		select {
		case <-m.done:
			return
		case <-next:
		case <-m.wake:
		}

		m.runDue()

		// Следующий таймер регистрируется ДО объявления раунда: проснувшийся
		// после WaitRound тест вправе сразу двигать часы, и его Advance обязан
		// попасть в уже зарегистрированного ожидающего.
		next = m.clk.After(m.nextWake())
		m.mu.Lock()
		m.round++
		m.cond.Broadcast()
		m.mu.Unlock()
	}
}

// nextWake — сколько ждать до ближайшей пробы.
func (m *Manager) nextWake() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clk.Now()
	best := time.Duration(-1)
	consider := func(at time.Time) {
		d := at.Sub(now)
		if d < 0 {
			d = 0
		}
		if best < 0 || d < best {
			best = d
		}
	}
	if !m.forceAt.IsZero() {
		consider(m.forceAt)
	}
	for _, id := range m.order {
		s := m.nodes[id]
		if !s.node.Supported || s.inFlight {
			continue
		}
		consider(s.nextProbe)
	}
	if best < 0 {
		return m.cfg.TailInterval // все узлы в полёте либо неподдерживаемы
	}
	return best
}

// runDue пробует всё, чему пришёл срок, и ждёт результаты.
func (m *Manager) runDue() {
	m.mu.Lock()
	now := m.clk.Now()
	if !m.forceAt.IsZero() && !now.Before(m.forceAt) {
		m.forceAt = time.Time{}
		m.lastFor = now
		for _, id := range m.order {
			m.nodes[id].nextProbe = now
		}
	}
	var due []*nodeState
	for _, id := range m.order {
		s := m.nodes[id]
		// Неподдерживаемый узел не пробуется ни разу (§6.11, A13).
		if !s.node.Supported || s.inFlight || s.nextProbe.After(now) {
			continue
		}
		s.inFlight = true
		due = append(due, s)
	}
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, s := range due {
		wg.Add(1)
		go func(s *nodeState) {
			defer wg.Done()
			m.probe(s)
		}(s)
	}
	wg.Wait()
}

// errProbeReturned — причина отмены контекста при штатном завершении Probe.
// probe() отменяет ctx на каждом выходе, чтобы освободить таймер (After);
// без отдельной причины эта уборочная отмена неотличима от отмены по
// настоящему таймауту через один и тот же ctx.Err() != nil (A36).
var errProbeReturned = errors.New("health: проба вернулась сама, отмена — не причина")

// probe выполняет одну пробу узла и применяет результат.
func (m *Manager) probe(s *nodeState) {
	ctx, cancel := context.WithCancelCause(context.Background())
	// After регистрируется синхронно — до входа в Probe, поэтому фейковые
	// часы не могут проскочить мимо этого ожидающего.
	timeout := m.clk.After(m.cfg.ProbeTimeout)
	stop := make(chan struct{})
	go func() {
		select {
		case <-timeout:
			cancel(context.DeadlineExceeded)
		case <-stop:
		case <-m.done:
			cancel(context.Canceled)
		}
	}()

	res := m.prober.Probe(ctx, s.node.ID)
	close(stop)
	cancel(errProbeReturned)

	m.mu.Lock()
	defer m.mu.Unlock()
	s.inFlight = false
	s.last = m.clk.Now()
	switch {
	case res.Err == nil:
		s.record(OK, m.n)
		s.rtt = res.RTT
		s.lastErr = ""
		// Успешная проба гасит подозрение, накопленное из трафика (Р2), но
		// не стирает историю проб.
		s.traffic = 0
	case !errors.Is(context.Cause(ctx), errProbeReturned):
		// Первая причина отмены побеждает (context.Cause): если Probe
		// вернулась сама, до неё успевает дойти только errProbeReturned из
		// уборки ниже, а настоящий таймаут или m.done — раньше.
		s.record(Timeout, m.n)
		s.lastErr = "timeout"
	default:
		s.record(Fail, m.n)
		s.lastErr = res.Err.Error()
	}
	s.nextProbe = m.clk.Now().Add(m.intervalLocked(s))
	m.selectLocked()
}

// --- расписание --------------------------------------------------------

// intervalLocked — ярус узла (§6.5). Активный и пул кандидатов часто,
// остальная подписка редко и вразнобой.
func (m *Manager) intervalLocked(s *nodeState) time.Duration {
	// probe_tiers выключена — ярусы схлопываются в полный обход на каждом
	// тике. Краснит A25 и A26.
	if !m.tiers {
		return m.cfg.ActiveInterval
	}
	if s.node.ID == m.active {
		return m.cfg.ActiveInterval
	}
	if m.inPoolLocked(s) {
		return m.cfg.CandidateInterval
	}
	return jitter(m.cfg.TailInterval, s.node.ID)
}

// inPoolLocked — пул кандидатов: PoolSize лучших живых плюс все непроверенные.
// Непроверенные здесь потому, что холодный старт обязан кончиться быстро (Р4),
// а мёртвые — в хвосте: они опрашиваются редко, но опрашиваются, иначе смерть
// становится необратимой (A4).
func (m *Manager) inPoolLocked(s *nodeState) bool {
	if s.state(m.k) == Untested {
		return true
	}
	if s.state(m.k) != Alive {
		return false
	}
	var alive []*nodeState
	for _, id := range m.order {
		n := m.nodes[id]
		if n.node.Supported && n.node.ID != m.active && n.state(m.k) == Alive {
			alive = append(alive, n)
		}
	}
	sort.SliceStable(alive, func(i, j int) bool { return alive[i].rtt < alive[j].rtt })
	for i, n := range alive {
		if i >= m.cfg.PoolSize {
			break
		}
		if n == s {
			return true
		}
	}
	return false
}

// retierLocked подтягивает сроки узлов, чей ярус стал чаще: узел, ставший
// активным, обязан опрашиваться как активный, а не досиживать хвостовой срок
// (иначе бюджет A28 не выполняется).
func (m *Manager) retierLocked() {
	now := m.clk.Now()
	for _, id := range m.order {
		s := m.nodes[id]
		if !s.node.Supported || s.inFlight {
			continue
		}
		if latest := now.Add(m.intervalLocked(s)); s.nextProbe.After(latest) {
			s.nextProbe = latest
		}
	}
}

// jitter разносит хвост детерминированно по id: ±tailJitter.
func jitter(d time.Duration, id string) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	// [-1, 1) с шагом 1/2048 — достаточно, чтобы 200 узлов не сошлись в тик.
	f := float64(int32(h.Sum32()%4096)-2048) / 2048
	return time.Duration(float64(d) * (1 + tailJitter*f))
}

// --- выбор -------------------------------------------------------------

// selectLocked пересчитывает активный узел и, если он сменился, испускает
// событие. Вызывается на каждом результате пробы: холодный старт обязан
// выбрать первый же ответивший узел, не дожидаясь конца раунда (Р4).
func (m *Manager) selectLocked() {
	defer m.retierLocked()

	if !m.auto {
		return // ручная фиксация не отменяется смертью узла (Р6, A22)
	}

	var best *nodeState
	for _, id := range m.order {
		s := m.nodes[id]
		if !s.node.Supported || s.state(m.k) != Alive {
			continue
		}
		// Строгое «меньше» плюс порядок узлов: при равных rtt выигрывает
		// первый по node_order, и прогон воспроизводим (A10, A11).
		if best == nil || s.rtt < best.rtt {
			best = s
		}
	}

	cur := m.nodes[m.active]
	curAlive := m.active != "" && cur != nil && cur.state(m.k) == Alive

	if best == nil {
		if m.active != "" {
			m.active = ""
			// Живых нет — это fail-close, а не переключение: событие
			// испускать не на что. Наружу это видно через Healthy().
		}
		return
	}

	if !curAlive {
		// Активный мёртв или его нет — переключаемся немедленно, безо
		// всякого tolerance: он асимметричен по построению (A9).
		if m.active != best.node.ID {
			from := m.active
			m.active = best.node.ID
			m.emitLocked(from, best.node.ID, ReasonDead)
		}
		return
	}

	if best.node.ID != m.active && best.rtt < cur.rtt-m.tolerance {
		from := m.active
		m.active = best.node.ID
		m.emitLocked(from, best.node.ID, ReasonFaster)
	}
}

// emitLocked кладёт событие в очередь и, если причина того требует, рвёт
// активные соединения (§5.5).
func (m *Manager) emitLocked(from, to string, r Reason) {
	ev := SwitchEvent{At: m.clk.Now(), From: from, To: to, Reason: r}
	// switch_reason выключена — рвём всегда, как sing-box с глобальным
	// флагом. Краснит A19.
	if m.cfg.Interrupt != nil && (!m.reasons || r == ReasonDead) {
		ev.Interrupted = m.cfg.Interrupt()
	}
	m.events.push(ev)
}

func (m *Manager) poke() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

type healthError string

func (e healthError) Error() string { return string(e) }

const (
	errUnknownNode     = healthError("health: неизвестный узел")
	errUnsupportedNode = healthError("health: узел не поддерживается сборкой")
)
