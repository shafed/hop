package health

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/policy"
)

// DialFunc — как пробер попадает наружу. Сигнатура совпадает с
// Engine.DialVia неслучайно: проба идёт тем же outbound и тем же роутингом, что
// и трафик (§6.7), а health при этом ничего не знает про Xray (§3.4).
type DialFunc func(ctx context.Context, nodeID string, dst netip.AddrPort) (net.Conn, error)

// Target — один пробе-URL §5.4.
//
// Адрес отдельно от имени: проба обязана уйти до всякого резолва, иначе на
// старте получается петля §5.7(а) — резолвер ждёт живого узла, живость узла
// ждёт резолва.
type Target struct {
	Addr netip.AddrPort
	// Host — значение заголовка Host; пусто — берётся из Addr.
	Host string
	// Path — путь, отдающий 204.
	Path string
}

// URLProber — активные пробы по нескольким URL (§5.4).
//
// URL несколько потому, что единственный тестовый домен может быть
// заблокирован, и тогда все узлы одновременно выглядят мёртвыми. Успех — первый
// ответивший таргет; узел мёртв, только если не ответил ни один.
//
// Политика multi_url: при выключении опрашивается только первый таргет, и
// заблокированный домен убивает всю подписку — это краснит T5.
type URLProber struct {
	dial    DialFunc
	targets []Target
	clk     clock.Clock
}

var _ Prober = (*URLProber)(nil)

// NewURLProber создаёт пробер по списку таргетов.
func NewURLProber(dial DialFunc, targets []Target, clk clock.Clock) *URLProber {
	return &URLProber{dial: dial, targets: append([]Target(nil), targets...), clk: clk}
}

// Probe гоняет пробу через узел nodeID.
func (p *URLProber) Probe(ctx context.Context, nodeID string) Result {
	targets := p.targets
	if !policy.MultiURL.On() && len(targets) > 1 {
		targets = targets[:1]
	}
	if len(targets) == 0 {
		return Result{Err: errors.New("health: список пробе-таргетов пуст")}
	}

	var last error
	for _, t := range targets {
		rtt, err := p.probeOne(ctx, nodeID, t)
		if err == nil {
			return Result{RTT: rtt}
		}
		last = err
		if ctx.Err() != nil {
			// Прогон отменён или вышло время: остальные таргеты ответить уже
			// не успеют, а исход обязан остаться таймаутом, а не отказом.
			return Result{Err: ctx.Err()}
		}
	}
	return Result{Err: last}
}

// probeOne — один таргет: GET и ожидание 2xx. Ответ 403 — это отказ узла в
// проксировании, а не живость: §8.1 переключает пробе-таргет именно так.
func (p *URLProber) probeOne(ctx context.Context, nodeID string, t Target) (time.Duration, error) {
	start := p.clk.Now()
	conn, err := p.dial(ctx, nodeID, t.Addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// net.Conn про контекст не знает, а blackhole не закрывает соединение
	// вовсе (§8.1). Единственный способ снять зависшее чтение — закрыть
	// соединение снаружи; без этого проба висит вечно и ярус встаёт.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	host := t.Host
	if host == "" {
		host = t.Addr.String()
	}
	path := t.Path
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("проба %s: ответ %s", t.Addr, resp.Status)
	}
	return p.clk.Now().Sub(start), nil
}

// Tier — ярус расписания §6.5.
type Tier uint8

const (
	// TierActive — активный узел: опрашивается чаще всех, потому что его смерть
	// пользователь чувствует немедленно.
	TierActive Tier = iota + 1
	// TierPool — пул кандидатов, куда переключаться. Без него переключение шло
	// бы вслепую.
	TierPool
	// TierRest — остальная подписка: редко и вразнобой. Полный обход 200 узлов
	// раз в 3 минуты — это 4000 TLS-хендшейков в час к одному провайдеру,
	// заметный паттерн и лишняя нагрузка.
	TierRest
)

// ScheduleConfig — интервалы ярусов §6.5.
type ScheduleConfig struct {
	Active time.Duration
	Pool   time.Duration
	Rest   time.Duration
	// Jitter — разброс внутри редкого яруса, чтобы подписка не опрашивалась
	// залпом.
	Jitter time.Duration
	// PoolSize — сколько кандидатов держим в горячем ярусе.
	PoolSize int
	// ProbeTimeout — сколько ждём одну пробу. Обязан быть меньше самого частого
	// периода, иначе ярус наезжает сам на себя.
	ProbeTimeout time.Duration
	// ConfirmDelay — пауза перед подтверждающей пробой (см. confirm). Ноль
	// выключает подтверждение целиком: мгновенный повтор той же пробы — не
	// второе свидетельство, а то же самое, и §6.3 от него ничего не получает.
	ConfirmDelay time.Duration
}

// DefaultScheduleConfig — стартовые значения §6.5. Проверяются численно
// бенчмарком B2: рост числа исходящих соединений за час означает, что
// расписание деградировало до полного обхода.
func DefaultScheduleConfig() ScheduleConfig {
	return ScheduleConfig{
		Active:   30 * time.Second,
		Pool:     60 * time.Second,
		Rest:     30 * time.Minute,
		Jitter:   5 * time.Minute,
		PoolSize: 5,
		// Бюджет T9/T11 — 5 секунд от отказа узла до переключения, а порог §6.3
		// требует двух неудач. Отсюда два таймаута плюс пауза подтверждения не
		// должны выходить за этот бюджет: узел, не ответивший на пробу за две
		// секунды, активным всё равно не годится.
		ProbeTimeout: 2 * time.Second,
		ConfirmDelay: 500 * time.Millisecond,
	}
}

// Trigger — событие, требующее немедленной проверки (§6.6).
type Trigger string

const (
	TriggerInterface Trigger = "interface" // смена интерфейса
	TriggerWake      Trigger = "wake"      // пробуждение из сна
	TriggerRoute     Trigger = "route"     // изменение таблицы маршрутизации
)

// Scheduler — ярусное расписание проб.
//
// Тикер один, самый частый, а ярус выражен сроком узла в next: три тикера
// пришлось бы синхронизировать между собой, и джиттер редкого яруса всё равно
// не ложится на тик — он сдвигает срок каждого узла по отдельности.
type Scheduler struct {
	prober Prober
	mon    *Monitor
	sel    *Selector
	cfg    ScheduleConfig
	clk    clock.Clock

	runMu sync.Mutex // один прогон одновременно: тикер и Force не дублируют пробы

	// sweeping — идёт ли прогон прямо сейчас. Смерть, увиденная внутри прогона,
	// не должна дёргать выбор: прогон пересчитает его сам, один раз и по
	// собранной картине (см. probe).
	sweeping atomic.Bool

	mu     sync.Mutex
	active string
	pool   []string
	rest   []string
	next   map[string]time.Time // когда узел снова подлежит пробе
}

// NewScheduler собирает расписание. Исходы проб уезжают в монитор, пересчёт
// выбора — в селектор.
func NewScheduler(p Prober, m *Monitor, s *Selector, cfg ScheduleConfig, clk clock.Clock) *Scheduler {
	// Нулевой таймаут — это проба, которая не кончается никогда: зависший узел
	// не отдал бы исход в окно §6.3, и смерть не наступила бы вовсе.
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = DefaultScheduleConfig().ProbeTimeout
	}
	return &Scheduler{
		prober: p,
		mon:    m,
		sel:    s,
		cfg:    cfg,
		clk:    clk,
		next:   make(map[string]time.Time),
	}
}

// SetNodes раскладывает узлы по ярусам.
func (s *Scheduler) SetNodes(active string, pool, rest []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.active = active
	s.pool = append([]string(nil), pool...)
	s.rest = append([]string(nil), rest...)
	// PoolSize — граница горячего яруса, а не пожелание: пул из всей подписки
	// выродил бы расписание в полный обход раз в минуту, и заметил бы это
	// только B2 (§6.5). Лишние кандидаты уезжают в редкий ярус.
	if n := s.cfg.PoolSize; n > 0 && len(s.pool) > n {
		s.rest = append(s.rest, s.pool[n:]...)
		s.pool = s.pool[:n]
	}

	now := s.clk.Now()
	next := make(map[string]time.Time, len(s.pool)+len(s.rest)+1)
	for id, tier := range s.tiersLocked() {
		if at, ok := s.next[id]; ok {
			next[id] = at // узел уже в расписании: перекладка ярусов не сбивает его срок
			continue
		}
		if tier == TierRest {
			// Первый обход редкого яруса тоже обязан быть вразнобой: иначе
			// раскладка 200 узлов бьёт по провайдеру залпом (§6.5).
			next[id] = now.Add(s.jitterFor(id))
			continue
		}
		next[id] = now // про горячий ярус ничего не известно — пробуем сразу
	}
	s.next = next
}

// Run гоняет тикеры ярусов до отмены контекста.
func (s *Scheduler) Run(ctx context.Context) error {
	t := s.clk.NewTicker(s.tick())
	defer t.Stop()

	s.Sweep(ctx) // старт агента — та же новость, что смена сети: истории нет вовсе
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C():
			s.Sweep(ctx)
		}
	}
}

// tick — шаг тикера. Он же самый мелкий срок, который расписание способно
// соблюсти: подтверждающая проба, назначенная через полсекунды, при тике в
// период активного яруса ждала бы полминуты, то есть подтверждения бы не было.
func (s *Scheduler) tick() time.Duration {
	if s.cfg.ConfirmDelay > 0 && s.cfg.ConfirmDelay < s.cfg.Active {
		return s.cfg.ConfirmDelay
	}
	return s.cfg.Active
}

// Force — форс-проверка по событию (§6.6): прогон начинается немедленно, не
// дожидаясь тикера. Смена сети означает, что вся история проб устарела
// одновременно, и ждать следующего тика — значит держать пользователя на
// заведомо мёртвом узле.
//
// Прогон делается прямо здесь, а не сигналом в Run: событие приходит из
// супервизора, и «немедленно» обязано наблюдаться без единого тика — иначе оно
// ничем не отличается от «на следующем тике».
//
// Политика forced_probe: при выключении событие игнорируется, а прогон ждёт
// тикера — это краснит T6.
func (s *Scheduler) Force(t Trigger) {
	s.mu.Lock()
	if !policy.ForcedProbe.On() {
		s.mu.Unlock()
		return
	}
	// Горячий ярус целиком: после смены сети устарел и активный узел, и весь
	// пул, куда переключаться. Редкая подписка ждёт своего срока — залп по
	// 200 узлам на каждое событие сети запрещён §6.5.
	now := s.clk.Now()
	for _, id := range s.hotLocked() {
		s.next[id] = now
	}
	s.mu.Unlock()

	s.Sweep(context.Background())
}

// Sweep — один прогон: пробуются узлы, чей срок наступил. Это то же самое, что
// делает Run на каждом тике; наружу метод вынесен ради B2 (§8.6), который
// крутит расписание по фейковым часам и считает исходящие соединения. Второй
// драйвер расписания в бенчмарке означал бы, что мерится копия тикера, а не
// само расписание.
func (s *Scheduler) Sweep(ctx context.Context) {
	s.runMu.Lock()
	defer s.runMu.Unlock()

	s.mu.Lock()
	now := s.clk.Now()
	var due []string
	for id, tier := range s.tiersLocked() {
		if now.Before(s.next[id]) {
			continue
		}
		due = append(due, id)
		// Срок двигается до пробы, а не после: проба идёт минуты, и повторный
		// тик не должен запустить её второй раз.
		s.next[id] = now.Add(s.periodFor(tier, id))
	}
	s.mu.Unlock()

	sort.Strings(due) // порядок обхода не должен зависеть от обхода карты
	s.probe(ctx, due)
}

// probe гоняет пробы и отдаёт исходы монитору; пересчёт выбора — один на
// прогон, а не на узел, иначе выбор скачет по недособранной картине.
func (s *Scheduler) probe(ctx context.Context, ids []string) {
	if len(ids) == 0 {
		return
	}
	s.sweeping.Store(true)
	s.round(ctx, ids)
	s.confirm(ids)
	s.sweeping.Store(false)
	s.sel.Reconsider()
}

// OnDeath — обработчик смерти узла для Monitor.SetOnDeath.
//
// Смерть, увиденную трафиком (§6.15), больше некому заметить: трафик идёт вне
// расписания, и до следующего тика активного яруса пользователь остался бы на
// мёртвом узле. Внутри прогона проб хук молчит — там выбор пересчитывается один
// раз в конце, иначе он скачет по недособранной картине.
func (s *Scheduler) OnDeath(string) {
	if s.sweeping.Load() {
		return
	}
	s.sel.Reconsider()
}

// round — один заход проб по списку.
func (s *Scheduler) round(ctx context.Context, ids []string) {
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			pctx, cancel := withTimeout(ctx, s.clk, s.cfg.ProbeTimeout)
			defer cancel()
			s.mon.Observe(id, s.prober.Probe(pctx, id))
		}(id)
	}
	wg.Wait()
}

// confirm подтягивает срок узлов, которые только что не ответили.
//
// Без этого окно §6.3 набирается за k периодов яруса: активный узел, умерший
// сразу после своей пробы, был бы признан мёртвым через минуту, а §8.3 (T9,
// T11) даёт на это пять секунд. Не повтор на месте: мгновенная вторая проба —
// не второе свидетельство, а то же самое, и ждать её здесь значило бы держать
// прогон открытым на всё время паузы.
//
// Живые узлы срок не двигают, залпа по подписке (§6.5) не будет: подтверждают
// только тех, кто уже отказал, а таких на здоровой подписке нет.
func (s *Scheduler) confirm(ids []string) {
	if s.cfg.ConfirmDelay <= 0 || !policy.ConfirmProbe.On() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Только горячий ярус: подтверждать каждый отказавший узел редкой подписки
	// — это залп по провайдеру, запрещённый §6.5, а спешить с ними некуда,
	// активным ни один из них сейчас не является.
	hot := make(map[string]bool, len(s.pool)+1)
	for _, id := range s.hotLocked() {
		hot[id] = true
	}

	due := s.clk.Now().Add(s.cfg.ConfirmDelay)
	for _, id := range ids {
		if !hot[id] {
			continue
		}
		h := s.mon.Get(id)
		// Мёртвый уже всё сказал, а узел без единой неудачи в конце окна
		// подтверждать нечего.
		if h.State == Dead || len(h.Window) == 0 || h.Window[len(h.Window)-1] == OK {
			continue
		}
		if due.Before(s.next[id]) {
			s.next[id] = due
		}
	}
}

// tiersLocked — узел → ярус. Активный узел важнее пула, пул важнее остальных:
// один и тот же id, попавший в два списка, обязан пробоваться по горячему.
func (s *Scheduler) tiersLocked() map[string]Tier {
	tiers := make(map[string]Tier, len(s.pool)+len(s.rest)+1)
	for _, id := range s.rest {
		tiers[id] = TierRest
	}
	for _, id := range s.pool {
		tiers[id] = TierPool
	}
	if s.active != "" {
		tiers[s.active] = TierActive
	}
	return tiers
}

// hotLocked — активный узел и пул кандидатов.
func (s *Scheduler) hotLocked() []string {
	hot := make([]string, 0, len(s.pool)+1)
	if s.active != "" {
		hot = append(hot, s.active)
	}
	for _, id := range s.pool {
		if id != s.active {
			hot = append(hot, id)
		}
	}
	return hot
}

func (s *Scheduler) periodFor(t Tier, id string) time.Duration {
	switch t {
	case TierActive:
		return s.cfg.Active
	case TierPool:
		return s.cfg.Pool
	default:
		return s.cfg.Rest + s.jitterFor(id)
	}
}

// jitterFor — стабильный сдвиг узла внутри окна редкого яруса. Хеш от id, а не
// math/rand: сдвиг обязан переживать перезапуск агента, иначе после каждого
// рестарта подписка снова опрашивается залпом.
func (s *Scheduler) jitterFor(id string) time.Duration {
	if s.cfg.Jitter <= 0 {
		return 0
	}
	h := fnv.New64a()
	_, _ = io.WriteString(h, id)
	return time.Duration(h.Sum64() % uint64(s.cfg.Jitter))
}

// withTimeout — отмена по часам продукта. context.WithTimeout не годится: он
// смотрит на настоящее время, а §8.1 требует, чтобы окна и интервалы шли через
// инъектируемые часы, иначе тест зависшей пробы занимает эти самые секунды.
func withTimeout(parent context.Context, clk clock.Clock, d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	// Срок встаёт здесь, а не в горутине: отсчёт обязан начаться в момент
	// вызова. Внутри горутины он начинался бы, когда её доведётся запустить
	// планировщику, и на фейковых часах это разъезжается наблюдаемо.
	after := clk.After(d)
	go func() {
		select {
		case <-after:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
