// Package resolver — перехваченный DNS (§5.7): резолв через активный узел,
// кэш с TTL, отказ вместо молчания и bootstrap мимо туннеля.
//
// Пакет собран вокруг одного правила — У6 регистра
// (docs/verification-dns.md): в сообщении меняются ровно три вещи —
// идентификатор, вырезанный EDNS Client Subnet в запросе наверх и
// синтезированный пустой ответ на AAAA. Всё остальное проходит байт в байт,
// включая TTL. Отсюда и разбор через internal/dnsmsg, который отдаёт
// смещения, а не разобранные структуры: ответ клиенту собирается копированием.
//
// Спина запроса живёт здесь, а её шаги — по файлам:
//
//	phase.go    — фаза трафика: удержание, fail-close, сброс кэша (Р15, Р16, Р25)
//	rewrite.go  — AAAA и ECS, единственные разрешённые искажения (Р19, Р26)
//	cache.go    — TTL, отрицательный кэш, LRU, склейка в полёте (Р17, Р18, Р24)
//	upstream.go — два апстрима, фора, повтор по TCP, усечение клиенту
//	bootstrap.go — отдельный резолвер имён узлов, мимо туннеля (Р21, Р22)
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dnsmsg"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/phase"
)

// Числа и границы — docs/verification-dns.md §4. Выдумывать их на месте
// нельзя: у каждого в регистре назван источник и цена.
const (
	// AttemptTimeout — таймаут одной попытки наверх по UDP. Апстрим
	// спрашивается через узел, то есть RTT здесь — RTT до узла плюс RTT узла
	// до апстрима.
	AttemptTimeout = 2 * time.Second
	// ClientBudget — общий бюджет клиентского запроса. Меньше типового
	// таймаута стаба ОС намеренно: клиент обязан получить наш SERVFAIL
	// раньше, чем решит, что мы не отвечаем вовсе.
	ClientBudget = 5 * time.Second
	// DefaultHeadStart — фора второму апстриму (§5.7).
	DefaultHeadStart = 150 * time.Millisecond
	// WaitingHold — потолок удержания в traffic_phase: waiting (Р16).
	// Типовой стаб ждёт 5 с и идёт к следующему серверу (тоже к нам), поэтому
	// удержание дольше не выигрывает ничего, а проигрывает право стаба на
	// собственный ретрай.
	WaitingHold = 4 * time.Second

	// TTLCap — потолок времени жизни записи (Р17). Пола нет: 0 значит 0.
	TTLCap = 600 * time.Second
	// NegativeCap, NegativeDefault — отрицательный кэш (Р18).
	NegativeCap     = 300 * time.Second
	NegativeDefault = 30 * time.Second

	// CacheEntries — потолок записей, вытеснение LRU. Существует не ради
	// памяти, а ради предсказуемости: кэш без границы — утечка, которую видно
	// через сутки и только на машине пользователя.
	CacheEntries = 4096
	// MaxInFlight — одновременных запросов наверх (Р24). Сверх потолка
	// клиент получает SERVFAIL немедленно.
	MaxInFlight = 256

	// UpstreamEDNS — буфер EDNS0, который мы объявляем апстриму.
	UpstreamEDNS = 4096
	// ClientUDPDefault — потолок ответа клиенту по UDP без EDNS0 (RFC 6891).
	ClientUDPDefault = 512
	// StreamMax — максимум сообщения по TCP (RFC 1035 §4.2.2).
	StreamMax = 65535
)

// ErrRefused — резолвер не отвечает вовсе: запрос не разобрался настолько,
// что даже отказ собрать не из чего (D8). Netstack на такое молчит.
var ErrRefused = errors.New("resolver: запрос не разбирается")

// Transport — каким транспортом пришёл клиент.
//
// От него зависит потолок ответа: клиенту по UDP длиннее его буфера EDNS0
// вернуть нельзя, ему уходит флаг TC (D34); клиенту по TCP — можно и нужно
// вернуть полный RRset (D33).
type Transport uint8

const (
	TransportUDP Transport = iota
	TransportTCP
)

// Диалеры наверх. Два разных поля, а не вызов с флагом: проверки D51 и D52
// отличают путь через узел от пути мимо именно счётчиками диалеров, а не
// договорённостью об аргументе. То же требование, что A34 предъявляет пробам.
type (
	// DialUDPFunc — датаграммный путь через активный узел (core.DialUDP).
	DialUDPFunc func(ctx context.Context, dst netip.AddrPort) (net.PacketConn, error)
	// DialFunc — потоковый путь через активный узел (core.Dial), повтор на TC.
	DialFunc func(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	// DialDirectFunc — путь мимо туннеля (§6.8): bootstrap и фаза bypass.
	// network — "udp" или "tcp": прямой путь несёт оба, в отличие от пути
	// через узел, где датаграммы и потоки разведены по разным вызовам Xray.
	DialDirectFunc func(ctx context.Context, network string, dst netip.AddrPort) (net.Conn, error)
)

// Config — всё, от чего зависит резолвер.
type Config struct {
	// Upstreams — §5.7: 1.1.1.1:53, затем 8.8.8.8:53. Порядок значим: второй
	// получает фору, а не гонку с первой миллисекунды.
	Upstreams []netip.AddrPort
	// HeadStart — фора второму. 0 означает DefaultHeadStart.
	HeadStart time.Duration

	DialUDP    DialUDPFunc
	Dial       DialFunc
	DialDirect DialDirectFunc

	// Phase — фаза трафика, а не булево Healthy: waiting, failing и bypass —
	// три разных ответа резолвера (Р15, Р16, Р25), и свести их к одному биту
	// нельзя.
	Phase func() phase.Traffic
	// Events — подписка §5.7. Кэш сбрасывает сам резолвер: связка только
	// соединяет провода. Забытый вызов Flush() в новой ветке кода — молчаливая
	// регрессия, которую флаг отключения политики не ловит; снятая подписка
	// ловится целиком.
	Events <-chan health.SwitchEvent

	Clock clock.Clock
}

// Stats — наблюдаемая поверхность (§2 регистра). Всё, что проверки умеют
// спросить у резолвера, спрашивается отсюда: кэш не вскрывается ни на запись,
// ни на чтение, иначе проверка проверяет тестовый код.
type Stats struct {
	Generation     uint64 // растёт на каждом сбросе кэша (D19, D20)
	Entries        int    // записей в кэше, из них
	Negative       int    // отрицательных
	Hits, Misses   uint64
	Upstream       []uint64 // запросов наверх, по апстримам, в порядке Config
	UpstreamDirect uint64   // запросов мимо туннеля (bootstrap и bypass)
	TCPRetry       uint64   // повторов по TCP на флаг TC
	TruncToClient  uint64   // ответов, отданных клиенту с TC
	Coalesced      uint64   // запросов, склеенных с уже летящим
	ServFail       uint64
	InFlight       int
	Held           int // ждущих в traffic_phase: waiting
}

// counters — то из Stats, что меняется из разных горутин.
type counters struct {
	generation     atomic.Uint64
	hits, misses   atomic.Uint64
	upstreamDirect atomic.Uint64
	tcpRetry       atomic.Uint64
	truncToClient  atomic.Uint64
	coalesced      atomic.Uint64
	servFail       atomic.Uint64
	inFlight       atomic.Int64
	held           atomic.Int64

	upstream []atomic.Uint64 // по апстримам, длина == len(cfg.Upstreams)
}

// Resolver — перехваченный DNS одного процесса. Кэш общий для всех клиентов
// (Р23): все они локальны и ходят в одну сеть через один узел.
type Resolver struct {
	cfg  Config
	clk  clock.Clock
	cnt  counters
	next atomic.Uint32 // идентификатор нашего запроса наверх (Р23)

	cache  *cache
	flight *flightGroup

	// mu защищает наблюдение за фазой. Фаза приходит функцией, то есть
	// опрашивается, а не приезжает событием; чтобы удержание в waiting не
	// превращалось в опрос по таймеру, связка обязана сказать PhaseChanged,
	// и здесь лежит то, чем ждущие об этом узнают.
	mu       sync.Mutex
	wake     chan struct{} // закрывается на каждом PhaseChanged
	inBypass bool          // последняя увиденная сторона края bypass (Р25)

	wg        sync.WaitGroup
	done      chan struct{}
	closeOnce sync.Once
}

// New собирает резолвер и запускает подписку на события переключения.
func New(cfg Config) (*Resolver, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, errors.New("resolver: нужен хотя бы один апстрим (§5.7)")
	}
	if cfg.HeadStart <= 0 {
		cfg.HeadStart = DefaultHeadStart
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.Phase == nil {
		// Фазы нет — считаем, что живого узла нет. Fail-close — консервативная
		// сторона, та же, что у netstack.Config.Healthy.
		cfg.Phase = func() phase.Traffic { return phase.Failing }
	}

	r := &Resolver{
		cfg:    cfg,
		clk:    cfg.Clock,
		cache:  newCache(cfg.Clock),
		flight: newFlightGroup(),
		wake:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	r.inBypass = cfg.Phase() == phase.Bypass
	r.cnt.upstream = make([]atomic.Uint64, len(cfg.Upstreams))

	if cfg.Events != nil {
		r.wg.Add(1)
		go r.watchSwitches()
	}
	return r, nil
}

// Query — netstack.Resolver: клиент пришёл датаграммой.
//
// client и server здесь не нужны: адрес, с которого уйдёт ответ, выбирает
// netstack (D2), а кэш общий для всех клиентов (Р23). Параметры остаются ради
// интерфейса, замороженного с этапа 3.
func (r *Resolver) Query(query []byte, _, _ netip.AddrPort) ([]byte, error) {
	return r.serve(query, TransportUDP)
}

// QueryStream — netstack.StreamResolver: клиент пришёл потоком, и потолка в
// 512 байт для него нет.
func (r *Resolver) QueryStream(query []byte, _, _ netip.AddrPort) ([]byte, error) {
	return r.serve(query, TransportTCP)
}

// serve — спина запроса. Порядок шагов — контракт, а не удобство:
//
//  1. разбор. Не разобралось — молчание, и это единственное молчание в
//     резолвере (D8): собрать отказ не из чего, вопроса в сообщении нет.
//  2. фаза. failing отвечает SERVFAIL и не смотрит в кэш вовсе (Р15), иначе
//     наблюдаемое поведение fail-close зависит от истории прогона.
//  3. AAAA. Синтез пустого NOERROR раньше кэша: наверх такой вопрос не идёт,
//     и в кэше ему делать нечего (Р19).
//  4. кэш, склейка и апстрим — одним шагом, потому что промах кэша и есть
//     поход наверх.
//  5. ответ клиенту: клиентский идентификатор и потолок его буфера.
func (r *Resolver) serve(query []byte, tr Transport) ([]byte, error) {
	q, err := dnsmsg.Parse(query)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}

	ctx, cancel := r.withBudget(context.Background(), ClientBudget)
	defer cancel()

	rt, err := r.gate(ctx, q)
	if err != nil {
		return r.servfail(q, tr)
	}

	if synth := r.synthesize(q); synth != nil {
		return r.fitRaw(q, synth, tr)
	}

	gen := r.cnt.generation.Load()
	answer, err := r.lookup(ctx, q, rt)
	if err != nil {
		// Р20: запрос, застигнутый переключением узла, повторяется ровно один
		// раз — уже через нового активного. Признак «переключение состоялось» —
		// выросшая Generation: её двигает сброс кэша по подписке, то есть тот
		// самый сигнал, ради которого подписка и заведена.
		//
		// Ровно один раз, а не до победного: узел, умирающий на каждом
		// запросе, иначе умножал бы каждый клиентский вопрос на длину
		// подписки. И только внутри общего бюджета: истёкший ctx повтору не
		// даст ничего, кроме лишнего сокета.
		if !r.switched(gen) {
			return r.servfail(q, tr)
		}
		// Живых узлов могло не остаться вовсе — тогда gate откажет сразу, без
		// ожидания бюджета (D17).
		rt, gerr := r.gate(ctx, q)
		if gerr != nil {
			return r.servfail(q, tr)
		}
		if answer, err = r.lookup(ctx, q, rt); err != nil {
			return r.servfail(q, tr)
		}
	}
	return r.fit(q, answer, tr)
}

// servfail — отказ кодом, а не молчанием (§5.6, У2).
func (r *Resolver) servfail(q dnsmsg.Msg, tr Transport) ([]byte, error) {
	r.cnt.servFail.Add(1)
	raw, err := dnsmsg.ServFail(q)
	if err != nil {
		// Собрать отказ не из чего: вопроса в сообщении нет. Это тот же
		// случай, что D8, и ответ здесь — молчание, а не битые байты.
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return r.fitRaw(q, raw, tr)
}

// withBudget — контекст, истекающий по модельным часам.
//
// context.WithTimeout не годится: он живёт в настоящем времени, а §8.1 велит
// мерить интервалы инъектируемыми часами — иначе проверка бюджета в 5 секунд
// стоит пять секунд.
func (r *Resolver) withBudget(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	after := r.clk.After(d)
	go func() {
		select {
		case <-after:
			cancel()
		case <-ctx.Done():
		case <-r.done:
			cancel()
		}
	}()
	return ctx, cancel
}

// queryID — идентификатор нашего запроса наверх. Не клиентский (Р23): иначе
// локальный процесс задаёт идентификаторы наших исходящих запросов.
func (r *Resolver) queryID() uint16 { return uint16(r.next.Add(1)) }

// Snapshot — весь наблюдаемый срез одним значением.
func (r *Resolver) Snapshot() Stats {
	entries, negative := r.cache.size()
	s := Stats{
		Generation:     r.cnt.generation.Load(),
		Entries:        entries,
		Negative:       negative,
		Hits:           r.cnt.hits.Load(),
		Misses:         r.cnt.misses.Load(),
		Upstream:       make([]uint64, len(r.cnt.upstream)),
		UpstreamDirect: r.cnt.upstreamDirect.Load(),
		TCPRetry:       r.cnt.tcpRetry.Load(),
		TruncToClient:  r.cnt.truncToClient.Load(),
		Coalesced:      r.cnt.coalesced.Load(),
		ServFail:       r.cnt.servFail.Load(),
		InFlight:       int(r.cnt.inFlight.Load()),
		Held:           int(r.cnt.held.Load()),
	}
	for i := range r.cnt.upstream {
		s.Upstream[i] = r.cnt.upstream[i].Load()
	}
	return s
}

// Close снимает подписку и отпускает ждущих.
func (r *Resolver) Close() error {
	r.closeOnce.Do(func() { close(r.done) })
	r.wg.Wait()
	return nil
}

// route — как этому запросу идти наверх. Решает фаза (Р15, Р25); дальше
// апстримы берут по этому значению диалер и не переспрашивают фазу: она может
// смениться посреди резолва, и два разных ответа на один вопрос внутри одного
// запроса означали бы два разных пути у попытки и её повтора.
type route uint8

const (
	// routeNode — через активный узел: DialUDP, повтор на TC через Dial.
	routeNode route = iota
	// routeDirect — мимо туннеля через DialDirect: фаза bypass (C8).
	routeDirect
)
