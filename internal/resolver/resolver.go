// Package resolver — перехваченный DNS из §5.7: настоящий резолв через
// активный узел, кэш с TTL, сброс кэша при смене узла, bootstrap мимо туннеля.
//
// Куда он встроен. netstack принимает по первому пакету вердикт hijack-dns
// (§3.4, п. 1) и отдаёт сюда полезную нагрузку — и по UDP, и по TCP. Обратно
// уходят готовые байты ответа; сборкой пакета и адресом источника занимается
// netstack, потому что ответ обязан прийти с того адреса, на который слал
// клиент.
//
// Чего пакет не знает. Ни про Xray, ни про подписки, ни про health (§3.4).
// Наружу вынесены ровно три вещи: Transport («задать вопрос апстриму»),
// Healthy («есть ли живой узел») и ActiveNode («какой именно»). Всё, от чего
// резолвер зависит, видно в Config.
//
// Три решения, которых нет в §5.7, и причины — они же записаны в спеку:
//
//  1. Апстрим — фиксированный публичный резолвер (DefaultServers), а не
//     системный. Системный лежит по ту сторону туннеля и обслуживается
//     провайдером: спросить его — значит слить провайдеру ровно тот список
//     имён, ради сокрытия которого §5.7 и написан.
//  2. Fail-close отвечает SERVFAIL, а не молчанием. §5.6 требует «отказ, а не
//     молчание» для пакетов; у DNS ровно та же развилка, и молчание здесь
//     стоит клиенту полного таймаута резолвера (5 с в glibc) на каждое имя.
//  3. Пока §5.6 держит стартовое окно (Healthy() ещё true, а узла нет),
//     запрос **ждёт и переспрашивает**, а не отказывает. Иначе первое же
//     приложение получает SERVFAIL в те секунды, пока идёт первый обход
//     подписки, — то самое, против чего написан абзац про стартовый бюджет.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/shafed/hop/internal/clock"
)

// Transport — как задать вопрос апстриму. Реализаций две: NodeTransport
// (через активный узел, тот же путь, что у трафика, — §6.7) и bootstrap-овая
// (мимо туннеля, §5.7а).
//
// stream=true означает DNS поверх TCP: единственный способ дослать запрос,
// на который апстрим ответил TC=1.
type Transport interface {
	Exchange(ctx context.Context, server netip.AddrPort, query []byte, stream bool) ([]byte, error)
}

// DefaultServers — апстрим по умолчанию. Два независимых оператора: один
// недоступный резолвер не должен превращаться в отсутствие DNS.
var DefaultServers = []netip.AddrPort{
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 53),
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53),
}

// Стартовые значения. Числа стартовые: их вправе опровергнуть тест.
const (
	// DefaultTimeout — весь бюджет одного запроса, включая ожидание узла в
	// стартовом окне. Меньше, чем таймаут клиента (5 с в glibc), чтобы ответ
	// об отказе пришёл раньше, чем клиент сдастся сам.
	DefaultTimeout = 4 * time.Second
	// DefaultAttemptTimeout — бюджет одного похода в апстрим.
	DefaultAttemptTimeout = 2 * time.Second
	// DefaultRetryDelay — пауза перед переспросом, пока §5.6 держит стартовое
	// окно.
	DefaultRetryDelay = 200 * time.Millisecond

	// DefaultMinTTL — нижняя граница кэширования. Апстрим, отдающий TTL=0 на
	// каждое имя, иначе превращает кэш в пустой звук.
	DefaultMinTTL = 5 * time.Second
	// DefaultMaxTTL — верхняя. Сутки в кэше пережили бы и смену сети, и
	// перезапуск узла.
	DefaultMaxTTL = time.Hour
	// DefaultNegativeTTL — сколько держится отрицательный ответ.
	DefaultNegativeTTL = 30 * time.Second
	// DefaultMaxEntries — потолок кэша. Кэш — это кэш: переполнение выбрасывает
	// записи, а не отказывает в резолве.
	DefaultMaxEntries = 4096
)

// Config — всё, от чего зависит резолвер.
type Config struct {
	// Transport — путь к апстриму. nil означает «резолва нет»: каждый запрос
	// получает SERVFAIL.
	Transport Transport
	// Servers — апстрим. Пусто — DefaultServers.
	Servers []netip.AddrPort
	Clock   clock.Clock

	// Healthy — есть ли живой узел (§5.7б, §5.6). nil означает «нет»:
	// fail-close — консервативная сторона.
	Healthy func() bool
	// ActiveNode — id активного узла. Он же метка записи кэша: §5.7в требует
	// сбросить кэш при смене узла, и запись, помеченная чужим узлом, — это и
	// есть сброс, только без гонки с событием переключения.
	ActiveNode func() string

	Timeout        time.Duration
	AttemptTimeout time.Duration
	RetryDelay     time.Duration
	MinTTL         time.Duration
	MaxTTL         time.Duration
	NegativeTTL    time.Duration
	MaxEntries     int
}

// Stats — наблюдаемость: без счётчиков «взято из кэша» и «спрошено у апстрима»
// неразличимы снаружи.
type Stats struct {
	Queries   int64
	Hits      int64
	Misses    int64
	Upstream  int64 // походов в апстрим
	Failed    int64 // ответов SERVFAIL
	Entries   int   // живых записей кэша
	Flushed   int64 // записей, выброшенных сбросом
	NodeStale int64 // записей, отвергнутых из-за смены узла (§5.7в)
}

// Resolver — сам резолвер.
type Resolver struct {
	cfg     Config
	clk     clock.Clock
	servers []netip.AddrPort

	mu      sync.Mutex
	cache   map[cacheKey]*entry
	inFlt   map[flightKey]*call
	stats   Stats
	flushed int64
}

// New собирает резолвер.
func New(cfg Config) *Resolver {
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.Healthy == nil {
		cfg.Healthy = func() bool { return false }
	}
	if cfg.ActiveNode == nil {
		cfg.ActiveNode = func() string { return "" }
	}
	setDefault := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	setDefault(&cfg.Timeout, DefaultTimeout)
	setDefault(&cfg.AttemptTimeout, DefaultAttemptTimeout)
	setDefault(&cfg.RetryDelay, DefaultRetryDelay)
	setDefault(&cfg.MinTTL, DefaultMinTTL)
	setDefault(&cfg.MaxTTL, DefaultMaxTTL)
	setDefault(&cfg.NegativeTTL, DefaultNegativeTTL)
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	servers := cfg.Servers
	if len(servers) == 0 {
		servers = DefaultServers
	}
	return &Resolver{
		cfg:     cfg,
		clk:     cfg.Clock,
		servers: servers,
		cache:   make(map[cacheKey]*entry),
		inFlt:   make(map[flightKey]*call),
	}
}

// Query — реализация netstack.Resolver. client и server нужны не резолву, а
// наблюдаемости: сборкой ответного пакета занимается netstack.
func (r *Resolver) Query(query []byte, client, server netip.AddrPort) ([]byte, error) {
	_, _ = client, server

	q, err := parseQuestion(query)
	if err != nil {
		// Битый запрос: если разобрался хотя бы заголовок — отвечаем FORMERR,
		// иначе отвечать не на что и не от чьего имени.
		if errors.Is(err, errNoHeader) {
			return nil, err
		}
		return errorReply(q, dnsmessage.RCodeFormatError)
	}

	r.count(func(s *Stats) { s.Queries++ })

	// Fail-close (§5.7б). Проверка стоит до кэша: живых узлов нет — резолва
	// нет, в том числе из кэша. Иначе VPN «работает» ровно настолько, чтобы
	// приложение получило адрес и упёрлось в отказ на connect.
	if !r.cfg.Healthy() {
		r.count(func(s *Stats) { s.Failed++ })
		return errorReply(q, dnsmessage.RCodeServerFailure)
	}

	// AAAA — пустой NOERROR, не поход в апстрим. §6.9 блокирует IPv6 на уровне
	// маршрутов TUN, поэтому настоящий AAAA-ответ означал бы, что приложение
	// сперва попробует адрес, который заведомо никуда не ведёт, и только по
	// таймауту happy eyeballs перейдёт на IPv4. NODATA говорит ему то же самое
	// сразу и честно: адресов этого семейства у нас нет.
	if q.typ == dnsmessage.TypeAAAA {
		return errorReply(q, dnsmessage.RCodeSuccess)
	}

	key := q.key()
	node := r.cfg.ActiveNode()

	if msg, ok := r.lookup(key, node); ok {
		r.count(func(s *Stats) { s.Hits++ })
		return pack(msg, q)
	}
	r.count(func(s *Stats) { s.Misses++ })

	msg, err := r.fetch(key, q, node)
	if err != nil {
		r.count(func(s *Stats) { s.Failed++ })
		return errorReply(q, dnsmessage.RCodeServerFailure)
	}
	return pack(msg, q)
}

// Flush выбрасывает кэш целиком. Зовётся на смене сети и на явном down; смену
// узла ловит метка записи (§5.7в), а не этот вызов, — событие переключения
// приходит асинхронно, и между ним и следующим запросом успел бы пролезть
// ответ из кэша чужого узла.
func (r *Resolver) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stats.Flushed += int64(len(r.cache))
	r.cache = make(map[cacheKey]*entry)
}

// Stats — снимок счётчиков.
func (r *Resolver) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.stats
	s.Entries = len(r.cache)
	return s
}

// fetch — один поход за ответом с дедупликацией одинаковых запросов.
//
// Дедупликация обязательна, а не приятна: клиент по UDP переспрашивает сам,
// не дожидаясь ответа, и без неё каждый ретрансмит превращается в отдельный
// поход в апстрим через узел.
func (r *Resolver) fetch(key cacheKey, q question, node string) (*dnsmessage.Message, error) {
	// Узел — часть ключа склейки, а не только метки в кэше: переключение
	// посреди похода не должно раздавать ответ прежнего узла тем, кто спросил
	// уже после него (§5.7в).
	fk := flightKey{key: key, node: node}

	r.mu.Lock()
	if c, ok := r.inFlt[fk]; ok {
		r.mu.Unlock()
		<-c.done
		return c.msg, c.err
	}
	c := &call{done: make(chan struct{})}
	r.inFlt[fk] = c
	r.mu.Unlock()

	c.msg, c.err = r.exchange(q, node)
	close(c.done)

	r.mu.Lock()
	delete(r.inFlt, fk)
	r.mu.Unlock()
	return c.msg, c.err
}

// exchange спрашивает апстрим, пока не кончится бюджет запроса.
//
// Цикл — это и есть ожидание стартового окна §5.6: пока Healthy() держится,
// неудача узла означает «узла ещё нет», а не «резолва нет». Как только
// Healthy() падает, ждать больше нечего.
func (r *Resolver) exchange(q question, node string) (*dnsmessage.Message, error) {
	if r.cfg.Transport == nil {
		return nil, errors.New("resolver: нет транспорта")
	}
	deadline := r.clk.Now().Add(r.cfg.Timeout)
	var lastErr error
	for {
		for _, srv := range r.servers {
			msg, err := r.ask(srv, q, node)
			if err == nil {
				return msg, nil
			}
			lastErr = err
			if r.clk.Now().After(deadline) {
				return nil, lastErr
			}
		}
		if !r.cfg.Healthy() || !r.clk.Now().Add(r.cfg.RetryDelay).Before(deadline) {
			if lastErr == nil {
				lastErr = errors.New("resolver: апстрим не ответил")
			}
			return nil, lastErr
		}
		<-r.clk.After(r.cfg.RetryDelay)
	}
}

// ask — один вопрос одному серверу, с досылкой по TCP на TC=1.
func (r *Resolver) ask(srv netip.AddrPort, q question, node string) (*dnsmessage.Message, error) {
	wire, id, err := q.wire()
	if err != nil {
		return nil, err
	}

	send := func(stream bool) (*dnsmessage.Message, error) {
		ctx, cancel := context.WithTimeout(context.Background(), r.cfg.AttemptTimeout)
		defer cancel()
		r.count(func(s *Stats) { s.Upstream++ })
		raw, err := r.cfg.Transport.Exchange(ctx, srv, wire, stream)
		if err != nil {
			return nil, err
		}
		return q.accept(raw, id)
	}

	msg, err := send(false)
	if err != nil {
		return nil, err
	}
	if msg.Header.Truncated {
		// TC=1: ответ не поместился в датаграмму. Разбирать обрезок нельзя —
		// в нём не хватает записей, и кэшировать его тем более.
		msg, err = send(true)
		if err != nil {
			return nil, err
		}
	}
	r.store(q.key(), msg, node)
	return msg, nil
}

// flightKey — что считается «тем же самым походом»: тот же вопрос через тот же
// узел.
type flightKey struct {
	key  cacheKey
	node string
}

// call — один поход за ответом, разделяемый одинаковыми запросами.
type call struct {
	done chan struct{}
	msg  *dnsmessage.Message
	err  error
}

func (r *Resolver) count(f func(*Stats)) {
	r.mu.Lock()
	f(&r.stats)
	r.mu.Unlock()
}

var (
	// errNoHeader — не разобрался даже заголовок.
	errNoHeader = errors.New("resolver: неразборчивый запрос")
	// errNoQuestion — заголовок разобрался, вопроса нет.
	errNoQuestion = errors.New("resolver: в запросе нет вопроса")
)

// errorReply — ответ с кодом ошибки. Отказ, а не молчание: клиент узнаёт исход
// сразу, а не через полный таймаут резолвера.
func errorReply(q question, rcode dnsmessage.RCode) ([]byte, error) {
	m := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 q.id,
			Response:           true,
			RecursionDesired:   q.rd,
			RecursionAvailable: true,
			RCode:              rcode,
		},
	}
	if q.name.Length > 0 {
		m.Questions = []dnsmessage.Question{{Name: q.name, Type: q.typ, Class: q.class}}
	}
	b, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("resolver: ответ не собрался: %w", err)
	}
	return b, nil
}

// canonical — имя в виде, годном для ключа кэша: регистр в DNS незначим
// (RFC 4343), а апстрим вправе вернуть его в любом.
func canonical(name string) string { return strings.ToLower(name) }
