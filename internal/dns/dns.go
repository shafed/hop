// Package dns — перехваченный резолвер §5.7.
//
// Резолв настоящий, не fake-IP: fake-IP оседает в кэшах приложений и переживает
// выключение VPN, после чего сайты перестают открываться необъяснимым для
// пользователя образом.
//
// Два пути наружу, и они не взаимозаменяемы:
//
//	Query      → через активный узел; подчиняется fail-close (§5.7б)
//	LookupHost → мимо туннеля, для хостнеймов самих узлов (§5.7а)
//
// Без второго на старте петля: чтобы поднять узел, надо резолвить его имя, а
// чтобы резолвить — надо поднять узел.
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time" //hop:realtime

	"golang.org/x/net/dns/dnsmessage"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/policy"
)

// Config — всё, от чего зависит резолвер.
type Config struct {
	// Upstream — резолверы, к которым ходим через туннель.
	Upstream []netip.AddrPort
	// Bootstrap — резолверы для LookupHost, мимо туннеля (§5.7а).
	Bootstrap []netip.AddrPort

	// Dial — исходящее через активный узел; в продукте это Engine.DialTCP.
	Dial func(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	// DialUDP — то же, но датаграммами: пишем и читаем сообщение целиком, без
	// префикса длины. nil — весь апстрим идёт по TCP.
	DialUDP func(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	// DialDirect — исходящее по тегу direct; в продукте Engine.DialDirect.
	DialDirect func(ctx context.Context, dst netip.AddrPort) (net.Conn, error)

	// Healthy — есть ли живой узел (§5.7б). nil означает «нет»: fail-close —
	// консервативная сторона.
	Healthy func() bool

	Clock clock.Clock

	// MinTTL, MaxTTL — рамки для TTL из ответа. Кэш уважает TTL (§5.7в), но
	// принимать от апстрима и пять секунд, и неделю одинаково нельзя.
	MinTTL, MaxTTL time.Duration
}

// Resolver — сам резолвер. Реализует netstack.Resolver.
type Resolver struct {
	cfg Config

	mu    sync.Mutex
	cache map[string]entry
}

// entry — запись кэша.
type entry struct {
	reply    []byte
	expireAt time.Time
}

// Проверка контракта §3.4: перехваченный DNS netstack — это наш резолвер.
var _ netstack.Resolver = (*Resolver)(nil)

const (
	defaultMinTTL = 5 * time.Second
	defaultMaxTTL = time.Hour

	// negativeTTL — отрицательный ответ живёт в кэше коротко: домена, которого
	// не было минуту назад, ждут снова, а держать отказ часами — это чинить
	// сеть перезапуском клиента.
	negativeTTL = 30 * time.Second

	// exchangeTimeout — сколько ждём апстрим. Query зовут из насоса netstack,
	// и висеть там нельзя: запрос без ответа обязан кончиться SERVFAIL.
	exchangeTimeout = 5 * time.Second

	// maxReply — потолок датаграммы ответа. 512 байт из RFC 1035 давно не
	// потолок: с EDNS апстрим присылает больше, а что не влезло — придёт с
	// флагом TC и будет перезапрошено по TCP.
	maxReply = 4096
)

// Апстримы по умолчанию — оба публичные и оба отвечают на 53/udp.
var defaultServers = []netip.AddrPort{
	netip.MustParseAddrPort("1.1.1.1:53"),
	netip.MustParseAddrPort("8.8.8.8:53"),
}

// dialFunc — исходящее до одного апстрима. Куда именно ведёт — через туннель
// или мимо него — решает вызывающий, подставляя Dial либо DialDirect.
type dialFunc func(ctx context.Context, dst netip.AddrPort) (net.Conn, error)

// New собирает резолвер.
func New(cfg Config) (*Resolver, error) {
	if cfg.Dial == nil {
		return nil, errors.New("dns: нет исходящего через узел")
	}
	if len(cfg.Upstream) == 0 {
		cfg.Upstream = defaultServers
	}
	if len(cfg.Bootstrap) == 0 {
		cfg.Bootstrap = defaultServers
	}
	if cfg.Healthy == nil {
		cfg.Healthy = func() bool { return false }
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.MinTTL <= 0 {
		cfg.MinTTL = defaultMinTTL
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = defaultMaxTTL
	}
	return &Resolver{cfg: cfg, cache: make(map[string]entry)}, nil
}

// Query отвечает на перехваченный запрос (netstack.Resolver).
//
// server — адрес, на который слал клиент: ответ обязан прийти именно с него,
// иначе резолвер клиента его не примет. Живых узлов нет — ответа нет: DNS
// подчиняется fail-close наравне с остальным трафиком (§5.7б), иначе приложение
// получает адрес и виснет на connect.
//
// Сам адрес источника проставляет netstack, собирая датаграмму обратно
// (`BuildUDP(f.dst, f.src, answer)`): резолвер отдаёт только сообщение, и
// подменять в нём нечего — но именно поэтому ответ обязан остаться ответом на
// тот же вопрос и с тем же идентификатором.
func (r *Resolver) Query(query []byte, client, server netip.AddrPort) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, fmt.Errorf("dns: запрос от %v неразбираем: %w", client, err)
	}
	q, err := p.Question()
	if err != nil {
		return nil, fmt.Errorf("dns: запрос от %v без вопроса: %w", client, err)
	}

	// §5.7б. Отказ, а не молчание: молчаливый дроп подвешивает приложение до
	// таймаута резолвера — та же ошибка, что запрещает §5.6.
	if !r.cfg.Healthy() {
		return answerWith(h, q, dnsmessage.RCodeServerFailure)
	}

	key := cacheKey(q)
	if cached, ok := r.lookup(key); ok {
		return withID(cached, h.ID), nil
	}

	answer, err := r.exchange(context.Background(), r.cfg.DialUDP, r.cfg.Dial, r.cfg.Upstream, query)
	if err != nil {
		return answerWith(h, q, dnsmessage.RCodeServerFailure)
	}
	r.store(key, answer)
	return withID(answer, h.ID), nil
}

// LookupHost резолвит хостнейм узла мимо туннеля (§5.7а).
//
// Политика bootstrap: при выключении запрос идёт через туннель, и старт с
// хостнеймом вместо IP уходит в петлю — это ловит TestBootstrapGoesDirect.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	// Узел, заданный адресом, резолвить нечем и незачем.
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	name, err := dnsmessage.NewName(fqdn(host))
	if err != nil {
		return nil, fmt.Errorf("dns: негодное имя %q: %w", host, err)
	}
	// Только A: §6.9 держит IPv6 заблокированным, и адрес, по которому нельзя
	// пойти, хуже отсутствия адреса.
	query, id, err := buildQuery(dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	if err != nil {
		return nil, err
	}

	dial, servers := r.cfg.DialDirect, r.cfg.Bootstrap
	if !policy.Bootstrap.On() {
		dial, servers = r.cfg.Dial, r.cfg.Upstream
	}
	if dial == nil {
		return nil, errors.New("dns: нет исходящего мимо туннеля")
	}

	// Живость узла здесь не спрашивается намеренно: bootstrap работает как раз
	// тогда, когда живого узла ещё нет. Результат в общий кэш не кладётся — он
	// получен мимо туннеля и не должен подменять то, что резолвится через узел.
	answer, err := r.exchange(ctx, nil, dial, servers, query)
	if err != nil {
		return nil, err
	}
	return addrsOf(answer, id)
}

// Flush опустошает кэш. Безусловная операция — развилка политики живёт в
// OnNodeSwitch, а не здесь.
func (r *Resolver) Flush() {
	r.mu.Lock()
	clear(r.cache)
	r.mu.Unlock()
}

// OnNodeSwitch зовётся при смене активного узла (§2, событие переключения).
//
// Кэш обязан обнулиться: тот же домен через другой узел резолвится в другой
// адрес, и старая запись отправляет трафик в CDN чужого региона (§5.7в).
//
// Политика dns_cache_flush_on_switch: при выключении кэш переживает
// переключение — это краснит T14.
func (r *Resolver) OnNodeSwitch() {
	if !policy.DNSCacheFlushOnSwitch.On() {
		return
	}
	r.Flush()
}

// Close снимает резолвер. Своих горутин у него нет: обмен живёт ровно столько,
// сколько длится вызов, — остаётся забыть кэш.
func (r *Resolver) Close() error {
	r.Flush()
	return nil
}

// lookup достаёт живую запись кэша.
func (r *Resolver) lookup(key string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[key]
	if !ok {
		return nil, false
	}
	if !r.cfg.Clock.Now().Before(e.expireAt) {
		delete(r.cache, key)
		return nil, false
	}
	return e.reply, true
}

// store кладёт ответ в кэш на срок, который назвал сам ответ.
func (r *Resolver) store(key string, answer []byte) {
	ttl := r.ttl(answer)
	if ttl <= 0 {
		return
	}
	r.mu.Lock()
	r.cache[key] = entry{reply: answer, expireAt: r.cfg.Clock.Now().Add(ttl)}
	r.mu.Unlock()
}

// ttl — сколько ответ живёт в кэше: минимальный TTL среди записей, зажатый в
// рамки конфига (§5.7в). Ноль означает «не кэшировать».
func (r *Resolver) ttl(answer []byte) time.Duration {
	var p dnsmessage.Parser
	h, err := p.Start(answer)
	if err != nil {
		return 0
	}
	if err := p.SkipAllQuestions(); err != nil {
		return 0
	}
	switch {
	case h.RCode == dnsmessage.RCodeNameError:
		return negativeTTL
	case h.RCode != dnsmessage.RCodeSuccess:
		// Отказ апстрима (SERVFAIL, REFUSED) — не факт о домене, а факт о самом
		// апстриме: кэшировать его значит продлевать чужую аварию.
		return 0
	}

	min := time.Duration(0)
	n := 0
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return 0
		}
		if err := p.SkipAnswer(); err != nil {
			return 0
		}
		if ttl := time.Duration(ah.TTL) * time.Second; n == 0 || ttl < min {
			min = ttl
		}
		n++
	}
	if n == 0 {
		return negativeTTL // NODATA — тот же отрицательный ответ, только вежливее
	}
	if min < r.cfg.MinTTL {
		min = r.cfg.MinTTL
	}
	if min > r.cfg.MaxTTL {
		min = r.cfg.MaxTTL
	}
	return min
}

// exchange опрашивает серверы по очереди до первого ответа.
//
// udp может быть nil — тогда обмен идёт только потоком. Усечённый ответ по UDP
// не ответ: RFC 1035 §4.2.1 велит перезапросить по TCP, иначе от набора записей
// остаётся начало, и приложение получит не тот адрес, а первый попавшийся.
func (r *Resolver) exchange(ctx context.Context, udp, stream dialFunc, servers []netip.AddrPort, query []byte) ([]byte, error) {
	last := errors.New("dns: апстримы не заданы")
	for _, s := range servers {
		if udp != nil {
			answer, err := r.ask(ctx, udp, s, query, false)
			switch {
			case err != nil:
				last = err
			case !truncated(answer):
				return answer, nil
			}
		}
		answer, err := r.ask(ctx, stream, s, query, true)
		if err != nil {
			last = err
			continue
		}
		return answer, nil
	}
	return nil, last
}

// ask — один обмен с одним сервером.
//
// Таймаут не через SetDeadline: часы в продукте инъектируемые (§8.1), а дедлайн
// соединения считается от настоящего времени — с фейковыми часами он сработал
// бы мгновенно. Поэтому гонка обмена с Clock.After, а отмена доходит до чтения
// закрытием соединения.
func (r *Resolver) ask(ctx context.Context, dial dialFunc, server netip.AddrPort, query []byte, framed bool) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		answer []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		answer, err := roundTrip(ctx, dial, server, query, framed)
		done <- result{answer, err}
	}()

	select {
	case res := <-done:
		return res.answer, res.err
	case <-r.cfg.Clock.After(exchangeTimeout):
		return nil, fmt.Errorf("dns: %v не ответил за %v", server, exchangeTimeout)
	}
}

// roundTrip отправляет запрос и читает ответ на одном соединении.
func roundTrip(ctx context.Context, dial dialFunc, server netip.AddrPort, query []byte, framed bool) ([]byte, error) {
	c, err := dial(ctx, server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	// Чтение про ctx не знает, поэтому отмена обрывает обмен закрытием
	// соединения: иначе горутина ask пережила бы свой таймаут.
	defer context.AfterFunc(ctx, func() { _ = c.Close() })()

	if framed {
		return streamExchange(c, query)
	}
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, maxReply)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// streamExchange — DNS поверх потока: сообщение с двухбайтовым префиксом длины
// (RFC 7766). Границу датаграммы поток не хранит, и без префикса ответ не
// отличить от его половины.
func streamExchange(c net.Conn, query []byte) ([]byte, error) {
	msg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(msg, uint16(len(query)))
	copy(msg[2:], query)
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}

	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	answer := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(c, answer); err != nil {
		return nil, err
	}
	return answer, nil
}
