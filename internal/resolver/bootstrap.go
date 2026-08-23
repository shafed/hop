package resolver

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dnsmsg"
	"github.com/shafed/hop/internal/policy"
)

// Bootstrap — резолвер имён узлов, мимо туннеля (§5.7а, Р21, Р22).
//
// §5.7(а) даёт петлю на старте: чтобы дозвониться до узла, надо резолвить его
// имя, а обычный резолв идёт через узел. Отдельный тип, а не режим того же
// Resolver — решение §2 регистра (требование 6): один объект с флагом «этот
// запрос служебный» означал бы, что сброс основного кэша при переключении
// узла (Р25) обязан помнить, какие записи не трогать, — и это ровно та
// развилка, которую забывают в новой ветке кода. У Bootstrap нет ни
// подписки на health.SwitchEvent, ни поля Phase: он не отзывается ни на
// смену сети, ни на смену узла, ни на fail-close (Р21, D53–D55) — потому что
// у него просто нет входа, которым эти новости могли бы до него дойти. Это
// не решение, которое можно выключить, это форма типа.
//
// Ходит Bootstrap только DialDirect (Р22, §6.8): другого диалера в его
// Config нет вовсе — выбор между резолвом мимо туннеля (bootstrap) и через
// узел (общий резолвер, флаг bootstrap выключен) делает связка, которая
// решает, кого из двух резолверов спросить. Bootstrap.Resolve тем не менее
// сам отказывается работать, когда флаг bootstrap выключен (см. ниже, у
// Resolve) — иначе проверки D51/D52, живущие в этом пакете, не смогли бы
// покраснеть без связки, которой в этой задаче нет (см. task-8-brief.md,
// «Чего в этой задаче нет»).
type Bootstrap struct {
	cfg  BootstrapConfig
	clk  clock.Clock
	next atomic.Uint32 // свой счётчик id наверх — не клиентский и не общий с Resolver (Р23, тот же принцип)

	mu    sync.Mutex
	byKey map[string]*list.Element
	lru   *list.List

	hits, stale atomic.Uint64
	upstream    []atomic.Uint64
}

// BootstrapConfig — всё, от чего зависит bootstrap.
type BootstrapConfig struct {
	// Upstreams — тот же список, что у основного резолвера (Р22): системная
	// DNS-конфигурация к этому моменту уже наша (§5.10), и читать её обратно
	// значило бы читать либо адрес TUN, либо гонку с собственной установкой.
	Upstreams []netip.AddrPort

	// DialDirect — единственный путь наверх (§6.8): текущий физический
	// интерфейс, не http.DefaultTransport и не голый net.Dialer. Тип общий с
	// Resolver.Config.DialDirect — тот же диалер связка передаёт в оба места.
	DialDirect DialDirectFunc

	Clock clock.Clock
}

// Числа §4 регистра, свои для bootstrap-кэша: он не тот кэш, что у Resolver
// (§2, требование 6), и границы у него другие — не потолок TTL, а пол.
const (
	// BootstrapEntries — потолок записей, вытеснение LRU. Тех же оснований,
	// что у CacheEntries: предсказуемость, а не память.
	BootstrapEntries = 256
	// BootstrapTTLFloor — пол TTL (Р21). У основного кэша пола нет и не
	// может быть (Р17: короткий TTL — это балансировщик, который надо
	// уважать); здесь наоборот: промах стоит недоступности всей подписки
	// ровно в момент смены сети, поэтому запись не убивают собственным
	// коротким TTL апстрима — держат минимум пять минут, а протухшую отдают
	// и вовсе (serve-stale, ниже). Потолка у bootstrap-TTL нет по той же
	// причине, по которой его нет у Р17: узел, переехавший на новый адрес,
	// найдут пробы (§6.3) — это уже существующий механизм, отдельный от TTL.
	BootstrapTTLFloor = 300 * time.Second
)

var (
	// errBootstrapDisabled — флаг bootstrap выключен. Bootstrap не пытается
	// сам сходить общим путём вместо себя (у него нет для этого диалера);
	// он просто отказывается работать, и это ровно то поведение, на котором
	// D51 и D52 обязаны покраснеть.
	errBootstrapDisabled = errors.New("resolver: bootstrap отключён политикой bootstrap")
	// errBootstrapNoAnswer — апстрим ответил, но без единой годной A-записи:
	// NXDOMAIN, NODATA или RCODE-отказ. Не отличаем их друг от друга —
	// bootstrap не отдаёт клиенту ответ, ему нужны адреса или их нет.
	errBootstrapNoAnswer = errors.New("resolver: bootstrap не получил ни одного адреса")
)

// bootstrapEntry — одна запись bootstrap-кэша.
//
// В отличие от entry основного кэша, здесь не хранится сырое сообщение:
// Bootstrap отдаёт вызывающему адреса, а не байты DNS-ответа (у Resolve в
// сигнатуре из §2 регистра нет клиента, которому нести TTL и секции байт в
// байт, — только результат резолва), и хранить то, что никогда не отдаётся
// как есть, было бы самодеятельностью в другую сторону.
type bootstrapEntry struct {
	key     string
	addrs   []netip.Addr
	expires time.Time
}

// NewBootstrap собирает bootstrap. DialDirect обязателен: без него Bootstrap
// не может исполнить единственное, ради чего он существует (Р22).
func NewBootstrap(cfg BootstrapConfig) (*Bootstrap, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, errors.New("resolver: bootstrap нужен хотя бы один апстрим (§5.7)")
	}
	if cfg.DialDirect == nil {
		return nil, errors.New("resolver: bootstrap нужен DialDirect (§6.8)")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	b := &Bootstrap{
		cfg:   cfg,
		clk:   cfg.Clock,
		byKey: make(map[string]*list.Element),
		lru:   list.New(),
	}
	b.upstream = make([]atomic.Uint64, len(cfg.Upstreams))
	return b, nil
}

// BootstrapStats — наблюдаемая поверхность bootstrap-кэша (§2 регистра).
type BootstrapStats struct {
	Entries  int      // записей в кэше, включая просроченные: serve-stale держит их нарочно (Р21)
	Hits     uint64   // отдано из кэша свежим
	Stale    uint64   // отдано из кэша просроченным, потому что апстрим недоступен (D56)
	Upstream []uint64 // запросов наверх, по апстримам, в порядке BootstrapConfig.Upstreams
}

// Stats — снимок счётчиков. Кэш вскрывается только отсюда и через Resolve —
// тот же принцип §2 регистра, требование 5, что и у Resolver.
func (b *Bootstrap) Stats() BootstrapStats {
	b.mu.Lock()
	entries := b.lru.Len()
	b.mu.Unlock()

	s := BootstrapStats{
		Entries:  entries,
		Hits:     b.hits.Load(),
		Stale:    b.stale.Load(),
		Upstream: make([]uint64, len(b.upstream)),
	}
	for i := range b.upstream {
		s.Upstream[i] = b.upstream[i].Load()
	}
	return s
}

// Resolve — имя узла в адреса, мимо туннеля.
//
// Флаг bootstrap проверяется первым делом. Р22/D51/D52 требуют, чтобы
// выключенный флаг отправлял имена узлов общим путём через туннель — но этот
// путь целиком снаружи Bootstrap (у него нет Dial/DialUDP, см. комментарий
// у типа), и решает его связка. Здесь, в границах этого типа, выключенный
// флаг означает единственное доступное ему проявление того же решения:
// Bootstrap отказывается резолвить сам, а не притворяется работающим в обход
// собственной политики. Именно на этом отказе краснеют D51 и D52.
func (b *Bootstrap) Resolve(host string) ([]netip.Addr, error) {
	if !policy.Bootstrap.On() {
		return nil, errBootstrapDisabled
	}

	key := bootstrapKey(host)

	if e, fresh := b.lookup(key); e != nil && fresh {
		b.hits.Add(1)
		return e.addrs, nil
	}

	addrs, ttl, err := b.fetch(context.Background(), host)
	if err == nil {
		b.put(key, addrs, ttl)
		return addrs, nil
	}

	// Апстрим недоступен (или ответил мусором) — просроченная запись лучше
	// отказа: промах здесь стоит недоступности всей подписки ровно в тот
	// момент, когда сеть только что сменилась, то есть в самый частый момент
	// отказа (Р21, D56).
	if e, _ := b.lookup(key); e != nil {
		b.stale.Add(1)
		return e.addrs, nil
	}
	return nil, err
}

// bootstrapKey — та же нормализация написания, что делает NewQuery при
// кодировании имени в проводной вид (обрезает конечную точку), плюс
// нижний регистр: иначе "node1.example.com" и "node1.example.com." или
// "Node1.example.com" промахивались бы друг мимо друга в этом кэше.
// Написание в ответе никого не заботит: Resolve отдаёт адреса, а не байты
// DNS-сообщения, значит проблемы Р23 (0x20-рандомизация стаба) здесь нет.
func bootstrapKey(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// lookup — запись по ключу, если есть, и свежая ли она.
//
// Протухшая запись не выбрасывается, в отличие от cache.get: serve-stale
// (Р21) обязан её найти после неудачного похода наверх. Из кэша её выселяет
// только LRU при превышении BootstrapEntries либо более новый успешный
// ответ на тот же вопрос.
func (b *Bootstrap) lookup(key string) (*bootstrapEntry, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	el, ok := b.byKey[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*bootstrapEntry)
	b.lru.MoveToFront(el)
	return e, b.clk.Now().Before(e.expires)
}

// put кладёт свежий ответ, замещая прежнюю запись целиком: апстрим мог
// сменить и адреса, и TTL.
func (b *Bootstrap) put(key string, addrs []netip.Addr, ttl time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if el, exists := b.byKey[key]; exists {
		b.removeLocked(el)
	}
	e := &bootstrapEntry{key: key, addrs: addrs, expires: b.clk.Now().Add(ttl)}
	b.byKey[key] = b.lru.PushFront(e)

	for b.lru.Len() > BootstrapEntries {
		b.removeLocked(b.lru.Back())
	}
}

func (b *Bootstrap) removeLocked(el *list.Element) {
	e := el.Value.(*bootstrapEntry)
	b.lru.Remove(el)
	delete(b.byKey, e.key)
}

// fetch — запрос типа A по очереди ко всем апстримам BootstrapConfig.Upstreams.
//
// Без форы второму: у основного резолвера она существует ради латентности
// клиентского запроса под общим бюджетом в 5 с (§5.7), а bootstrap ничьим
// клиентским бюджетом не связан — это фоновый резолв на старте и на смене
// узла, и гонка с первой миллисекунды удвоила бы трафик наверх без всякой
// пользы: если первый апстрим ответил, второй спрашивать незачем.
func (b *Bootstrap) fetch(ctx context.Context, host string) ([]netip.Addr, time.Duration, error) {
	id := uint16(b.next.Add(1))
	wire, err := dnsmsg.NewQuery(id, host, dnsmsg.TypeA)
	if err != nil {
		return nil, 0, err
	}
	q, err := dnsmsg.Parse(wire)
	if err != nil {
		// Сюда не должны попадать: собственный NewQuery не должен отдавать
		// то, что не разбирается им же обратно.
		return nil, 0, fmt.Errorf("resolver: bootstrap не смог разобрать собственный запрос: %w", err)
	}

	var lastErr error
	for i := range b.cfg.Upstreams {
		m, err := b.attempt(ctx, i, wire, id, q)
		if err != nil {
			lastErr = err
			continue
		}
		addrs, err := addressesA(m)
		if err != nil {
			lastErr = err
			continue
		}
		return addrs, bootstrapTTL(m), nil
	}
	if lastErr == nil {
		lastErr = errBootstrapNoAnswer
	}
	return nil, 0, lastErr
}

// attempt — один апстрим: датаграмма мимо туннеля и таймаут попытки.
//
// Таймаут строится на clk.After и закрытии сокета, а не на SetReadDeadline
// («правила дома», §8.1): дедлайн сокета — настоящее время, а модельные часы
// теста не могут его сдвинуть. Читающая горутина уходит вместе с сокетом —
// attempt не возвращается, пока она не подтвердит уход (reader.Wait), тем же
// приёмом, что и askUDP у основного резолвера (upstream.go, ask): молчащий
// апстрим — штатное состояние сети (D40/D44 регистра), а не повод копить
// горутины.
//
// accept, sameQuestion и checkSections — общие с основным путём наверх
// (upstream.go): один способ отличить свой ответ от чужой датаграммы и от
// мусора на весь пакет, а не два разных, которые могут разойтись.
func (b *Bootstrap) attempt(ctx context.Context, idx int, wire []byte, id uint16, q dnsmsg.Msg) (dnsmsg.Msg, error) {
	dst := b.cfg.Upstreams[idx]
	conn, err := b.cfg.DialDirect(ctx, "udp", dst)
	if err != nil {
		return dnsmsg.Msg{}, fmt.Errorf("bootstrap %s: %w", dst, err)
	}

	var reader sync.WaitGroup
	defer reader.Wait()
	defer conn.Close()

	if _, err := conn.Write(wire); err != nil {
		return dnsmsg.Msg{}, fmt.Errorf("bootstrap %s: %w", dst, err)
	}
	b.upstream[idx].Add(1)

	answers := make(chan attemptResult, 1)
	reader.Add(1)
	go func() {
		defer reader.Done()
		// Наш запрос без EDNS0 — апстрим не вправе ответить длиннее 512
		// байт (RFC 6891 §6.2.3); адреса узлов не бывают RRset такого
		// размера, чтобы это стало проблемой.
		buf := make([]byte, dnsmsg.MinUDPSize)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				answers <- attemptResult{err: err}
				return
			}
			m, mine, err := accept(buf[:n], id, q)
			if !mine {
				continue
			}
			answers <- attemptResult{msg: m, err: err}
			return
		}
	}()

	select {
	case res := <-answers:
		return res.msg, res.err
	case <-b.clk.After(AttemptTimeout):
		return dnsmsg.Msg{}, fmt.Errorf("%w: %s", errAttemptTimeout, dst)
	case <-ctx.Done():
		return dnsmsg.Msg{}, ctx.Err()
	}
}

// addressesA — адреса из секции ANSWER ответа на A-запрос.
//
// Bootstrap — единственное место в пакете, которому нужны сами значения
// записей, а не только их границы: Resolve отдаёт vызывающему netip.Addr, а
// не байты сообщения (в отличие от Resolver, который обязан пронести ответ
// клиенту байт в байт по У6 и потому значений не читает). RDATA длиной не в
// 4 байта — не валидная A-запись; пропускаем её, а не падаем: апстрим,
// подмешавший в ANSWER что-то ещё, не должен обрушить резолв остальных
// адресов (тот же принцип терпимости к мусору, что у D15).
func addressesA(m dnsmsg.Msg) ([]netip.Addr, error) {
	if rc := m.Header.Rcode(); rc != dnsmsg.RcodeNoError {
		return nil, fmt.Errorf("%w: rcode %d", errBootstrapNoAnswer, rc)
	}

	var addrs []netip.Addr
	s := m.Scan()
	for s.Next() {
		rr := s.RR()
		if rr.Section != dnsmsg.SectionAnswer || rr.Type != dnsmsg.TypeA {
			continue
		}
		if rr.RDEnd-rr.RDStart != 4 {
			continue
		}
		addrs = append(addrs, netip.AddrFrom4([4]byte(m.Raw[rr.RDStart:rr.RDEnd])))
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", errBadAnswer, err)
	}
	if len(addrs) == 0 {
		return nil, errBootstrapNoAnswer
	}
	return addrs, nil
}

// bootstrapTTL — минимум TTL по ANSWER, поднятый до BootstrapTTLFloor.
//
// Пол, а не потолок (Р17 наоборот): у основного кэша короткий TTL уважают
// буквально, потому что это приём балансировщиков; здесь короткий TTL узла
// хостинг-провайдера ничего не выигрывает и только заставляет резолвить
// имя узла на каждую смену сети — ровно то, ради чего Р21 назначил пол.
func bootstrapTTL(m dnsmsg.Msg) time.Duration {
	var secs uint32
	if f, err := m.Facts(); err == nil {
		secs = f.MinTTL
	}
	d := time.Duration(secs) * time.Second
	if d < BootstrapTTLFloor {
		d = BootstrapTTLFloor
	}
	return d
}
