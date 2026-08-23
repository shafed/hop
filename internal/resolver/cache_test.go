package resolver

import (
	"bytes"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dnsmsg"
	"github.com/shafed/hop/internal/dnstest"
	"github.com/shafed/hop/internal/phase"
)

// Проверки кэша: TTL и его границы (Р17, D21–D25), отрицательный кэш (Р18,
// D26–D29), ключ и регистр имени (Р23, D30, D31), потолок с вытеснением LRU
// (D32), склейка в полёте и потолок летящих (Р24, D38, D39).
//
// Ни одна проверка не кладёт запись в кэш руками: §2 регистра, требование 5 —
// кэш вскрывается только через Query и Stats, а протухание ставится сдвигом
// фейковых часов. Проверка, подложившая запись, проверяла бы тестовый код.

// cacheAddr — единственный апстрим стенда. Один, а не два: фора второму —
// предмет D41–D43 и чужой задачи, а кэшу безразлично, кто именно ответил.
var cacheAddr = netip.MustParseAddrPort("203.0.113.53:53")

// newCacheTestResolver — резолвер на фейковых часах с поддельным апстримом.
//
// Фаза proxied: гейт (заглушка З7) её пока не смотрит, но значение обязано
// быть таким, при котором и настоящий гейт пропустит запрос, — иначе проверка
// начнёт молча проверять чужую заглушку. Часы возвращаются: протухание
// ставится только ими.
func newCacheTestResolver(t *testing.T) (*Resolver, *dnstest.Upstream, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(time.Unix(0, 0))
	dclk := dnstest.NewClock(clk)
	up := dnstest.New(dclk)

	r, err := New(Config{
		Upstreams:  []netip.AddrPort{cacheAddr},
		DialUDP:    up.DialUDP,
		Dial:       up.Dial,
		DialDirect: up.DialDirect,
		Phase:      func() phase.Traffic { return phase.Proxied },
		Clock:      dclk,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	return r, up, clk
}

// answering — апстрим, собирающий ответ по дошедшему запросу.
//
// Идентификатор и имя берутся из запроса, а не задаются тестом: наверх уходит
// наш идентификатор, а не клиентский (Р23), и заранее заготовленный Answer
// его не подобрал бы — резолвер клиента такой ответ отбросил бы как чужой.
func answering(build func(id uint16, name string) []byte) dnstest.Behavior {
	return dnstest.Behavior{Func: func(query []byte) []byte {
		q, err := dnsmsg.Parse(query)
		if err != nil {
			return nil
		}
		return build(q.Header.ID, q.Question.Name.String())
	}}
}

// answeringA — самый частый стенд: A-запись с заданным TTL на любое имя.
func answeringA(ttl uint32) dnstest.Behavior {
	ip := netip.MustParseAddr("203.0.113.9")
	return answering(func(id uint16, name string) []byte {
		return dnstest.ResponseA(id, name, ttl, ip)
	})
}

// ask1 — один клиентский запрос по UDP с разобранным ответом.
func ask1(t *testing.T, r *Resolver, id uint16, name string, qtype uint16) dnsmsg.Msg {
	t.Helper()
	raw, err := r.Query(
		dnstest.BuildQuery(dnstest.QueryOpts{ID: id, Name: name, Type: qtype}),
		netip.AddrPort{}, netip.AddrPort{},
	)
	if err != nil {
		t.Fatalf("Query %s/%d: %v", name, qtype, err)
	}
	return parseTest(t, raw)
}

// wantUpstream — сколько всего запросов дошло наверх. Именно это число, а не
// счётчик попаданий, отвечает на вопрос «стоил ли повтор похода через узел»:
// ради него кэш и заведён (§5.3, B3).
func wantUpstream(t *testing.T, up *dnstest.Upstream, want int, why string) {
	t.Helper()
	if got := len(up.Queries()); got != want {
		t.Fatalf("%s: наверх ушло %d запросов, хотим %d", why, got, want)
	}
}

// TestD21RepeatedQueryHitsCache. D21. Два одинаковых запроса подряд в
// пределах TTL: наверх ушёл один, Hits = 1.
func TestD21RepeatedQueryHitsCache(t *testing.T) {
	r, up, _ := newCacheTestResolver(t)
	up.Program(cacheAddr, answeringA(300))

	first := ask1(t, r, 1, "example.com", dnstest.TypeA)
	second := ask1(t, r, 2, "example.com", dnstest.TypeA)

	wantUpstream(t, up, 1, "повтор в пределах TTL")
	if s := r.Snapshot(); s.Hits != 1 || s.Misses != 1 {
		t.Fatalf("Hits=%d Misses=%d, хотим 1 и 1", s.Hits, s.Misses)
	}
	if !bytes.Equal(first.Sections(), second.Sections()) {
		t.Fatal("попадание в кэш отдало не тот же ответ, что промах")
	}
	if second.Header.ID != 2 {
		t.Fatalf("ID из кэша = %d, хотим клиентский 2", second.Header.ID)
	}
}

// TestD22ExpiredEntryGoesUpstream. D22. Повтор после истечения TTL идёт
// наверх; протухание ставится сдвигом модельных часов.
func TestD22ExpiredEntryGoesUpstream(t *testing.T) {
	r, up, clk := newCacheTestResolver(t)
	up.Program(cacheAddr, answeringA(60))

	ask1(t, r, 1, "example.com", dnstest.TypeA)
	clk.Advance(61 * time.Second)
	ask1(t, r, 2, "example.com", dnstest.TypeA)

	wantUpstream(t, up, 2, "запись протухла")
	if s := r.Snapshot(); s.Hits != 0 {
		t.Fatalf("Hits=%d, хотим 0: протухшая запись не отдаётся", s.Hits)
	}
}

// TestD23ZeroTTLIsNotCached. D23. Ответ с TTL 0 не кэшируется вовсе (Р17,
// RFC 1035 прямо запрещает): повтор идёт наверх, и в кэше пусто.
func TestD23ZeroTTLIsNotCached(t *testing.T) {
	r, up, _ := newCacheTestResolver(t)
	up.Program(cacheAddr, answeringA(0))

	ask1(t, r, 1, "example.com", dnstest.TypeA)
	if s := r.Snapshot(); s.Entries != 0 {
		t.Fatalf("Entries=%d, хотим 0: TTL 0 значит 0", s.Entries)
	}
	ask1(t, r, 2, "example.com", dnstest.TypeA)
	wantUpstream(t, up, 2, "TTL 0")
}

// TestD24TTLIsCappedAtTTLCap. D24. Ответ с TTL 86400: запись жива на
// шестисотой секунде и мертва на шестьсот первой (Р17, потолок 600 с).
//
// Обе границы, а не одна: проверка только на смерть зелена и в реализации,
// которая не кэширует вовсе, а проверка только на жизнь — в той, что игнорирует
// потолок.
func TestD24TTLIsCappedAtTTLCap(t *testing.T) {
	r, up, clk := newCacheTestResolver(t)
	up.Program(cacheAddr, answeringA(86400))

	ask1(t, r, 1, "example.com", dnstest.TypeA)

	clk.Advance(TTLCap)
	ask1(t, r, 2, "example.com", dnstest.TypeA)
	wantUpstream(t, up, 1, "на шестисотой секунде запись ещё жива")

	clk.Advance(time.Second)
	ask1(t, r, 3, "example.com", dnstest.TypeA)
	wantUpstream(t, up, 2, "на шестьсот первой секунде запись мертва")
}

// TestD25TTLIsMinimumOverAnswerSection. D25. ANSWER из CNAME (TTL 30) и
// A (TTL 300): запись живёт 30 с — минимум по секции (Р17).
func TestD25TTLIsMinimumOverAnswerSection(t *testing.T) {
	r, up, clk := newCacheTestResolver(t)
	ip := netip.MustParseAddr("203.0.113.9")
	up.Program(cacheAddr, answering(func(id uint16, name string) []byte {
		return dnstest.ResponseCNAMEA(id, name, "target.example.com", 30, 300, ip)
	}))

	ask1(t, r, 1, "example.com", dnstest.TypeA)

	clk.Advance(30 * time.Second)
	ask1(t, r, 2, "example.com", dnstest.TypeA)
	wantUpstream(t, up, 1, "минимум секции — 30 с, они ещё не вышли")

	clk.Advance(time.Second)
	ask1(t, r, 3, "example.com", dnstest.TypeA)
	wantUpstream(t, up, 2, "запись обязана жить по минимуму, а не по TTL A-записи")
}

// negativeSOA — SOA с раздельно заданными MINIMUM и TTL самой записи: Р18
// велит брать меньшее из них и потолка, и проверки D26/D29 различают, какое
// именно поле сработало.
func negativeSOA(minimum uint32) dnstest.SOA {
	return dnstest.SOA{
		MName: "ns.example.com", RName: "hostmaster.example.com",
		Serial: 1, Refresh: 7200, Retry: 3600, Expire: 1209600, Minimum: minimum,
	}
}

// TestD26NXDomainCachedBySOAMinimum. D26. NXDOMAIN с SOA MINIMUM 60
// закэширован на 60 с: повтор внутри окна наверх не идёт (Р18, флаг
// dns_negative_cache).
//
// Имя теста зафиксировано реестром политик: на него ссылается Guard флага
// dns_negative_cache, и negcheck требует, чтобы с выключенным флагом проверка
// краснела.
func TestD26NXDomainCachedBySOAMinimum(t *testing.T) {
	r, up, clk := newCacheTestResolver(t)
	// TTL самой записи SOA заведомо больше MINIMUM: сработать обязан именно
	// MINIMUM, иначе проверка не отличила бы одно поле от другого.
	up.Program(cacheAddr, answering(func(id uint16, name string) []byte {
		return dnstest.ResponseNXDOMAINWithSOA(id, name, dnstest.TypeA, "example.com", 3600, negativeSOA(60))
	}))

	first := ask1(t, r, 1, "nope.example.com", dnstest.TypeA)
	if rc := first.Header.Rcode(); rc != dnsmsg.RcodeNXDomain {
		t.Fatalf("rcode = %d, хотим NXDOMAIN", rc)
	}
	if s := r.Snapshot(); s.Entries != 1 || s.Negative != 1 {
		t.Fatalf("Entries=%d Negative=%d, хотим 1 и 1", s.Entries, s.Negative)
	}

	clk.Advance(59 * time.Second)
	second := ask1(t, r, 2, "nope.example.com", dnstest.TypeA)
	wantUpstream(t, up, 1, "отрицательный ответ обязан лежать в кэше 60 с")
	if rc := second.Header.Rcode(); rc != dnsmsg.RcodeNXDomain {
		t.Fatalf("из кэша пришёл rcode %d, хотим NXDOMAIN", rc)
	}
	if s := r.Snapshot(); s.Hits != 1 {
		t.Fatalf("Hits=%d, хотим 1", s.Hits)
	}

	clk.Advance(2 * time.Second)
	ask1(t, r, 3, "nope.example.com", dnstest.TypeA)
	wantUpstream(t, up, 2, "за 60 с отрицательная запись обязана умереть")
}

// TestD27NXDomainWithoutSOACachedForDefault. D27. NXDOMAIN без SOA
// закэширован на умолчательные 30 с (Р18).
func TestD27NXDomainWithoutSOACachedForDefault(t *testing.T) {
	r, up, clk := newCacheTestResolver(t)
	up.Program(cacheAddr, answering(func(id uint16, name string) []byte {
		return dnstest.ResponseNXDOMAIN(id, name, dnstest.TypeA)
	}))

	ask1(t, r, 1, "nope.example.com", dnstest.TypeA)

	clk.Advance(NegativeDefault)
	ask1(t, r, 2, "nope.example.com", dnstest.TypeA)
	wantUpstream(t, up, 1, "без SOA отрицательная запись живёт 30 с")

	clk.Advance(time.Second)
	ask1(t, r, 3, "nope.example.com", dnstest.TypeA)
	wantUpstream(t, up, 2, "на тридцать первой секунде запись мертва")
}

// TestD28NodataCachedLikeNXDomain. D28. NOERROR с пустым ANSWER (NODATA)
// кэшируется по тем же правилам, что NXDOMAIN (Р18, флаг
// dns_negative_cache).
//
// Имя теста зафиксировано реестром политик, как и у D26. Тип вопроса — TXT, а
// не AAAA: на AAAA резолвер синтезирует пустой ответ сам (Р19) и наверх не
// ходит вовсе, то есть проверка мерила бы синтез, а не отрицательный кэш.
func TestD28NodataCachedLikeNXDomain(t *testing.T) {
	r, up, clk := newCacheTestResolver(t)
	up.Program(cacheAddr, answering(func(id uint16, name string) []byte {
		return dnstest.ResponseNoDataWithSOA(id, name, dnstest.TypeTXT, "example.com", 3600, negativeSOA(60))
	}))

	first := ask1(t, r, 1, "empty.example.com", dnstest.TypeTXT)
	if rc := first.Header.Rcode(); rc != dnsmsg.RcodeNoError || first.Header.ANCount != 0 {
		t.Fatalf("rcode=%d ANCOUNT=%d, хотим NODATA", rc, first.Header.ANCount)
	}
	if s := r.Snapshot(); s.Entries != 1 || s.Negative != 1 {
		t.Fatalf("Entries=%d Negative=%d, хотим 1 и 1: NODATA — отрицательный ответ", s.Entries, s.Negative)
	}

	clk.Advance(59 * time.Second)
	ask1(t, r, 2, "empty.example.com", dnstest.TypeTXT)
	wantUpstream(t, up, 1, "NODATA кэшируется теми же правилами, что NXDOMAIN")
	if s := r.Snapshot(); s.Hits != 1 {
		t.Fatalf("Hits=%d, хотим 1", s.Hits)
	}

	clk.Advance(2 * time.Second)
	ask1(t, r, 3, "empty.example.com", dnstest.TypeTXT)
	wantUpstream(t, up, 2, "за 60 с отрицательная запись обязана умереть")
}

// TestD29NegativeTTLIsCappedAtNegativeCap. D29. SOA MINIMUM 86400:
// отрицательная запись живёт 300 с — потолок (Р18).
func TestD29NegativeTTLIsCappedAtNegativeCap(t *testing.T) {
	r, up, clk := newCacheTestResolver(t)
	up.Program(cacheAddr, answering(func(id uint16, name string) []byte {
		return dnstest.ResponseNXDOMAINWithSOA(id, name, dnstest.TypeA, "example.com", 86400, negativeSOA(86400))
	}))

	ask1(t, r, 1, "nope.example.com", dnstest.TypeA)

	clk.Advance(NegativeCap)
	ask1(t, r, 2, "nope.example.com", dnstest.TypeA)
	wantUpstream(t, up, 1, "на трёхсотой секунде отрицательная запись ещё жива")

	clk.Advance(time.Second)
	ask1(t, r, 3, "nope.example.com", dnstest.TypeA)
	wantUpstream(t, up, 2, "потолок отрицательного кэша — 300 с, а не MINIMUM зоны")
}

// TestD30CachedAnswerCarriesThisQuerysNameCase. D30. EXAMPLE.com после
// example.com — попадание в кэш, и в ответе написание имени из ЭТОГО запроса
// (Р23).
//
// Цена ошибки здесь тихая и потому дорогая: стаб, применяющий
// 0x20-рандомизацию, сверяет секцию вопроса побайтно и ответ с чужим
// написанием молча отбрасывает — снаружи это выглядит как «DNS не работает»
// при полностью рабочем резолвере.
func TestD30CachedAnswerCarriesThisQuerysNameCase(t *testing.T) {
	r, up, _ := newCacheTestResolver(t)
	up.Program(cacheAddr, answeringA(300))

	ask1(t, r, 1, "example.com", dnstest.TypeA)

	upperRaw := dnstest.BuildQuery(dnstest.QueryOpts{ID: 2, Name: "EXAMPLE.com", Type: dnstest.TypeA})
	resp, err := r.Query(upperRaw, netip.AddrPort{}, netip.AddrPort{})
	if err != nil {
		t.Fatalf("Query EXAMPLE.com: %v", err)
	}

	wantUpstream(t, up, 1, "регистр имени не участвует в ключе кэша")
	if s := r.Snapshot(); s.Hits != 1 || s.Entries != 1 {
		t.Fatalf("Hits=%d Entries=%d, хотим 1 и 1: EXAMPLE.com и example.com — одна запись", s.Hits, s.Entries)
	}

	got := parseTest(t, resp)
	want := parseTest(t, upperRaw)
	if !bytes.Equal(got.QuestionBytes(), want.QuestionBytes()) {
		t.Fatalf("секция вопроса из кэша, а не из запроса:\nполучили %q\nхотим    %q",
			got.QuestionBytes(), want.QuestionBytes())
	}
	if got.Header.ID != 2 {
		t.Fatalf("ID = %d, хотим клиентский 2", got.Header.ID)
	}
}

// TestD31SameNameDifferentTypesAreDistinct. D31. A и TXT одного имени — две
// записи и два запроса наверх: тип входит в ключ (Р23).
func TestD31SameNameDifferentTypesAreDistinct(t *testing.T) {
	r, up, _ := newCacheTestResolver(t)
	ip := netip.MustParseAddr("203.0.113.9")
	up.Program(cacheAddr, dnstest.Behavior{Func: func(query []byte) []byte {
		q, err := dnsmsg.Parse(query)
		if err != nil {
			return nil
		}
		name := q.Question.Name.String()
		if q.Question.Type == dnstest.TypeTXT {
			return dnstest.BuildResponse(dnstest.ResponseOpts{
				ID: q.Header.ID, QName: name, QType: dnstest.TypeTXT,
				Flags:  dnstest.Flags{RD: true, RA: true, RCode: dnstest.RCodeNOERROR},
				Answer: []dnstest.RR{{Name: name, Type: dnstest.TypeTXT, TTL: 300, Data: []byte{2, 'h', 'i'}}},
			})
		}
		return dnstest.ResponseA(q.Header.ID, name, 300, ip)
	}})

	a := ask1(t, r, 1, "example.com", dnstest.TypeA)
	txt := ask1(t, r, 2, "example.com", dnstest.TypeTXT)

	wantUpstream(t, up, 2, "тип вопроса входит в ключ кэша")
	if s := r.Snapshot(); s.Entries != 2 || s.Hits != 0 {
		t.Fatalf("Entries=%d Hits=%d, хотим 2 и 0", s.Entries, s.Hits)
	}
	if bytes.Equal(a.Sections(), txt.Sections()) {
		t.Fatal("A и TXT вернули одно и то же — записи не различились по типу")
	}
}

// TestD32CacheCapEvictsToLimit. D32. 5000 разных имён — Entries ≤ 4096:
// кэш без границы это утечка, которую видно только через сутки и только на
// машине пользователя.
func TestD32CacheCapEvictsToLimit(t *testing.T) {
	r, up, _ := newCacheTestResolver(t)
	up.Program(cacheAddr, answeringA(600))

	const names = 5000
	for i := range names {
		ask1(t, r, uint16(i), fmt.Sprintf("h%d.example.com", i), dnstest.TypeA)
	}

	wantUpstream(t, up, names, "5000 разных имён — 5000 промахов")
	s := r.Snapshot()
	if s.Entries != CacheEntries {
		t.Fatalf("Entries=%d, хотим ровно потолок %d", s.Entries, CacheEntries)
	}
}

// TestD32EvictionIsLeastRecentlyUsed. D32, вторая половина: вытесняется
// самый давно не спрошенный, а не самый давно положенный.
//
// Разница между LRU и «выбросить старейшую вставку» видна только так —
// попаданием в кэш между заполнением и переполнением. Без него обе стратегии
// дают одинаковое Entries, и проверка потолка зелена для обеих.
func TestD32EvictionIsLeastRecentlyUsed(t *testing.T) {
	r, up, _ := newCacheTestResolver(t)
	up.Program(cacheAddr, answeringA(600))

	name := func(i int) string { return fmt.Sprintf("h%d.example.com", i) }

	for i := range CacheEntries {
		ask1(t, r, uint16(i), name(i), dnstest.TypeA)
	}
	filled := len(up.Queries())

	// Трогаем нулевое имя: теперь давно не спрошенное — первое, а не нулевое.
	ask1(t, r, 1, name(0), dnstest.TypeA)
	if got := len(up.Queries()); got != filled {
		t.Fatalf("наверх ушло %d запросов, хотим %d: имя обязано было лежать в кэше", got, filled)
	}

	// Одна вставка сверх потолка — ровно одно вытеснение.
	ask1(t, r, 2, name(CacheEntries), dnstest.TypeA)

	ask1(t, r, 3, name(0), dnstest.TypeA)
	if got := len(up.Queries()); got != filled+1 {
		t.Fatalf("наверх ушло %d запросов, хотим %d: вытеснили недавно спрошенное имя", got, filled+1)
	}

	ask1(t, r, 4, name(1), dnstest.TypeA)
	if got := len(up.Queries()); got != filled+2 {
		t.Fatalf("наверх ушло %d запросов, хотим %d: вытеснить обязано было давно не спрошенное имя", got, filled+2)
	}
}

// blocking — апстрим, который отвечает только после закрытия release.
//
// Так строится «одновременно» без единого обращения к настоящему времени:
// клиенты копятся, пока стенд держит ответ, и тест решает, когда их отпустить.
// Сон вместо этого дал бы тест, который иногда зелен (§8.1, house-rules).
func blocking(release <-chan struct{}, b dnstest.Behavior) dnstest.Behavior {
	inner := b.Func
	return dnstest.Behavior{Func: func(query []byte) []byte {
		<-release
		return inner(query)
	}}
}

// waitDecided крутится, пока все n клиентов не окажутся кто в полёте, кто
// склеенным, кто уже отказанным.
//
// Сумма трёх, а не одна склейка: с выключенным dns_single_flight склейки не
// будет вовсе, и ожидание именно её повесило бы negcheck до общего таймаута
// go test вместо честного красного за доли секунды. Смотрит только в Stats:
// §2 регистра, требование 5, другого способа заглянуть в кэш не даёт.
func waitDecided(r *Resolver, n int) Stats {
	for {
		s := r.Snapshot()
		if s.InFlight+int(s.Coalesced)+int(s.ServFail) >= n {
			return s
		}
		runtime.Gosched()
	}
}

// TestD38IdenticalQuestionsCoalesce. D38. 100 одновременных одинаковых
// вопросов: наверх ушёл один, все 100 клиентов получили ответ,
// Coalesced = 99 (Р24, флаг dns_single_flight).
//
// Имя теста зафиксировано реестром политик: negcheck требует, чтобы с
// выключенным dns_single_flight проверка краснела — то есть чтобы развилка
// была настоящей, а не украшением.
func TestD38IdenticalQuestionsCoalesce(t *testing.T) {
	r, up, _ := newCacheTestResolver(t)
	release := make(chan struct{})
	up.Program(cacheAddr, blocking(release, answeringA(300)))

	const clients = 100
	answers := make([][]byte, clients)
	errs := make([]error, clients)
	var wg sync.WaitGroup
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers[i], errs[i] = r.Query(
				dnstest.BuildQuery(dnstest.QueryOpts{ID: uint16(i), Name: "example.com", Type: dnstest.TypeA}),
				netip.AddrPort{}, netip.AddrPort{},
			)
		}()
	}

	before := waitDecided(r, clients)
	close(release)
	wg.Wait()

	if before.Coalesced != clients-1 {
		t.Fatalf("Coalesced=%d, хотим %d: одинаковые вопросы обязаны склеиваться", before.Coalesced, clients-1)
	}
	if before.InFlight != 1 {
		t.Fatalf("InFlight=%d, хотим 1: наверх идёт один запрос на всех", before.InFlight)
	}
	wantUpstream(t, up, 1, "сто одинаковых вопросов")

	for i := range clients {
		if errs[i] != nil {
			t.Fatalf("клиент %d получил ошибку %v — склейка обязана отдать ответ всем", i, errs[i])
		}
		m := parseTest(t, answers[i])
		if m.Header.ID != uint16(i) {
			t.Fatalf("клиент %d получил ID %d — ответ ушёл не тому", i, m.Header.ID)
		}
		if m.Header.ANCount == 0 {
			t.Fatalf("клиент %d получил пустой ответ", i)
		}
	}
	if s := r.Snapshot(); s.InFlight != 0 {
		t.Fatalf("InFlight=%d после завершения, хотим 0", s.InFlight)
	}
}

// TestD39InFlightCapRefusesImmediately. D39. 300 одновременных разных
// вопросов: InFlight ≤ 256, сверх потолка — немедленный SERVFAIL, а не
// ожидание (Р24).
//
// Цена решения названа в регистре и проверяется здесь буквально: потолок не
// различает, кто именно шумит, и под шквалом легитимный запрос получает
// SERVFAIL наравне с мусорным.
func TestD39InFlightCapRefusesImmediately(t *testing.T) {
	r, up, _ := newCacheTestResolver(t)
	release := make(chan struct{})
	up.Program(cacheAddr, blocking(release, answeringA(300)))

	const clients = 300
	answers := make([][]byte, clients)
	errs := make([]error, clients)
	var wg sync.WaitGroup
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers[i], errs[i] = r.Query(
				dnstest.BuildQuery(dnstest.QueryOpts{ID: uint16(i), Name: fmt.Sprintf("h%d.example.com", i), Type: dnstest.TypeA}),
				netip.AddrPort{}, netip.AddrPort{},
			)
		}()
	}

	// Отказанные не ждут освобождения места, поэтому все 300 определяются до
	// того, как стенд отпущен: 256 стоят в полёте, остальным уже отказано.
	before := waitDecided(r, clients)
	if before.InFlight > MaxInFlight {
		t.Fatalf("InFlight=%d, потолок %d", before.InFlight, MaxInFlight)
	}
	if before.InFlight != MaxInFlight {
		t.Fatalf("InFlight=%d, хотим ровно %d: места под потолком обязаны быть заняты все", before.InFlight, MaxInFlight)
	}
	if want := uint64(clients - MaxInFlight); before.ServFail != want {
		t.Fatalf("ServFail=%d, хотим %d: сверх потолка отказ немедленный", before.ServFail, want)
	}

	close(release)
	wg.Wait()

	var refused, served int
	for i := range clients {
		if errs[i] != nil {
			t.Fatalf("клиент %d остался без ответа (%v) — отказ выражается кодом, а не молчанием", i, errs[i])
		}
		switch rc := parseTest(t, answers[i]).Header.Rcode(); rc {
		case dnsmsg.RcodeServFail:
			refused++
		case dnsmsg.RcodeNoError:
			served++
		default:
			t.Fatalf("клиент %d получил rcode %d", i, rc)
		}
	}
	if refused != clients-MaxInFlight || served != MaxInFlight {
		t.Fatalf("отказано %d, обслужено %d; хотим %d и %d", refused, served, clients-MaxInFlight, MaxInFlight)
	}
	if s := r.Snapshot(); s.InFlight != 0 {
		t.Fatalf("InFlight=%d после завершения, хотим 0: места обязаны освобождаться", s.InFlight)
	}
}

// Сброс кэша выкидывает всё и не оставляет отрицательных записей. Строки
// регистра у этого нет: D19 и D20 считают Generation и принадлежат задаче
// фаз (З7), которая зовёт reset по подписке. Здесь проверяется только то, за
// что отвечает кэш, — что после reset отдавать ему нечего.
func TestCacheResetEmptiesEverything(t *testing.T) {
	r, up, _ := newCacheTestResolver(t)
	up.Program(cacheAddr, answeringA(600))

	ask1(t, r, 1, "example.com", dnstest.TypeA)
	if s := r.Snapshot(); s.Entries != 1 {
		t.Fatalf("Entries=%d до сброса, хотим 1", s.Entries)
	}

	r.cache.reset()

	if s := r.Snapshot(); s.Entries != 0 || s.Negative != 0 {
		t.Fatalf("Entries=%d Negative=%d после сброса, хотим 0 и 0", s.Entries, s.Negative)
	}
	ask1(t, r, 2, "example.com", dnstest.TypeA)
	wantUpstream(t, up, 2, "после сброса кэш пуст")
}

// cacheTTL — единственная функция кэша, у которой есть решения без строки
// регистра, и проверяются они здесь напрямую: пройти сквозь Query они не
// могут, потому что усечённый ответ и битый хвост обрабатываются раньше кэша
// (повтор по TCP — D33, отказ клиенту — D15), и сквозная проверка мерила бы
// чужой шаг.
func TestCacheTTLRejectsWhatMustNotBeCached(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.9")
	name := "example.com"

	cases := []struct {
		name string
		raw  []byte
		why  string
	}{
		{
			name: "усечённый ответ",
			raw:  dnstest.WithTC(dnstest.ResponseA(1, name, 300, ip)),
			why:  "TC значит заведомо неполный RRset: закэшировать его — раздавать обрезок молча, без похода наверх",
		},
		{
			name: "лишние байты за последней записью",
			raw:  dnstest.TrailingGarbage(dnstest.ResponseA(1, name, 300, ip)),
			why:  "сообщение, у которого не сходится хвост, — мусор из сети (D15)",
		},
		{
			name: "REFUSED",
			raw: dnstest.BuildResponse(dnstest.ResponseOpts{
				ID: 1, QName: name, QType: dnstest.TypeA,
				Flags: dnstest.Flags{RD: true, RA: true, RCode: 5},
			}),
			why: "чужой сбой не должен становиться нашим на минуту вперёд",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := dnsmsg.Parse(tc.raw)
			if err != nil {
				// Мусор, который не разбирается вовсе, до кэша не доходит —
				// проверять на нём политику TTL нечего.
				return
			}
			if ttl, _, ok := cacheTTL(m); ok {
				t.Fatalf("закэширован на %v: %s", ttl, tc.why)
			}
		})
	}
}
