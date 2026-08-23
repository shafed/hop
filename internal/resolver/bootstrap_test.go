package resolver

import (
	"net/netip"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dnsmsg"
	"github.com/shafed/hop/internal/dnstest"
	"github.com/shafed/hop/internal/phase"
)

// Проверки bootstrap: резолвер имён узлов мимо туннеля (У7, Р21, Р22,
// D51–D58 в docs/verification-dns.md §5.7).
//
// Кэш здесь свой, не общий с internal/resolver/cache.go: §2 регистра,
// требование 6, отдельно требует отдельного типа со своим кэшем — и тесты
// поэтому не переиспользуют newCacheTestResolver. Кэш вскрывается только
// через Resolve и Stats — тот же принцип §2, требование 5, что и у основного
// кэша: протухание ставится сдвигом фейковых часов, а не подкладыванием
// записи.
//
// Модельное время двигается только после dnstest.Clock.WaitAfterCalls — та
// же дисциплина, что держит upstream_test.go: часы, сдвинутые раньше, чем
// горутина реально встала в ожидание, срок не наступает ни для кого.

// bootstrapTestWatchdog — потолок настоящего времени на любое ожидание в
// этом файле. Достигается только на сломанном коде.
const bootstrapTestWatchdog = 5 * time.Second

// bootstrapAddr — единственный апстрим стенда. Форы второму у bootstrap нет
// (см. комментарий у fetch в bootstrap.go), поэтому одного достаточно для
// всех проверок этого файла.
var bootstrapAddr = netip.MustParseAddrPort("203.0.113.53:53")

// newBootstrapTestStand — Bootstrap на фейковых часах с поддельным
// апстримом на одном адресе.
func newBootstrapTestStand(t *testing.T) (b *Bootstrap, up *dnstest.Upstream, fake *clock.Fake, dclk *dnstest.Clock) {
	t.Helper()
	fake = clock.NewFake(time.Unix(0, 0))
	dclk = dnstest.NewClock(fake)
	up = dnstest.New(dclk)

	b, err := NewBootstrap(BootstrapConfig{
		Upstreams:  []netip.AddrPort{bootstrapAddr},
		DialDirect: up.DialDirect,
		Clock:      dclk,
	})
	if err != nil {
		t.Fatalf("NewBootstrap: %v", err)
	}
	return b, up, fake, dclk
}

// bootstrapAnsweringA — апстрим, отвечающий A-записями на дошедший запрос: id и имя
// берутся из запроса, а не задаются тестом, потому что bootstrap несёт
// наверх свой идентификатор, а не подсмотренный заранее (тот же принцип
// Р23, что у основного резолвера, — здесь просто нет клиента, у которого id
// можно было бы позаимствовать).
func bootstrapAnsweringA(ttl uint32, addrs ...netip.Addr) dnstest.Behavior {
	return dnstest.Behavior{Func: func(query []byte) []byte {
		q, err := dnsmsg.Parse(query)
		if err != nil {
			return nil
		}
		id := q.Header.ID
		name := q.Question.Name.String()

		var rrs []dnstest.RR
		for _, a := range addrs {
			rrs = append(rrs, dnstest.RR{Name: name, Type: dnstest.TypeA, TTL: ttl, Data: a.AsSlice()})
		}
		return dnstest.BuildResponse(dnstest.ResponseOpts{
			ID: id, QName: name, QType: dnstest.TypeA,
			Flags:  dnstest.Flags{RD: true, RA: true},
			Answer: rrs,
		})
	}}
}

// bootstrapResult — пара «адреса или ошибка» с канала resolveAsync.
type bootstrapResult struct {
	addrs []netip.Addr
	err   error
}

// resolveAsync зовёт Resolve в своей горутине — нужен только сценариям,
// которые обязаны двигать фейковые часы, пока Resolve ждёт таймаут попытки.
func resolveAsync(b *Bootstrap, host string) <-chan bootstrapResult {
	ch := make(chan bootstrapResult, 1)
	go func() {
		addrs, err := b.Resolve(host)
		ch <- bootstrapResult{addrs: addrs, err: err}
	}()
	return ch
}

func awaitBootstrap(t *testing.T, ch <-chan bootstrapResult) bootstrapResult {
	t.Helper()
	select {
	case res := <-ch:
		return res
	case <-time.After(bootstrapTestWatchdog): //hop:realtime сторож
		t.Fatal("Bootstrap.Resolve не ответил за сторожевой срок")
		return bootstrapResult{}
	}
}

// waitAfter ждёт, пока общее число обращений к After на dclk не дойдёт до n,
// с настоящим сторожем на случай, если резолвер в ожидание не встал вовсе.
func waitAfter(t *testing.T, dclk *dnstest.Clock, n uint64) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		dclk.WaitAfterCalls(n)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(bootstrapTestWatchdog): //hop:realtime сторож
		t.Fatalf("ожиданий на часах %d, ждали %d — Resolve не встал в ожидание таймаута", dclk.AfterCalls(), n)
	}
}

// D51. Старт: живых узлов нет, надо резолвить имя узла — резолвится через
// Bootstrap, а Config.Dial и DialUDP основного резолвера (для Bootstrap их
// вовсе нет) не вызываются ни разу. Флаг bootstrap: выключенный отправляет
// имена узлов общим путём через туннель, а Bootstrap в границах собственного
// типа не умеет ничего, кроме как отказаться резолвить (см. комментарий у
// Resolve в bootstrap.go) — на этом отказе и обязана покраснеть проверка.
func TestD51NodeNameResolvesViaBootstrap(t *testing.T) {
	b, up, _, _ := newBootstrapTestStand(t)
	ip1 := netip.MustParseAddr("203.0.113.10")
	ip2 := netip.MustParseAddr("203.0.113.11")
	up.Program(bootstrapAddr, bootstrapAnsweringA(300, ip1, ip2))

	addrs, err := b.Resolve("node1.example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(addrs) != 2 || addrs[0] != ip1 || addrs[1] != ip2 {
		t.Fatalf("адреса = %v, хотим [%s %s]", addrs, ip1, ip2)
	}

	if calls := up.Calls(); calls.DialUDP != 0 || calls.Dial != 0 {
		t.Fatalf("bootstrap тронул путь через узел: %+v", calls)
	}
}

// D52. То же: запрос ушёл через DialDirect, и это видно и счётчиком стенда
// (Calls.DialDirect), и собственным счётчиком Bootstrap (Stats().Upstream) —
// §6.8. Флаг bootstrap: см. D51.
func TestD52BootstrapGoesDirect(t *testing.T) {
	b, up, _, _ := newBootstrapTestStand(t)
	ip := netip.MustParseAddr("203.0.113.20")
	up.Program(bootstrapAddr, bootstrapAnsweringA(300, ip))

	if _, err := b.Resolve("node2.example.com"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if calls := up.Calls(); calls.DialDirect != 1 {
		t.Fatalf("Calls.DialDirect = %d, хотим 1", calls.DialDirect)
	}
	qs := up.Queries()
	if len(qs) != 1 || qs[0].Via != dnstest.ViaDialDirect {
		t.Fatalf("запрос ушёл не через DialDirect: %+v", qs)
	}
	if st := b.Stats(); len(st.Upstream) != 1 || st.Upstream[0] != 1 {
		t.Fatalf("Stats().Upstream = %v, хотим [1]", st.Upstream)
	}
}

// D53. Fail-close основного резолвера (Р15) не касается bootstrap: «нет живых
// узлов — нет резолва» — про клиентский DNS, а у bootstrap нет входа, которым
// фаза трафика могла бы до него дойти (BootstrapConfig без Phase). Без флага:
// это асимметрия двух резолверов, а не переключаемая политика.
//
// Проверка держит оба резолвера рядом на одних часах и одном апстриме, чтобы
// асимметрия была видна прямо в тесте: один и тот же мир (фаза failing) даёт
// SERVFAIL у Resolver и рабочий ответ у Bootstrap.
func TestD53BootstrapWorksInFailingPhase(t *testing.T) {
	fake := clock.NewFake(time.Unix(0, 0))
	dclk := dnstest.NewClock(fake)
	up := dnstest.New(dclk)

	r, err := New(Config{
		Upstreams: []netip.AddrPort{bootstrapAddr},
		DialUDP:   up.DialUDP,
		Dial:      up.Dial,
		Phase:     func() phase.Traffic { return phase.Failing },
		Clock:     dclk,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { r.Close() })

	resp, err := r.Query(dnstest.BuildQuery(dnstest.QueryOpts{ID: 1, Name: "example.com", Type: dnstest.TypeA}), netip.AddrPort{}, netip.AddrPort{})
	if err != nil {
		t.Fatalf("Query (Resolver, failing): %v", err)
	}
	got, err := dnsmsg.Parse(resp)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rc := got.Header.Rcode(); rc != dnsmsg.RcodeServFail {
		t.Fatalf("Resolver в failing: rcode = %d, хотим SERVFAIL — fail-close должен работать", rc)
	}

	b, err := NewBootstrap(BootstrapConfig{
		Upstreams:  []netip.AddrPort{bootstrapAddr},
		DialDirect: up.DialDirect,
		Clock:      dclk,
	})
	if err != nil {
		t.Fatalf("NewBootstrap: %v", err)
	}
	ip := netip.MustParseAddr("203.0.113.30")
	up.Program(bootstrapAddr, bootstrapAnsweringA(300, ip))

	addrs, err := b.Resolve("node3.example.com")
	if err != nil {
		t.Fatalf("Bootstrap.Resolve рядом с fail-close основного резолвера: %v — из отказа не было бы выхода", err)
	}
	if len(addrs) != 1 || addrs[0] != ip {
		t.Fatalf("адреса = %v, хотим [%s]", addrs, ip)
	}
}

// D56. Запись протухла, апстрим недоступен — отдана просроченная запись,
// Stale вырос (Р21, serve-stale). Без флага: не политика, а свойство кэша.
//
// Заодно проверяет пол TTL (Р21, §4: 300 с): апстрим называет 60 с, и запись
// обязана пережить их — до 300-й секунды включительно она отдаётся как
// попадание в кэш, а не как поход наверх.
func TestD56BootstrapServesStaleWhenUpstreamDown(t *testing.T) {
	b, up, fake, dclk := newBootstrapTestStand(t)
	ip := netip.MustParseAddr("203.0.113.40")
	up.Program(bootstrapAddr, bootstrapAnsweringA(60, ip))

	addrs, err := b.Resolve("node4.example.com")
	if err != nil {
		t.Fatalf("первый Resolve: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != ip {
		t.Fatalf("адреса = %v, хотим [%s]", addrs, ip)
	}
	if before := b.Stats(); before.Hits != 0 || before.Stale != 0 {
		t.Fatalf("после первого резолва Hits/Stale = %d/%d, хотим 0/0: это не попадание в кэш", before.Hits, before.Stale)
	}

	// За секунду до пола TTL запись ещё обязана быть свежей: TTL апстрима
	// (60 с) не должен победить пол (300 с, Р21).
	fake.Advance(BootstrapTTLFloor - time.Second)
	if _, err := b.Resolve("node4.example.com"); err != nil {
		t.Fatalf("Resolve за секунду до пола TTL: %v", err)
	}
	if st := b.Stats(); st.Hits != 1 {
		t.Fatalf("Hits = %d, хотим 1: TTL апстрима (60 с) не должен был победить пол (%s)", st.Hits, BootstrapTTLFloor)
	}
	if calls := up.Calls(); calls.DialDirect != 1 {
		t.Fatalf("Calls.DialDirect = %d, хотим 1: попадание в кэш не должно было идти наверх", calls.DialDirect)
	}

	// Теперь запись состарилась, а апстрим замолчал — Resolve обязан
	// попытаться сходить наверх (и упереться в таймаут попытки), а не
	// отдать протухшее без попытки: serve-stale — это то, что происходит
	// после неудачи, а не вместо неё (Р21: «апстрим недоступен»).
	fake.Advance(2 * time.Second)
	up.Program(bootstrapAddr, dnstest.Behavior{Silent: true})

	ch := resolveAsync(b, "node4.example.com")
	waitAfter(t, dclk, dclk.AfterCalls()+1)
	fake.Advance(AttemptTimeout)

	res := awaitBootstrap(t, ch)
	if res.err != nil {
		t.Fatalf("Resolve после протухания при молчащем апстриме: %v", res.err)
	}
	if len(res.addrs) != 1 || res.addrs[0] != ip {
		t.Fatalf("просроченные адреса = %v, хотим [%s]", res.addrs, ip)
	}
	if st := b.Stats(); st.Stale != 1 {
		t.Fatalf("Stale = %d, хотим 1", st.Stale)
	}
	if calls := up.Calls(); calls.DialDirect != 2 {
		t.Fatalf("Calls.DialDirect = %d, хотим 2: serve-stale обязан идти после попытки, а не вместо неё", calls.DialDirect)
	}
}

// Кэш хранит записи, включая просроченные (serve-stale), но не безгранично:
// вытеснение LRU держит его на BootstrapEntries записях — тот же приём и то
// же основание (предсказуемость, не память), что у CacheEntries основного
// резолвера (D32).
func TestBootstrapCacheEvictsAtEntriesCap(t *testing.T) {
	b, up, _, _ := newBootstrapTestStand(t)
	up.Program(bootstrapAddr, bootstrapAnsweringA(300, netip.MustParseAddr("203.0.113.99")))

	for i := 0; i < BootstrapEntries+10; i++ {
		host := fmtHost(i)
		if _, err := b.Resolve(host); err != nil {
			t.Fatalf("Resolve(%s): %v", host, err)
		}
	}
	if st := b.Stats(); st.Entries > BootstrapEntries {
		t.Fatalf("Entries = %d, хотим не больше %d", st.Entries, BootstrapEntries)
	}
}

func fmtHost(i int) string {
	const digits = "0123456789"
	// Свой форматтер без fmt.Sprintf ради единообразия с остальным файлом
	// не нужен — используем стандартный пакет.
	return "node-" + itoa(i) + ".example.com"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// Промах кэша с успешным ответом кладёт запись; повторный Resolve того же
// имени, пока она свежа, не должен идти наверх снова — Hits растёт, счётчик
// диалера не растёт.
func TestBootstrapCachedAnswerAvoidsNetwork(t *testing.T) {
	b, up, _, _ := newBootstrapTestStand(t)
	ip := netip.MustParseAddr("203.0.113.50")
	up.Program(bootstrapAddr, bootstrapAnsweringA(300, ip))

	for i := 0; i < 3; i++ {
		addrs, err := b.Resolve("node5.example.com")
		if err != nil {
			t.Fatalf("Resolve #%d: %v", i, err)
		}
		if len(addrs) != 1 || addrs[0] != ip {
			t.Fatalf("Resolve #%d: адреса = %v", i, addrs)
		}
	}
	if calls := up.Calls(); calls.DialDirect != 1 {
		t.Fatalf("Calls.DialDirect = %d, хотим 1: повторные резолвы обязаны бить в кэш", calls.DialDirect)
	}
	if st := b.Stats(); st.Hits != 2 {
		t.Fatalf("Hits = %d, хотим 2", st.Hits)
	}
}

// Апстрим без единого адреса (NXDOMAIN) — ошибка, а не пустой успех, и в
// кэш ничего не ложится: пустой список адресов неотличим был бы от «ещё не
// резолвили», а bootstrap не отрицательный кэш вроде Р18 у основного
// резолвера — négative-кэш узловых имён здесь не в скобках задачи (см.
// отчёт).
func TestBootstrapNXDOMAINReturnsError(t *testing.T) {
	b, up, _, _ := newBootstrapTestStand(t)
	up.Program(bootstrapAddr, dnstest.Behavior{Func: func(query []byte) []byte {
		q, err := dnsmsg.Parse(query)
		if err != nil {
			return nil
		}
		return dnstest.ResponseNXDOMAIN(q.Header.ID, q.Question.Name.String(), dnstest.TypeA)
	}})

	if _, err := b.Resolve("nowhere.example.com"); err == nil {
		t.Fatal("Resolve вернул успех на NXDOMAIN")
	}
	if st := b.Stats(); st.Entries != 0 {
		t.Fatalf("Entries = %d, хотим 0: NXDOMAIN не должен был лечь в кэш", st.Entries)
	}
}
