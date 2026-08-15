package resolver

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time" //hop:realtime

	"golang.org/x/net/dns/dnsmessage"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dnstest"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/policy"
)

// Резолвер обязан подходить netstack как есть: интерфейс там объявлен с этапа
// 3, и этап 6 — подстановка, а не переписывание.
var _ netstack.Resolver = (*Resolver)(nil)

const (
	nameA = "example.test"
	nameB = "other.test"
)

// fixture — резолвер поверх настоящих DNS-серверов, по одному на узел.
//
// Серверов два, потому что T14 говорит именно так: «домен резолвится в IP1
// через A и IP2 через B». Один сервер с меняющейся зоной проверял бы кэш, но
// не проверял бы узел — а вопрос ровно в узле.
type fixture struct {
	t   *testing.T
	clk *clock.Fake
	res *Resolver

	srv map[string]*dnstest.Server

	mu      sync.Mutex
	active  string
	healthy bool
}

func newFixture(t *testing.T, nodes ...string) *fixture {
	t.Helper()
	if len(nodes) == 0 {
		nodes = []string{"A"}
	}
	f := &fixture{
		t:       t,
		clk:     clock.NewFake(time.Unix(1700000000, 0)),
		srv:     map[string]*dnstest.Server{},
		active:  nodes[0],
		healthy: true,
	}
	for _, id := range nodes {
		s, err := dnstest.New()
		if err != nil {
			t.Fatalf("сервер узла %s: %v", id, err)
		}
		t.Cleanup(s.Close)
		f.srv[id] = s
	}

	f.res = New(Config{
		Transport: byNode{inner: NewNodeTransport(Direct{}), addr: f.upstream},
		// Адрес апстрима подменяется транспортом узла: путь наружу известен
		// узлу, а не резолверу.
		Servers:    []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")},
		Clock:      f.clk,
		Healthy:    f.isHealthy,
		ActiveNode: f.node,
	})
	return f
}

// byNode — транспорт, у которого путь к апстриму зависит от активного узла.
// Так же устроен продукт: NodeDialer замыкает id узла, и смена узла меняет
// путь без единого вызова в резолвер.
type byNode struct {
	inner *NodeTransport
	addr  func() netip.AddrPort
}

func (b byNode) Exchange(ctx context.Context, _ netip.AddrPort, query []byte, stream bool) ([]byte, error) {
	return b.inner.Exchange(ctx, b.addr(), query, stream)
}

func (f *fixture) upstream() netip.AddrPort { return f.server().Addr() }

func (f *fixture) server() *dnstest.Server {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.srv[f.active]
}

func (f *fixture) node() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active
}

func (f *fixture) isHealthy() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.healthy
}

func (f *fixture) switchTo(node string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active = node
}

func (f *fixture) setHealthy(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthy = v
}

// resolve задаёт вопрос так, как его задал бы netstack.
func (f *fixture) resolve(name string) *dnsmessage.Message {
	f.t.Helper()
	answer, err := f.res.Query(queryFor(f.t, name, 0x1234), netip.MustParseAddrPort("10.255.0.2:5300"),
		netip.MustParseAddrPort("10.255.0.1:53"))
	if err != nil {
		f.t.Fatalf("резолв %s: %v", name, err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(answer); err != nil {
		f.t.Fatalf("ответ не разобрался: %v", err)
	}
	if m.Header.ID != 0x1234 {
		f.t.Fatalf("id ответа %#x, ожидался %#x", m.Header.ID, 0x1234)
	}
	return &m
}

func (f *fixture) addrsOf(name string) []netip.Addr {
	f.t.Helper()
	return addrsOf(f.t, f.resolve(name))
}

func queryFor(t testing.TB, name string, id uint16) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		t.Fatalf("имя %q: %v", name, err)
	}
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("запрос не собрался: %v", err)
	}
	return b
}

func addrsOf(t testing.TB, m *dnsmessage.Message) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for _, a := range m.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			out = append(out, netip.AddrFrom4(r.A))
		}
	}
	return out
}

func onlyAddr(t testing.TB, addrs []netip.Addr) netip.Addr {
	t.Helper()
	if len(addrs) != 1 {
		t.Fatalf("адресов %d, ожидался один: %v", len(addrs), addrs)
	}
	return addrs[0]
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// TestQueryGoesThroughNodeAndAnswers — §5.7: резолв настоящий, через узел, и
// ответ доходит до клиента.
func TestQueryGoesThroughNodeAndAnswers(t *testing.T) {
	f := newFixture(t)
	f.srv["A"].Set(nameA, time.Minute, ip("203.0.113.10"))

	if got := onlyAddr(t, f.addrsOf(nameA)); got != ip("203.0.113.10") {
		t.Fatalf("резолв дал %v", got)
	}
	if udp, tcp := f.srv["A"].Queries(); udp != 1 || tcp != 0 {
		t.Fatalf("апстрим получил udp=%d tcp=%d, ожидалось 1/0", udp, tcp)
	}
}

// TestCacheAnswersSecondQuery — §5.7в, первая половина: кэш есть, и он не
// ходит в апстрим повторно, пока жив TTL. TTL при этом идёт вниз: клиент
// обязан видеть остаток, а не исходное число.
func TestCacheAnswersSecondQuery(t *testing.T) {
	f := newFixture(t)
	f.srv["A"].Set(nameA, time.Minute, ip("203.0.113.10"))

	first := f.resolve(nameA)
	if ttl := first.Answers[0].Header.TTL; ttl != 60 {
		t.Fatalf("TTL первого ответа %d, ожидалось 60", ttl)
	}

	f.clk.Advance(20 * time.Second)
	second := f.resolve(nameA)
	if got := onlyAddr(t, addrsOf(t, second)); got != ip("203.0.113.10") {
		t.Fatalf("из кэша пришло %v", got)
	}
	if ttl := second.Answers[0].Header.TTL; ttl != 40 {
		t.Fatalf("TTL из кэша %d, ожидалось 40", ttl)
	}
	if udp, _ := f.srv["A"].Queries(); udp != 1 {
		t.Fatalf("апстрим спрошен %d раз, ожидался один", udp)
	}
	if s := f.res.Stats(); s.Hits != 1 || s.Misses != 1 {
		t.Fatalf("счётчики: hits=%d misses=%d", s.Hits, s.Misses)
	}
}

// TestCacheExpiresByTTL — вторая половина §5.7в: TTL уважается, а не
// игнорируется.
func TestCacheExpiresByTTL(t *testing.T) {
	f := newFixture(t)
	f.srv["A"].Set(nameA, 30*time.Second, ip("203.0.113.10"))
	f.resolve(nameA)

	f.clk.Advance(31 * time.Second)
	f.srv["A"].Set(nameA, 30*time.Second, ip("203.0.113.11"))
	if got := onlyAddr(t, f.addrsOf(nameA)); got != ip("203.0.113.11") {
		t.Fatalf("после истечения TTL пришло %v", got)
	}
	if udp, _ := f.srv["A"].Queries(); udp != 2 {
		t.Fatalf("апстрим спрошен %d раз, ожидалось два", udp)
	}
}

// TestT14CacheDoesNotSurviveSwitch — T14 регистра §8.2 и охраняющий тест
// политики dns_cache_flush_on_switch.
//
// Домен резолвится в IP1 через A и в IP2 через B. После переключения
// следующий резолв обязан дать IP2 — иначе трафик пойдёт через новый узел на
// адрес, выданный CDN прежнего региона (§5.7в).
func TestT14CacheDoesNotSurviveSwitch(t *testing.T) {
	f := newFixture(t, "A", "B")
	f.srv["A"].Set(nameA, time.Hour, ip("203.0.113.1"))
	f.srv["B"].Set(nameA, time.Hour, ip("198.51.100.2"))

	if got := onlyAddr(t, f.addrsOf(nameA)); got != ip("203.0.113.1") {
		t.Fatalf("через A пришло %v", got)
	}

	// Время не двигается вовсе: TTL здесь ни при чём, вопрос только в узле.
	f.switchTo("B")
	if got := onlyAddr(t, f.addrsOf(nameA)); got != ip("198.51.100.2") {
		t.Fatalf("после переключения на B пришло %v — кэш пережил смену узла", got)
	}
	if n := f.srv["B"].QueriesFor(nameA); n != 1 {
		t.Fatalf("узел B спрошен %d раз, ожидался один", n)
	}
}

// TestFailCloseAnswersServfail — §5.7б: живых узлов нет — резолва нет. Отказ,
// а не молчание (§5.6): молчание стоит клиенту полного таймаута на каждое имя.
func TestFailCloseAnswersServfail(t *testing.T) {
	f := newFixture(t)
	f.srv["A"].Set(nameA, time.Minute, ip("203.0.113.10"))
	f.resolve(nameA) // прогреть кэш

	f.setHealthy(false)
	m := f.resolve(nameA)
	if m.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode %v, ожидался SERVFAIL", m.Header.RCode)
	}
	if len(m.Answers) != 0 {
		t.Fatalf("в отказе %d ответов", len(m.Answers))
	}
	if udp, _ := f.srv["A"].Queries(); udp != 1 {
		t.Fatalf("в fail-close апстрим спрошен ещё раз (всего %d)", udp)
	}
}

// TestTruncatedAnswerIsRefetchedOverTCP — RFC 1035 §4.2.2: на TC=1 запрос
// дословывается по TCP. Без этого клиент получил бы ответ без записей.
func TestTruncatedAnswerIsRefetchedOverTCP(t *testing.T) {
	f := newFixture(t)
	f.srv["A"].Set(nameA, time.Minute, ip("203.0.113.10"))
	f.srv["A"].SetTruncate(true)

	if got := onlyAddr(t, f.addrsOf(nameA)); got != ip("203.0.113.10") {
		t.Fatalf("после досылки по TCP пришло %v", got)
	}
	if udp, tcp := f.srv["A"].Queries(); udp != 1 || tcp != 1 {
		t.Fatalf("udp=%d tcp=%d, ожидалось 1/1", udp, tcp)
	}
}

// TestNXDOMAINIsCached — отрицательный ответ тоже ответ: без его кэширования
// приложение, ломящееся в несуществующее имя, гоняет узел на каждом запросе.
func TestNXDOMAINIsCached(t *testing.T) {
	f := newFixture(t)
	f.srv["A"].SetNXDOMAIN(nameB)

	for i := 0; i < 3; i++ {
		if rc := f.resolve(nameB).Header.RCode; rc != dnsmessage.RCodeNameError {
			t.Fatalf("rcode %v, ожидался NXDOMAIN", rc)
		}
	}
	if udp, _ := f.srv["A"].Queries(); udp != 1 {
		t.Fatalf("апстрим спрошен %d раз, ожидался один", udp)
	}
}

// TestAAAAAnsweredEmptyWithoutUpstream — §6.9: IPv6 блокируется маршрутами
// TUN, значит и адресов этого семейства у нас нет. Пустой NOERROR говорит это
// приложению сразу; настоящий AAAA-ответ заставил бы его сперва потыкаться в
// адрес, который заведомо никуда не ведёт.
func TestAAAAAnsweredEmptyWithoutUpstream(t *testing.T) {
	f := newFixture(t)
	f.srv["A"].Set(nameA, time.Minute, ip("203.0.113.10"))

	n, err := dnsmessage.NewName(nameA + ".")
	if err != nil {
		t.Fatalf("имя: %v", err)
	}
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 9, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}},
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}

	answer, err := f.res.Query(wire, netip.AddrPort{}, netip.AddrPort{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var out dnsmessage.Message
	if err := out.Unpack(answer); err != nil {
		t.Fatalf("ответ не разобрался: %v", err)
	}
	if out.Header.RCode != dnsmessage.RCodeSuccess || len(out.Answers) != 0 {
		t.Fatalf("на AAAA пришло rcode=%v, записей %d", out.Header.RCode, len(out.Answers))
	}
	if len(out.Questions) != 1 || out.Questions[0].Type != dnsmessage.TypeAAAA {
		t.Fatalf("в ответе не тот вопрос: %+v", out.Questions)
	}
	if udp, tcp := f.srv["A"].Queries(); udp != 0 || tcp != 0 {
		t.Fatalf("на AAAA сходили в апстрим: udp=%d tcp=%d", udp, tcp)
	}
}

// TestFlushDropsEverything — Flush нужен смене сети: адреса за прежним
// провайдером после неё ничего не значат.
func TestFlushDropsEverything(t *testing.T) {
	f := newFixture(t)
	f.srv["A"].Set(nameA, time.Hour, ip("203.0.113.10"))
	f.resolve(nameA)

	f.res.Flush()
	f.srv["A"].Set(nameA, time.Hour, ip("203.0.113.11"))
	if got := onlyAddr(t, f.addrsOf(nameA)); got != ip("203.0.113.11") {
		t.Fatalf("после Flush пришло %v", got)
	}
	if s := f.res.Stats(); s.Flushed != 1 {
		t.Fatalf("сброшено записей %d, ожидалась одна", s.Flushed)
	}
}

// TestMalformedQueryAnswersFormErr — на мусор с разборчивым заголовком
// отвечаем FORMERR: клиент узнаёт исход сразу.
func TestMalformedQueryAnswersFormErr(t *testing.T) {
	f := newFixture(t)

	// Заголовок с QDCOUNT=1 и без единого байта вопроса.
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	answer, err := f.res.Query(query, netip.MustParseAddrPort("10.255.0.2:5300"),
		netip.MustParseAddrPort("10.255.0.1:53"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(answer); err != nil {
		t.Fatalf("ответ не разобрался: %v", err)
	}
	if m.Header.RCode != dnsmessage.RCodeFormatError {
		t.Fatalf("rcode %v, ожидался FORMERR", m.Header.RCode)
	}

	// Обрубок короче заголовка — отвечать не от чьего имени.
	if _, err := f.res.Query([]byte{0x12}, netip.AddrPort{}, netip.AddrPort{}); err == nil {
		t.Fatal("на обрубок короче заголовка ответ построился")
	}
}

// blocking — транспорт, застревающий до отпускания. Единственный способ
// увидеть дедупликацию: без него одинаковые запросы успевают отработать по
// очереди, и склеивать нечего.
type blocking struct {
	inner   Transport
	addr    func() netip.AddrPort
	release chan struct{}

	mu    sync.Mutex
	calls int
}

func (b *blocking) Exchange(ctx context.Context, _ netip.AddrPort, query []byte, stream bool) ([]byte, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	<-b.release
	return b.inner.Exchange(ctx, b.addr(), query, stream)
}

func (b *blocking) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

// TestIdenticalQueriesCoalesce — клиент по UDP переспрашивает сам, не дожидаясь
// ответа. Без склейки каждый ретрансмит превращался бы в отдельный поход через
// узел.
func TestIdenticalQueriesCoalesce(t *testing.T) {
	f := newFixture(t)
	f.srv["A"].Set(nameA, time.Minute, ip("203.0.113.10"))

	tr := &blocking{inner: NewNodeTransport(Direct{}), addr: f.upstream, release: make(chan struct{})}
	f.res = New(Config{
		Transport:  tr,
		Servers:    []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")},
		Clock:      f.clk,
		Healthy:    f.isHealthy,
		ActiveNode: f.node,
	})

	const n = 8
	var wg sync.WaitGroup
	got := make([]netip.Addr, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			answer, err := f.res.Query(queryFor(t, nameA, uint16(i)), netip.AddrPort{}, netip.AddrPort{})
			if err != nil {
				t.Errorf("резолв %d: %v", i, err)
				return
			}
			var m dnsmessage.Message
			if err := m.Unpack(answer); err != nil {
				t.Errorf("ответ %d не разобрался: %v", i, err)
				return
			}
			if m.Header.ID != uint16(i) {
				t.Errorf("ответ %d пришёл с id %d", i, m.Header.ID)
			}
			if a := addrsOf(t, &m); len(a) == 1 {
				got[i] = a[0]
			}
		}(i)
	}

	// Дождаться, пока все восемь упрутся в один и тот же поход.
	waitFor(t, func() bool { return tr.count() >= 1 })
	close(tr.release)
	wg.Wait()

	for i, a := range got {
		if a != ip("203.0.113.10") {
			t.Fatalf("клиент %d получил %v", i, a)
		}
	}
	if c := tr.count(); c != 1 {
		t.Fatalf("походов в апстрим %d, ожидался один", c)
	}
}

// mismatch — апстрим, отвечающий не на тот вопрос.
type mismatch struct{}

func (mismatch) Exchange(_ context.Context, _ netip.AddrPort, query []byte, _ bool) ([]byte, error) {
	var in dnsmessage.Message
	if err := in.Unpack(query); err != nil {
		return nil, err
	}
	name, _ := dnsmessage.NewName(nameB + ".")
	out := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: in.Header.ID, Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
			Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 66}},
		}},
	}
	return out.Pack()
}

// TestAnswerToAnotherQuestionIsRejected — путь до апстрима идёт через узел по
// UDP, и по нему может прийти что угодно. Принять чужой ответ означает
// положить в кэш чужую запись — то есть отравить резолвер всем приложениям
// сразу.
func TestAnswerToAnotherQuestionIsRejected(t *testing.T) {
	f := newFixture(t)
	f.res = New(Config{
		Transport:  mismatch{},
		Clock:      f.clk,
		Healthy:    f.isHealthy,
		ActiveNode: f.node,
		Timeout:    time.Millisecond, // переспрашивать нечего
	})

	m := f.resolve(nameA)
	if m.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode %v, ожидался SERVFAIL", m.Header.RCode)
	}
	if s := f.res.Stats(); s.Entries != 0 {
		t.Fatalf("в кэше %d записей — чужой ответ осел", s.Entries)
	}
}

// flaky — апстрим, который начинает отвечать не сразу: стартовое окно §5.6.
type flaky struct {
	inner Transport
	addr  func() netip.AddrPort

	mu    sync.Mutex
	ready bool
	calls int
}

func (fl *flaky) Exchange(ctx context.Context, _ netip.AddrPort, query []byte, stream bool) ([]byte, error) {
	fl.mu.Lock()
	fl.calls++
	ready := fl.ready
	fl.mu.Unlock()
	if !ready {
		return nil, context.DeadlineExceeded
	}
	return fl.inner.Exchange(ctx, fl.addr(), query, stream)
}

func (fl *flaky) open() {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	fl.ready = true
}

// TestStartupWindowWaitsForNode — §5.6: пока идёт первый обход подписки,
// Healthy() ещё true, а узла нет. Запрос обязан ждать и переспрашивать, а не
// отказывать: иначе первое же приложение получает SERVFAIL в те секунды, пока
// всё на самом деле работает.
func TestStartupWindowWaitsForNode(t *testing.T) {
	f := newFixture(t)
	f.srv["A"].Set(nameA, time.Minute, ip("203.0.113.10"))

	fl := &flaky{inner: NewNodeTransport(Direct{}), addr: f.upstream}
	f.res = New(Config{
		Transport:  fl,
		Servers:    []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")},
		Clock:      f.clk,
		Healthy:    f.isHealthy,
		ActiveNode: f.node,
		Timeout:    10 * time.Second,
		RetryDelay: time.Second,
	})

	done := make(chan netip.Addr, 1)
	go func() {
		answer, err := f.res.Query(queryFor(t, nameA, 7), netip.AddrPort{}, netip.AddrPort{})
		if err != nil {
			t.Errorf("резолв: %v", err)
			done <- netip.Addr{}
			return
		}
		var m dnsmessage.Message
		if err := m.Unpack(answer); err != nil {
			t.Errorf("ответ не разобрался: %v", err)
			done <- netip.Addr{}
			return
		}
		if a := addrsOf(t, &m); len(a) == 1 {
			done <- a[0]
			return
		}
		done <- netip.Addr{}
	}()

	// Узла ещё нет: запрос упирается в отказ и уходит ждать.
	waitFor(t, func() bool { return fl.calls > 0 })
	select {
	case a := <-done:
		t.Fatalf("резолвер сдался в стартовом окне, вернув %v", a)
	case <-time.After(50 * time.Millisecond): //hop:realtime
	}

	fl.open()
	f.clk.Advance(time.Second)
	select {
	case a := <-done:
		if a != ip("203.0.113.10") {
			t.Fatalf("после появления узла пришло %v", a)
		}
	case <-time.After(5 * time.Second): //hop:realtime
		t.Fatal("резолвер не ответил после появления узла")
	}
}

// waitFor крутится, пока условие не станет истинным. Настоящее время здесь —
// только сторож теста, а не проверяемая величина.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second) //hop:realtime
	for !cond() {
		if time.Now().After(deadline) { //hop:realtime
			t.Fatal("условие не наступило за 2 с")
		}
		time.Sleep(time.Millisecond) //hop:realtime
	}
}

// Политика проверяется тестом T14 выше; здесь — страховка от опечатки в имени.
func TestPolicyNamesAreRegistered(t *testing.T) {
	for _, want := range []*policy.Policy{policy.DNSCacheFlush, policy.Bootstrap} {
		var found bool
		for _, p := range policy.All() {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("политика %q не в реестре", want.Name)
		}
	}
}
