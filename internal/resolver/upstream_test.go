package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time" //hop:realtime — сторож теста и модельные длительности

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dnsmsg"
	"github.com/shafed/hop/internal/dnstest"
	"github.com/shafed/hop/internal/phase"
)

// Проверки пути наверх: D1, D14, D15, D33–D37, D40–D44
// (docs/verification-dns.md §5).
//
// Модельное время двигается только после dnstest.Clock.WaitAfterCalls: пока
// горутина не встала в ожидание, Advance для неё не наступает, и тест, который
// крутит часы вслепую, зелен через раз. Ожидание обёрнуто сторожем на
// настоящем времени по одной причине: с выключенным флагом политики ожидания
// может не быть вовсе, и охранник обязан покраснеть за секунду, а не за
// таймаут go test — negcheck гоняет его именно так.

// testWatchdog — потолок настоящего времени на любое ожидание в этом файле.
// Достигается только на сломанном коде: на исправном все ожидания снимаются
// модельными часами немедленно.
const testWatchdog = 5 * time.Second

// sockets — счётчик открытых и незакрытых сокетов наверх.
//
// D40 и D44 — про ресурсы, и «сокет закрыт» здесь факт о вызове Close, а не
// догадка по числу горутин: обёртка считает то, что резолвер сделал, а не то,
// что тест успел заметить.
type sockets struct {
	mu         sync.Mutex
	cond       *sync.Cond
	open, peak int
	reads      int // входов в Read на сокетах наверх
}

func newSockets() *sockets {
	s := &sockets{}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *sockets) opened() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.open++
	if s.open > s.peak {
		s.peak = s.open
	}
}

func (s *sockets) closed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.open--
}

func (s *sockets) counts() (open, peak int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open, s.peak
}

// reading отмечает вход в Read — до того, как чтение заблокируется.
//
// Это единственный синхронный признак «прошлую датаграмму разобрали и ждём
// следующую». Без него проверка «ответ с чужим идентификатором отброшен»
// зелена и в резолвере, который его принял: таймаут попытки успевает
// сработать раньше, чем датаграмма доедет, и тест меряет гонку, а не логику.
func (s *sockets) reading() {
	s.mu.Lock()
	s.reads++
	s.cond.Broadcast()
	s.mu.Unlock()
}

// waitReads ждёт n-го входа в Read.
func (s *sockets) waitReads(t *testing.T, n int) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		s.mu.Lock()
		for s.reads < n {
			s.cond.Wait()
		}
		s.mu.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(testWatchdog): //hop:realtime сторож
		s.mu.Lock()
		got := s.reads
		s.mu.Unlock()
		t.Fatalf("входов в Read %d, ждали %d — сокет наверх не читают", got, n)
	}
}

type countedPacketConn struct {
	net.PacketConn
	s    *sockets
	once sync.Once
}

func (c *countedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.s.reading()
	return c.PacketConn.ReadFrom(p)
}

// Close считает ровно первое закрытие: повторный Close — не второй сокет.
func (c *countedPacketConn) Close() error {
	c.once.Do(c.s.closed)
	return c.PacketConn.Close()
}

type countedConn struct {
	net.Conn
	s    *sockets
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(c.s.closed)
	return c.Conn.Close()
}

func (s *sockets) countDialUDP(inner DialUDPFunc) DialUDPFunc {
	return func(ctx context.Context, dst netip.AddrPort) (net.PacketConn, error) {
		c, err := inner(ctx, dst)
		if err != nil {
			return nil, err
		}
		s.opened()
		return &countedPacketConn{PacketConn: c, s: s}, nil
	}
}

func (s *sockets) countDial(inner DialFunc) DialFunc {
	return func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		c, err := inner(ctx, dst)
		if err != nil {
			return nil, err
		}
		s.opened()
		return &countedConn{Conn: c, s: s}, nil
	}
}

func (s *sockets) countDialDirect(inner DialDirectFunc) DialDirectFunc {
	return func(ctx context.Context, network string, dst netip.AddrPort) (net.Conn, error) {
		c, err := inner(ctx, network, dst)
		if err != nil {
			return nil, err
		}
		s.opened()
		return &countedConn{Conn: c, s: s}, nil
	}
}

// upstreamStand — резолвер на фейковых часах против поддельного апстрима.
type upstreamStand struct {
	t     *testing.T
	r     *Resolver
	up    *dnstest.Upstream
	clk   *dnstest.Clock
	fake  *clock.Fake
	socks *sockets
	addrs []netip.AddrPort
}

// newUpstreamStand поднимает резолвер на n апстримах.
//
// Апстримов по умолчанию два — столько же, сколько в продукте (§5.7): при
// апстриме, отвечающем без задержки, фора не наступает никогда, потому что
// модельные часы стоят, пока тест их не сдвинет. Один апстрим берут сценарии,
// где второй добавил бы к проверке только вторую копию того же отказа.
func newUpstreamStand(t *testing.T, n int) *upstreamStand {
	t.Helper()

	fake := clock.NewFake(time.Unix(0, 0))
	clk := dnstest.NewClock(fake)
	up := dnstest.New(clk)
	socks := newSockets()

	addrs := make([]netip.AddrPort, n)
	for i := range addrs {
		addrs[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(10 + i)}), 53)
	}

	r, err := New(Config{
		Upstreams:  addrs,
		DialUDP:    socks.countDialUDP(up.DialUDP),
		Dial:       socks.countDial(up.Dial),
		DialDirect: socks.countDialDirect(up.DialDirect),
		Phase:      func() phase.Traffic { return phase.Proxied },
		Clock:      clk,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { r.Close() })

	return &upstreamStand{t: t, r: r, up: up, clk: clk, fake: fake, socks: socks, addrs: addrs}
}

type queryResult struct {
	resp []byte
	err  error
}

// queryAsync запускает клиентский запрос и не ждёт его: пока он летит, тест
// двигает модельные часы.
func (s *upstreamStand) queryAsync(query []byte, tr Transport) <-chan queryResult {
	ch := make(chan queryResult, 1)
	go func() {
		var (
			resp []byte
			err  error
		)
		if tr == TransportTCP {
			resp, err = s.r.QueryStream(query, netip.AddrPort{}, netip.AddrPort{})
		} else {
			resp, err = s.r.Query(query, netip.AddrPort{}, netip.AddrPort{})
		}
		ch <- queryResult{resp: resp, err: err}
	}()
	return ch
}

// await — результат запроса со сторожем.
func (s *upstreamStand) await(ch <-chan queryResult) queryResult {
	s.t.Helper()
	select {
	case res := <-ch:
		return res
	case <-time.After(testWatchdog): //hop:realtime сторож
		s.t.Fatal("резолвер не ответил за сторожевой срок")
		return queryResult{}
	}
}

// query — запрос целиком, для сценариев, где часы двигать не нужно.
func (s *upstreamStand) query(query []byte, tr Transport) []byte {
	s.t.Helper()
	res := s.await(s.queryAsync(query, tr))
	if res.err != nil {
		s.t.Fatalf("Query: %v", res.err)
	}
	return res.resp
}

// waitAfter ждёт, пока общее число обращений к After не дойдёт до n.
func (s *upstreamStand) waitAfter(n uint64) {
	s.t.Helper()
	done := make(chan struct{})
	go func() {
		s.clk.WaitAfterCalls(n)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(testWatchdog): //hop:realtime сторож
		s.t.Fatalf("ожиданий на часах %d, ждали %d — резолвер не встал в ожидание",
			s.clk.AfterCalls(), n)
	}
}

// answerA — апстрим отвечает A-записью с тем идентификатором, что пришёл.
//
// Func, а не готовые байты: наверх уходит наш идентификатор, а не клиентский
// (Р23), и тест его не знает — знать его значило бы дублировать в тесте
// правило, которое он проверяет.
func answerA(name string, ttl uint32, ip string, delay time.Duration) dnstest.Behavior {
	addr := netip.MustParseAddr(ip)
	return dnstest.Behavior{
		Delay: delay,
		Func: func(q []byte) []byte {
			return dnstest.ResponseA(dnstest.QueryID(q), name, ttl, addr)
		},
	}
}

func clientQuery(id uint16, name string) []byte {
	return dnstest.BuildQuery(dnstest.QueryOpts{ID: id, Name: name, Type: dnstest.TypeA})
}

func parseAnswer(t *testing.T, raw []byte) dnsmsg.Msg {
	t.Helper()
	m, err := dnsmsg.Parse(raw)
	if err != nil {
		t.Fatalf("разбор ответа клиенту: %v", err)
	}
	return m
}

// firstA — адрес первой A-записи секции ANSWER.
func firstA(t *testing.T, m dnsmsg.Msg) netip.Addr {
	t.Helper()
	sc := m.Scan()
	for sc.Next() {
		rr := sc.RR()
		if rr.Section != dnsmsg.SectionAnswer || rr.Type != dnsmsg.TypeA {
			continue
		}
		addr, ok := netip.AddrFromSlice(m.Raw[rr.RDStart:rr.RDEnd])
		if !ok {
			t.Fatalf("RDATA A в %d байт", rr.RDLength())
		}
		return addr
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("обход ответа: %v", err)
	}
	t.Fatal("в ответе нет A-записи")
	return netip.Addr{}
}

// countAnswers — записей в секции ANSWER по факту, а не по счётчику
// заголовка: D33 требует полный RRset, а не обещание полного.
func countAnswers(t *testing.T, m dnsmsg.Msg) int {
	t.Helper()
	n := 0
	sc := m.Scan()
	for sc.Next() {
		if sc.RR().Section == dnsmsg.SectionAnswer {
			n++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("обход ответа: %v", err)
	}
	return n
}

// D1. Запрос A-записи при живом узле: наверх ушло через DialUDP, мимо туннеля
// не ушло ничего.
func TestD1QueryGoesUpThroughNodeDialer(t *testing.T) {
	s := newUpstreamStand(t, 2)
	s.up.Program(s.addrs[0], answerA("example.com", 300, "203.0.113.7", 0))

	resp := s.query(clientQuery(0x1234, "example.com"), TransportUDP)

	m := parseAnswer(t, resp)
	if m.Header.ID != 0x1234 {
		t.Fatalf("идентификатор ответа %#x, хотим клиентский 0x1234", m.Header.ID)
	}
	if got := firstA(t, m); got != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("адрес в ответе %s", got)
	}

	calls := s.up.Calls()
	if calls.DialUDP != 1 {
		t.Fatalf("DialUDP позван %d раз, хотим 1", calls.DialUDP)
	}
	if calls.Dial != 0 || calls.DialDirect != 0 {
		t.Fatalf("лишние диалеры: Dial=%d DialDirect=%d", calls.Dial, calls.DialDirect)
	}

	st := s.r.Snapshot()
	if st.Upstream[0] != 1 || st.Upstream[1] != 0 {
		t.Fatalf("Upstream = %v, хотим [1 0]", st.Upstream)
	}
	if st.UpstreamDirect != 0 {
		t.Fatalf("UpstreamDirect = %d, мимо туннеля ходить было не за чем", st.UpstreamDirect)
	}
}

// D14. Оба апстрима молчат: SERVFAIL в пределах общего бюджета 5 с, клиент не
// остался без ответа.
func TestD14BothUpstreamsSilentGiveServFail(t *testing.T) {
	s := newUpstreamStand(t, 2)
	// Оба адреса не запрограммированы вовсе — стенд на такие молчит.

	start := s.fake.Now()
	ch := s.queryAsync(clientQuery(0x0E14, "silent.example"), TransportUDP)

	// Бюджет клиента, таймаут первой попытки, фора второму.
	s.waitAfter(3)
	s.fake.Advance(DefaultHeadStart)
	// Плюс таймаут второй попытки.
	s.waitAfter(4)
	s.fake.Advance(AttemptTimeout)

	res := s.await(ch)
	if res.err != nil {
		t.Fatalf("Query: %v", res.err)
	}
	m := parseAnswer(t, res.resp)
	if rc := m.Header.Rcode(); rc != dnsmsg.RcodeServFail {
		t.Fatalf("rcode = %d, хотим SERVFAIL", rc)
	}
	if elapsed := s.fake.Now().Sub(start); elapsed >= ClientBudget {
		t.Fatalf("отказ занял %s при бюджете %s — клиент ждал дольше, чем ему обещано", elapsed, ClientBudget)
	}
	if st := s.r.Snapshot(); st.ServFail != 1 || st.Entries != 0 {
		t.Fatalf("ServFail = %d, Entries = %d, хотим 1 и 0", st.ServFail, st.Entries)
	}
	if open, _ := s.socks.counts(); open != 0 {
		t.Fatalf("после отказа осталось %d открытых сокетов", open)
	}
}

// D15. Апстрим ответил мусором: SERVFAIL, в кэш ничего не положено.
//
// Апстрим один: сценарий про ответ апстрима, а не про выбор между двумя, и
// второй добавил бы к проверке только вторую копию того же отказа.
func TestD15GarbageFromUpstreamIsServFail(t *testing.T) {
	cases := []struct {
		name   string
		answer func(query []byte) []byte
	}{
		{
			name:   "битый заголовок",
			answer: func([]byte) []byte { return dnstest.BrokenHeader() },
		},
		{
			name: "лишние байты за последней записью",
			answer: func(q []byte) []byte {
				return dnstest.TrailingGarbage(
					dnstest.ResponseA(dnstest.QueryID(q), "garbage.example", 300, netip.MustParseAddr("203.0.113.9")))
			},
		},
		{
			name: "ответ на чужой вопрос",
			answer: func(q []byte) []byte {
				return dnstest.ResponseA(dnstest.QueryID(q), "other.example", 300, netip.MustParseAddr("203.0.113.9"))
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newUpstreamStand(t, 1)
			s.up.Program(s.addrs[0], dnstest.Behavior{Func: c.answer})

			resp := s.query(clientQuery(0x0E15, "garbage.example"), TransportUDP)

			m := parseAnswer(t, resp)
			if rc := m.Header.Rcode(); rc != dnsmsg.RcodeServFail {
				t.Fatalf("rcode = %d, хотим SERVFAIL", rc)
			}
			if st := s.r.Snapshot(); st.Entries != 0 {
				t.Fatalf("в кэше %d записей — мусор осел", st.Entries)
			}
			if open, _ := s.socks.counts(); open != 0 {
				t.Fatalf("после отказа осталось %d открытых сокетов", open)
			}
		})
	}
}

// truncatedThenFull — апстрим, отвечающий по UDP усечённо, а по TCP полно.
//
// Различает транспорт порядком вызовов: Behavior один на адрес, и стенд не
// сообщает, кто спрашивает. Порядок задан самим сценарием — сначала
// датаграмма, потом повтор по TCP, — и другого в D33–D37 не бывает.
func truncatedThenFull(short, full func(id uint16) []byte) dnstest.Behavior {
	var calls atomic.Int32
	return dnstest.Behavior{
		Func: func(q []byte) []byte {
			id := dnstest.QueryID(q)
			if calls.Add(1) == 1 {
				return dnstest.WithTC(short(id))
			}
			return full(id)
		},
	}
}

// D33. Апстрим ответил с флагом TC, клиент пришёл по TCP: резолвер повторил по
// TCP, клиент получил полный RRset. Флаг dns_tcp_retry.
func TestD33TruncatedAnswerRetriesOverTCP(t *testing.T) {
	const name = "big.example"
	full := func(id uint16) []byte {
		return dnstest.BuildResponse(dnstest.ResponseOpts{
			ID: id, QName: name, QType: dnstest.TypeA,
			Flags: dnstest.Flags{RD: true, RA: true},
			Answer: []dnstest.RR{
				{Name: name, Type: dnstest.TypeA, TTL: 300, Data: netip.MustParseAddr("203.0.113.1").AsSlice()},
				{Name: name, Type: dnstest.TypeA, TTL: 300, Data: netip.MustParseAddr("203.0.113.2").AsSlice()},
				{Name: name, Type: dnstest.TypeA, TTL: 300, Data: netip.MustParseAddr("203.0.113.3").AsSlice()},
			},
		})
	}
	short := func(id uint16) []byte {
		return dnstest.ResponseA(id, name, 300, netip.MustParseAddr("203.0.113.1"))
	}

	s := newUpstreamStand(t, 1)
	s.up.Program(s.addrs[0], truncatedThenFull(short, full))

	resp := s.query(clientQuery(0x0D33, name), TransportTCP)

	m := parseAnswer(t, resp)
	if m.Header.Truncated() {
		t.Fatal("клиенту по TCP ушёл ответ с TC — усекать его не за чем")
	}
	if got := countAnswers(t, m); got != 3 {
		t.Fatalf("записей в ANSWER %d, хотим полный RRset из 3", got)
	}
	if st := s.r.Snapshot(); st.TCPRetry != 1 {
		t.Fatalf("TCPRetry = %d, хотим 1", st.TCPRetry)
	}

	qs := s.up.Queries()
	if len(qs) != 2 {
		t.Fatalf("наверх ушло %d запросов, хотим 2 (датаграмма и повтор)", len(qs))
	}
	if qs[0].Via != dnstest.ViaDialUDP || qs[1].Via != dnstest.ViaDial {
		t.Fatalf("пути наверх: %s, затем %s", qs[0].Via, qs[1].Via)
	}
	if open, _ := s.socks.counts(); open != 0 {
		t.Fatalf("после повтора осталось %d открытых сокетов", open)
	}
}

// oversizedAfterTC — тот же апстрим, но полный ответ заведомо не влезает в
// 512 байт клиента: сценарии D34 и D36.
func oversizedAfterTC(name string, size int) dnstest.Behavior {
	return truncatedThenFull(
		func(id uint16) []byte {
			return dnstest.ResponseA(id, name, 300, netip.MustParseAddr("203.0.113.1"))
		},
		func(id uint16) []byte { return dnstest.ResponseOversized(id, name, size) },
	)
}

// D34. То же, клиент пришёл по UDP без EDNS0: ему ушёл ответ ≤ 512 байт с
// флагом TC, а не урезанный RRset без него.
func TestD34TruncatedToUDPClientCarriesTC(t *testing.T) {
	const name = "big.example"
	s := newUpstreamStand(t, 1)
	s.up.Program(s.addrs[0], oversizedAfterTC(name, 600))

	query := clientQuery(0x0D34, name)
	resp := s.query(query, TransportUDP)

	if len(resp) > ClientUDPDefault {
		t.Fatalf("клиенту ушло %d байт при потолке %d", len(resp), ClientUDPDefault)
	}
	m := parseAnswer(t, resp)
	if !m.Header.Truncated() {
		t.Fatal("флаг TC не поднят: приложение примет обрезок за весь RRset")
	}
	if got := countAnswers(t, m); got != 0 {
		t.Fatalf("в усечённом ответе %d записей — режем по границе секции, а не по байтам", got)
	}
	if m.Header.ANCount != 0 || m.Header.NSCount != 0 || m.Header.ARCount != 0 {
		t.Fatalf("счётчики секций не обнулены: AN=%d NS=%d AR=%d", m.Header.ANCount, m.Header.NSCount, m.Header.ARCount)
	}
	if st := s.r.Snapshot(); st.TruncToClient != 1 || st.TCPRetry != 1 {
		t.Fatalf("TruncToClient = %d, TCPRetry = %d, хотим 1 и 1", st.TruncToClient, st.TCPRetry)
	}
}

// D34б. Клиент объявил буфер EDNS0 512, ответ не влез: усечённый ответ несёт
// OPT, отражающую EDNS0 клиента (RFC 6891 §6.1.1), не апстримовскую.
func TestD34bTruncatedResponseCarriesClientOPT(t *testing.T) {
	const name = "big.example"
	s := newUpstreamStand(t, 1)
	s.up.Program(s.addrs[0], oversizedAfterTC(name, 600))

	query := dnstest.BuildQuery(dnstest.QueryOpts{
		ID: 0x0D3B, Name: name, Type: dnstest.TypeA,
		EDNS0: true, BufSize: 512,
	})
	resp := s.query(query, TransportUDP)

	m := parseAnswer(t, resp)
	if !m.Header.Truncated() {
		t.Fatal("флаг TC не поднят — подготовка теста сломана")
	}
	if m.Header.ARCount != 1 {
		t.Fatalf("ARCOUNT = %d, хотим 1 (одна OPT)", m.Header.ARCount)
	}
	opt, ok, err := m.EDNS()
	if err != nil {
		t.Fatalf("разбор OPT: %v", err)
	}
	if !ok {
		t.Fatal("в усечённом ответе нет OPT: клиент с EDNS0 сочтёт нас не понимающими EDNS0")
	}
	if opt.UDPSize != 512 {
		t.Fatalf("UDPSize в OPT = %d, хотим 512 — то, что объявил клиент", opt.UDPSize)
	}
}

// D34б, отрицательный случай: клиент без EDNS0 не получает OPT — ему нечего
// отражать, и вставлять OPT в ответ клиенту, который её не заявлял, само по
// себе искажение (У6).
func TestD34bClientWithoutEDNS0GetsNoOPT(t *testing.T) {
	const name = "big.example"
	s := newUpstreamStand(t, 1)
	s.up.Program(s.addrs[0], oversizedAfterTC(name, 600))

	resp := s.query(clientQuery(0x0D3C, name), TransportUDP)

	m := parseAnswer(t, resp)
	if !m.Header.Truncated() {
		t.Fatal("флаг TC не поднят — подготовка теста сломана")
	}
	if m.Header.ARCount != 0 {
		t.Fatalf("ARCOUNT = %d, хотим 0: клиент EDNS0 не объявлял", m.Header.ARCount)
	}
}

// D35. То же, клиент объявил буфер EDNS0 4096, ответ 1200 байт: ушёл целиком,
// без TC.
func TestD35AnswerWithinClientBufferGoesWhole(t *testing.T) {
	const name = "medium.example"
	const size = 1200

	s := newUpstreamStand(t, 1)
	s.up.Program(s.addrs[0], dnstest.Behavior{Func: func(q []byte) []byte {
		return dnstest.ResponseOversized(dnstest.QueryID(q), name, size)
	}})

	query := dnstest.BuildQuery(dnstest.QueryOpts{
		ID: 0x0D35, Name: name, Type: dnstest.TypeA,
		EDNS0: true, BufSize: 4096,
	})
	resp := s.query(query, TransportUDP)

	// Длина ответа от идентификатора не зависит, поэтому её можно посчитать
	// той же фикстурой с любым.
	if want := len(dnstest.ResponseOversized(0, name, size)); len(resp) != want {
		t.Fatalf("клиенту ушло %d байт, апстрим прислал %d", len(resp), want)
	}
	if len(resp) <= ClientUDPDefault {
		t.Fatalf("фикстура на %d байт не проверяет ничего: она влезла бы и в 512", len(resp))
	}
	m := parseAnswer(t, resp)
	if m.Header.Truncated() {
		t.Fatal("поднят TC на ответе, влезшем в объявленный клиентом буфер")
	}
	if st := s.r.Snapshot(); st.TruncToClient != 0 || st.TCPRetry != 0 {
		t.Fatalf("TruncToClient = %d, TCPRetry = %d, хотим 0 и 0", st.TruncToClient, st.TCPRetry)
	}
}

// D36. Клиент повторил тот же вопрос по TCP после TC: получил полный ответ, и
// повторного похода наверх не было — отдано из кэша.
func TestD36RepeatOverTCPComesFromCache(t *testing.T) {
	const name = "big.example"
	s := newUpstreamStand(t, 1)
	s.up.Program(s.addrs[0], oversizedAfterTC(name, 600))

	first := s.query(clientQuery(0x0D36, name), TransportUDP)
	if m := parseAnswer(t, first); !m.Header.Truncated() {
		t.Fatal("первый ответ по UDP обязан нести TC")
	}
	before := s.up.Calls()

	second := s.query(clientQuery(0x0D37, name), TransportTCP)

	m := parseAnswer(t, second)
	if m.Header.Truncated() {
		t.Fatal("ответ по TCP усечён")
	}
	if countAnswers(t, m) == 0 {
		t.Fatal("в ответе по TCP нет записей — полный RRset не доехал")
	}
	if after := s.up.Calls(); after != before {
		t.Fatalf("наверх сходили ещё раз: было %+v, стало %+v", before, after)
	}
	if st := s.r.Snapshot(); st.Hits != 1 {
		t.Fatalf("Hits = %d, хотим 1: второй вопрос обязан прийти из кэша", st.Hits)
	}
}

// D37. Апстрим по TCP отдал сообщение с неверным префиксом длины: SERVFAIL,
// соединение закрыто, частичное сообщение клиенту не уходит.
func TestD37BadLengthPrefixOverTCPIsServFail(t *testing.T) {
	const name = "broken.example"
	s := newUpstreamStand(t, 1)
	// BadLengthPrefix относится только к потоку: датаграмму стенд отдаёт по
	// Func, то есть с флагом TC, и повтор по TCP наткнётся на битый кадр.
	s.up.Program(s.addrs[0], dnstest.Behavior{
		BadLengthPrefix: true,
		Func: func(q []byte) []byte {
			return dnstest.WithTC(dnstest.ResponseA(dnstest.QueryID(q), name, 300, netip.MustParseAddr("203.0.113.1")))
		},
	})

	resp := s.query(clientQuery(0x0D3A, name), TransportTCP)

	m := parseAnswer(t, resp)
	if rc := m.Header.Rcode(); rc != dnsmsg.RcodeServFail {
		t.Fatalf("rcode = %d, хотим SERVFAIL", rc)
	}
	if countAnswers(t, m) != 0 {
		t.Fatal("клиенту уехали записи из оборванного кадра")
	}
	if st := s.r.Snapshot(); st.Entries != 0 {
		t.Fatalf("в кэше %d записей после битого кадра", st.Entries)
	}
	if open, _ := s.socks.counts(); open != 0 {
		t.Fatalf("соединение не закрыто: %d открытых сокетов", open)
	}
}

// settleGoroutines ждёт, пока число горутин не вернётся к base.
//
// Опрос, а не ожидание на канале: горутина бюджета (withBudget) уходит по
// отмене контекста уже после того, как Query вернулся, и синхронного признака
// её ухода наружу нет. Сторож на настоящем времени — единственный способ не
// превратить дефект в таймаут go test.
func settleGoroutines(t *testing.T, base int) {
	t.Helper()
	deadline := time.After(testWatchdog) //hop:realtime сторож
	for {
		n := runtime.NumGoroutine()
		if n <= base {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("горутин %d, до запросов было %d — что-то повисло", n, base)
		default:
			runtime.Gosched()
		}
	}
}

// D40. Сто запросов к молчащему апстриму, затем истечение таймаутов:
// InFlight = 0, сокеты закрыты, висящих горутин нет.
func TestD40SilentUpstreamLeavesNoSockets(t *testing.T) {
	const clients = 100

	s := newUpstreamStand(t, 2)
	// Оба апстрима молчат: именно на этом состоянии сети ресурсы и копятся.

	base := runtime.NumGoroutine()

	chans := make([]<-chan queryResult, clients)
	for i := range chans {
		// Имена разные: одинаковые склеились бы в один полёт (Р24), и проверка
		// про сто сокетов проверяла бы один.
		chans[i] = s.queryAsync(clientQuery(uint16(0x1000+i), fmt.Sprintf("h%d.example", i)), TransportUDP)
	}

	// На каждый запрос: бюджет, таймаут первой попытки, фора второму.
	s.waitAfter(3 * clients)
	s.fake.Advance(DefaultHeadStart)
	// Плюс таймаут второй попытки на каждый.
	s.waitAfter(4 * clients)
	s.fake.Advance(AttemptTimeout)

	for i, ch := range chans {
		res := s.await(ch)
		if res.err != nil {
			t.Fatalf("клиент %d: %v", i, res.err)
		}
		if rc := parseAnswer(t, res.resp).Header.Rcode(); rc != dnsmsg.RcodeServFail {
			t.Fatalf("клиент %d: rcode = %d, хотим SERVFAIL", i, rc)
		}
	}

	open, peak := s.socks.counts()
	if open != 0 {
		t.Fatalf("осталось %d открытых сокетов наверх", open)
	}
	if peak < clients {
		t.Fatalf("пик открытых сокетов %d — сто запросов наверх не ушли", peak)
	}
	if st := s.r.Snapshot(); st.InFlight != 0 || st.ServFail != clients {
		t.Fatalf("InFlight = %d, ServFail = %d, хотим 0 и %d", st.InFlight, st.ServFail, clients)
	}
	settleGoroutines(t, base)
}

// D44. Тысяча запросов подряд по одному: сокетов наверх не накапливается,
// InFlight возвращается к 0.
func TestD44SequentialQueriesLeaveNoSockets(t *testing.T) {
	const queries = 1000

	s := newUpstreamStand(t, 1)
	ip := netip.MustParseAddr("203.0.113.44")

	for i := range queries {
		name := fmt.Sprintf("h%d.example", i)
		s.up.Program(s.addrs[0], dnstest.Behavior{Func: func(q []byte) []byte {
			return dnstest.ResponseA(dnstest.QueryID(q), name, 300, ip)
		}})

		resp := s.query(clientQuery(uint16(i), name), TransportUDP)
		if got := firstA(t, parseAnswer(t, resp)); got != ip {
			t.Fatalf("запрос %d: адрес %s", i, got)
		}
		if open, _ := s.socks.counts(); open != 0 {
			t.Fatalf("запрос %d: %d открытых сокетов после ответа", i, open)
		}
	}

	_, peak := s.socks.counts()
	if peak != 1 {
		t.Fatalf("пик открытых сокетов %d — последовательные запросы держат больше одного", peak)
	}
	if st := s.r.Snapshot(); st.InFlight != 0 {
		t.Fatalf("InFlight = %d после всех ответов", st.InFlight)
	}
}

// D41. Первый апстрим отвечает за 20 мс: второй не спрошен вовсе.
// Флаг dns_upstream.
//
// Вторая половина теста — не дубль D42, а то, что делает проверку валидной:
// «второй не спрошен» обязано быть утверждением об этом ответе, а не о
// резолвере, который про второй апстрим не знает вовсе. С выключенным флагом
// первая половина зелена, и без второй охранник не охранял бы ничего (§8).
func TestD41FastFirstUpstreamSkipsSecond(t *testing.T) {
	s := newUpstreamStand(t, 2)
	s.up.Program(s.addrs[0], answerA("fast.example", 300, "203.0.113.41", 20*time.Millisecond))

	ch := s.queryAsync(clientQuery(0x0D41, "fast.example"), TransportUDP)
	// Бюджет, таймаут попытки, фора второму и задержка ответа на стенде.
	s.waitAfter(4)
	s.fake.Advance(20 * time.Millisecond)

	res := s.await(ch)
	if res.err != nil {
		t.Fatalf("Query: %v", res.err)
	}
	if got := firstA(t, parseAnswer(t, res.resp)); got != netip.MustParseAddr("203.0.113.41") {
		t.Fatalf("адрес в ответе %s", got)
	}
	if st := s.r.Snapshot(); st.Upstream[1] != 0 {
		t.Fatalf("Upstream[1] = %d: второй спрошен, хотя первый ответил до форы", st.Upstream[1])
	}

	// Тот же резолвер, другое имя: первый молчит — значит фора обязана
	// наступить и второй обязан быть спрошен.
	base := s.clk.AfterCalls()
	s.up.Program(s.addrs[0], dnstest.Behavior{Silent: true})
	s.up.Program(s.addrs[1], answerA("slow.example", 300, "203.0.113.42", 0))

	ch = s.queryAsync(clientQuery(0x0D42, "slow.example"), TransportUDP)
	s.waitAfter(base + 3)
	s.fake.Advance(DefaultHeadStart)

	res = s.await(ch)
	if res.err != nil {
		t.Fatalf("Query: %v", res.err)
	}
	if got := firstA(t, parseAnswer(t, res.resp)); got != netip.MustParseAddr("203.0.113.42") {
		t.Fatalf("адрес в ответе %s, хотим адрес второго апстрима", got)
	}
	if st := s.r.Snapshot(); st.Upstream[1] != 1 {
		t.Fatalf("Upstream[1] = %d, хотим 1: второй апстрим обязан быть спрошен после форы", st.Upstream[1])
	}
}

// D42. Первый молчит: второй спрошен через 150 мс модельного времени, ответ
// доехал. Флаг dns_upstream.
func TestD42SilentFirstFallsToSecond(t *testing.T) {
	s := newUpstreamStand(t, 2)
	s.up.Program(s.addrs[0], dnstest.Behavior{Silent: true})
	s.up.Program(s.addrs[1], answerA("fallback.example", 300, "203.0.113.43", 0))

	start := s.fake.Now()
	ch := s.queryAsync(clientQuery(0x0D43, "fallback.example"), TransportUDP)

	// Бюджет, таймаут первой попытки, фора второму: дальше часы можно двигать.
	s.waitAfter(3)
	if got := len(s.up.Queries()); got != 1 {
		t.Fatalf("наверх ушло %d запросов до истечения форы, хотим 1", got)
	}
	s.fake.Advance(DefaultHeadStart)

	res := s.await(ch)
	if res.err != nil {
		t.Fatalf("Query: %v", res.err)
	}
	if got := firstA(t, parseAnswer(t, res.resp)); got != netip.MustParseAddr("203.0.113.43") {
		t.Fatalf("адрес в ответе %s, хотим адрес второго апстрима", got)
	}

	qs := s.up.Queries()
	if len(qs) != 2 {
		t.Fatalf("наверх ушло %d запросов, хотим 2", len(qs))
	}
	if qs[1].Dst != s.addrs[1] {
		t.Fatalf("второй запрос ушёл на %s, хотим %s", qs[1].Dst, s.addrs[1])
	}
	if elapsed := s.fake.Now().Sub(start); elapsed != DefaultHeadStart {
		t.Fatalf("второй спрошен через %s, хотим ровно %s", elapsed, DefaultHeadStart)
	}
	if st := s.r.Snapshot(); st.Upstream[0] != 1 || st.Upstream[1] != 1 {
		t.Fatalf("Upstream = %v, хотим [1 1]", st.Upstream)
	}
}

// D43. Второй уже спрошен, затем ответил первый: клиенту ушёл первый
// доехавший, в кэш легла одна запись.
func TestD43FirstArrivedWinsAndCachesOnce(t *testing.T) {
	const name = "race.example"
	s := newUpstreamStand(t, 2)
	// Первый отвечает на 300 мс — то есть после форы, но раньше второго.
	s.up.Program(s.addrs[0], answerA(name, 300, "203.0.113.1", 300*time.Millisecond))
	s.up.Program(s.addrs[1], answerA(name, 300, "203.0.113.2", time.Second))

	ch := s.queryAsync(clientQuery(0x0D44, name), TransportUDP)

	// Бюджет, таймаут первой попытки, фора, задержка первого апстрима.
	s.waitAfter(4)
	s.fake.Advance(DefaultHeadStart)
	// Плюс таймаут второй попытки и задержка второго апстрима.
	s.waitAfter(6)
	s.fake.Advance(300*time.Millisecond - DefaultHeadStart)

	res := s.await(ch)
	if res.err != nil {
		t.Fatalf("Query: %v", res.err)
	}
	if got := firstA(t, parseAnswer(t, res.resp)); got != netip.MustParseAddr("203.0.113.1") {
		t.Fatalf("адрес в ответе %s, хотим адрес доехавшего первым", got)
	}

	st := s.r.Snapshot()
	if st.Upstream[0] != 1 || st.Upstream[1] != 1 {
		t.Fatalf("Upstream = %v, хотим [1 1]: оба спрошены", st.Upstream)
	}
	if st.Entries != 1 {
		t.Fatalf("в кэше %d записей, хотим одну", st.Entries)
	}
	if st.Misses != 1 {
		t.Fatalf("Misses = %d, хотим 1", st.Misses)
	}
	if open, _ := s.socks.counts(); open != 0 {
		t.Fatalf("осталось %d открытых сокетов: проигравшая попытка не убрана", open)
	}
}

// Наверх уходит наш идентификатор, и принимается только ответ с ним (Р23).
//
// Номера в регистре у этой проверки нет: D4 смотрит на запрос, а здесь
// проверяется вторая половина того же решения — что чужой ответ на нашем
// сокете не становится ответом клиенту. Без неё локальный процесс, знающий
// свой идентификатор, задавал бы содержимое чужих ответов.
func TestUpstreamAnswerWithForeignIDIsIgnored(t *testing.T) {
	const name = "spoof.example"
	const clientID = 0xABCD

	s := newUpstreamStand(t, 1)
	s.up.Program(s.addrs[0], dnstest.Behavior{
		// Задержка, чтобы датаграмма доехала по команде теста, а не когда
		// придётся: иначе проверка «ответ отброшен» зеленела бы и в случае,
		// когда он просто не успел прийти.
		Delay: 10 * time.Millisecond,
		Func: func(q []byte) []byte {
			return dnstest.ResponseA(dnstest.QueryID(q)^0xFFFF, name, 300, netip.MustParseAddr("203.0.113.66"))
		},
	})

	ch := s.queryAsync(clientQuery(clientID, name), TransportUDP)
	// Бюджет, таймаут попытки, задержка ответа на стенде.
	s.waitAfter(3)
	s.socks.waitReads(t, 1)
	s.fake.Advance(10 * time.Millisecond)
	// Второй вход в Read означает, что чужую датаграмму разобрали и выбросили:
	// принявший её резолвер сюда бы не вернулся, а отдал бы её клиенту.
	s.socks.waitReads(t, 2)
	s.fake.Advance(AttemptTimeout)

	res := s.await(ch)
	if res.err != nil {
		t.Fatalf("Query: %v", res.err)
	}
	m := parseAnswer(t, res.resp)
	if rc := m.Header.Rcode(); rc != dnsmsg.RcodeServFail {
		t.Fatalf("rcode = %d, хотим SERVFAIL: ответ с чужим идентификатором принят", rc)
	}
	if st := s.r.Snapshot(); st.Entries != 0 {
		t.Fatalf("в кэше %d записей — чужой ответ осел", st.Entries)
	}

	qs := s.up.Queries()
	if len(qs) != 1 {
		t.Fatalf("наверх ушло %d запросов, хотим 1", len(qs))
	}
	if got := dnstest.QueryID(qs[0].Payload); got == clientID {
		t.Fatalf("наверх ушёл клиентский идентификатор %#x", got)
	}
}
