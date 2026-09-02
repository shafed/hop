package resolver

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dnsmsg"
	"github.com/shafed/hop/internal/dnstest"
	"github.com/shafed/hop/internal/phase"
)

// parseTest — Parse с фейлом теста вместо ветвления на ошибку в каждом
// сценарии: фикстуры этого файла всегда собирают валидные сообщения, и
// ошибка разбора здесь — дефект теста, а не то, что тест проверяет.
func parseTest(t *testing.T, raw []byte) dnsmsg.Msg {
	t.Helper()
	m, err := dnsmsg.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

// newRewriteTestResolver — резолвер на фейковых часах с поддельным апстримом
// на одном адресе. Фаза всегда proxied: gate (заглушка З7) её пока не
// смотрит, но значение обязано быть таким, при котором настоящий gate тоже
// пропустит запрос — иначе тест начнёт молча проверять чужую заглушку.
//
// clk и fake ходят наружу вместе с резолвером: негативный контроль D45
// (HOP_DISABLE=dns_aaaa_nodata) уводит запрос наверх вместо синтеза, и без
// прокрутки фейковых часов тест висит до -timeout вместо падения по
// утверждению.
func newRewriteTestResolver(t *testing.T) (r *Resolver, up *dnstest.Upstream, addr netip.AddrPort, clk *dnstest.Clock, fake *clock.Fake) {
	t.Helper()
	fake = clock.NewFake(time.Unix(0, 0))
	clk = dnstest.NewClock(fake)
	up = dnstest.New(clk)
	addr = netip.MustParseAddrPort("203.0.113.53:53")

	var err error
	r, err = New(Config{
		Upstreams:  []netip.AddrPort{addr},
		DialUDP:    up.DialUDP,
		Dial:       up.Dial,
		DialDirect: up.DialDirect,
		Phase:      func() phase.Traffic { return phase.Proxied },
		Clock:      clk,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	return r, up, addr, clk, fake
}

// queryRacingAttemptTimeout запускает r.Query асинхронно и доводит фейковые
// часы до таймаута попытки наверх (AttemptTimeout, askUDP), если запрос до
// него дошёл.
//
// Обращений к часам в худшем случае два: бюджет клиента (withBudget, всегда
// первое) и таймаут попытки (askUDP, только когда синтеза не было и апстрим
// не запрограммирован). В штатном режиме политика отвечает раньше второго
// обращения — ветка часов тогда не выбирается вовсе, и функция возвращается
// по готовому ответу. Нужна ровно для D45: под HOP_DISABLE=dns_aaaa_nodata
// синтеза нет, запрос уходит наверх, апстрим молчит, и без прокрутки этих
// часов горутина резолвера висит до -timeout, а не падает по утверждению.
func queryRacingAttemptTimeout(t *testing.T, r *Resolver, query []byte, clk *dnstest.Clock, fake *clock.Fake) queryResult {
	t.Helper()

	ch := make(chan queryResult, 1)
	go func() {
		resp, err := r.Query(query, netip.AddrPort{}, netip.AddrPort{})
		ch <- queryResult{resp: resp, err: err}
	}()

	afterTwo := make(chan struct{})
	go func() {
		clk.WaitAfterCalls(2)
		close(afterTwo)
	}()

	select {
	case res := <-ch:
		return res
	case <-afterTwo:
		fake.Advance(AttemptTimeout)
	case <-time.After(testWatchdog): //hop:realtime сторож
		t.Fatal("резолвер не ответил и не встал в ожидание за сторожевой срок")
	}

	select {
	case res := <-ch:
		return res
	case <-time.After(testWatchdog): //hop:realtime сторож
		t.Fatal("резолвер не ответил за сторожевой срок после таймаута попытки")
	}
	return queryResult{}
}

// D45. Запрос типа AAAA — NOERROR с пустым ANSWER, наверх не ушло ничего
// (Р19, флаг dns_aaaa_nodata).
func TestD45AAAAIsSynthesizedNodata(t *testing.T) {
	r, up, _, clk, fake := newRewriteTestResolver(t)

	query := dnstest.BuildQuery(dnstest.QueryOpts{ID: 0xBEEF, Name: "example.com", Type: dnstest.TypeAAAA})
	res := queryRacingAttemptTimeout(t, r, query, clk, fake)
	if res.err != nil {
		t.Fatalf("Query: %v", res.err)
	}

	got := parseTest(t, res.resp)
	if !got.Header.Response() {
		t.Fatal("QR не поднят")
	}
	if rc := got.Header.Rcode(); rc != dnsmsg.RcodeNoError {
		t.Fatalf("rcode = %d, хотим NOERROR", rc)
	}
	if got.Header.ANCount != 0 || got.Header.NSCount != 0 || got.Header.ARCount != 0 {
		t.Fatalf("секции не пусты: AN=%d NS=%d AR=%d", got.Header.ANCount, got.Header.NSCount, got.Header.ARCount)
	}
	if got.Header.ID != 0xBEEF {
		t.Fatalf("ID = %#x, хотим клиентский 0xbeef", got.Header.ID)
	}

	req := parseTest(t, query)
	if !bytes.Equal(got.QuestionBytes(), req.QuestionBytes()) {
		t.Fatalf("секция вопроса изменилась: %x != %x", got.QuestionBytes(), req.QuestionBytes())
	}

	if calls := up.Calls(); calls != (dnstest.Calls{}) {
		t.Fatalf("апстрим тронут: %+v, хотим ни одного вызова", calls)
	}
}

// D46. AAAA синтезируется, затем A того же имени резолвится нормально — то
// есть ответ на AAAA не был NXDOMAIN, который стаб клиента вправе
// распространить на все типы разом (Р19, флаг dns_aaaa_nodata).
func TestD46AAAANodataKeepsAWorking(t *testing.T) {
	r, up, addr, _, _ := newRewriteTestResolver(t)
	const name = "example.com"

	aaaaQuery := dnstest.BuildQuery(dnstest.QueryOpts{ID: 1, Name: name, Type: dnstest.TypeAAAA})
	if _, err := r.Query(aaaaQuery, netip.AddrPort{}, netip.AddrPort{}); err != nil {
		t.Fatalf("AAAA Query: %v", err)
	}

	ip := netip.MustParseAddr("203.0.113.9")
	up.Program(addr, dnstest.Behavior{
		Func: func(query []byte) []byte {
			return dnstest.ResponseA(dnstest.QueryID(query), name, 300, ip)
		},
	})

	aQuery := dnstest.BuildQuery(dnstest.QueryOpts{ID: 2, Name: name, Type: dnstest.TypeA})
	resp, err := r.Query(aQuery, netip.AddrPort{}, netip.AddrPort{})
	if err != nil {
		t.Fatalf("A Query: %v", err)
	}

	got := parseTest(t, resp)
	if rc := got.Header.Rcode(); rc != dnsmsg.RcodeNoError {
		t.Fatalf("A получил rcode %d вместо NOERROR — AAAA перед ним не должен был это испортить", rc)
	}
	if got.Header.ANCount == 0 {
		t.Fatal("A вернулся без ответа: AAAA испортил резолв того же имени")
	}
}

// D49 (юнит-тест на upstreamQuery). Путь наверх (ask, upstream.go) —
// заглушка задачи З4 и пока ничего не отправляет, поэтому проверка строится
// на самой сборке запроса, а не сквозь Query (согласовано с ведущим задачи).
//
// Запрос клиента с EDNS Client Subnet — наверх уходит без ECS, свой ECS не
// добавлен (Р26).
func TestD49UpstreamQueryStripsECS(t *testing.T) {
	ecs := &dnstest.ECS{Family: 1, SourcePrefix: 24, Address: netip.MustParseAddr("203.0.113.0")}
	q := parseTest(t, dnstest.BuildQuery(dnstest.QueryOpts{
		ID: 7, Name: "example.com", Type: dnstest.TypeA,
		EDNS0: true, ECS: ecs,
	}))

	r := &Resolver{}
	out, err := r.upstreamQuery(q, 42)
	if err != nil {
		t.Fatalf("upstreamQuery: %v", err)
	}

	got := parseTest(t, out)
	if got.Header.ID != 42 {
		t.Fatalf("ID = %d, хотим свой 42", got.Header.ID)
	}
	opt, ok, err := got.EDNS()
	if err != nil {
		t.Fatalf("EDNS: %v", err)
	}
	if !ok {
		t.Fatal("OPT потерялась вовсе")
	}
	if opt.UDPSize != UpstreamEDNS {
		t.Fatalf("буфер = %d, хотим %d", opt.UDPSize, UpstreamEDNS)
	}
	opts, err := got.Options(opt)
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	for _, o := range opts {
		if o.Code == dnsmsg.OptionECS {
			t.Fatal("ECS не вырезан")
		}
	}
}

// D50 (частично, юнит-тест на upstreamQuery). DO-бит клиента обязан дойти до
// апстрима — иначе апстриму неоткуда взять RRSIG. Что RRSIG и DO-бит ответа
// проходят к клиенту насквозь — уже проверяет upstream.go (fit/Reply
// копируют секции байт в байт); здесь только запрос наверх.
func TestD50UpstreamQueryPreservesDOBit(t *testing.T) {
	q := parseTest(t, dnstest.BuildQuery(dnstest.QueryOpts{
		ID: 1, Name: "example.com", Type: dnstest.TypeA, EDNS0: true, DO: true,
	}))

	r := &Resolver{}
	out, err := r.upstreamQuery(q, 99)
	if err != nil {
		t.Fatalf("upstreamQuery: %v", err)
	}

	got := parseTest(t, out)
	opt, ok, err := got.EDNS()
	if err != nil || !ok {
		t.Fatalf("EDNS: ok=%v err=%v", ok, err)
	}
	if !opt.DO {
		t.Fatal("DO-бит потерян в запросе наверх")
	}
	if opt.UDPSize != UpstreamEDNS {
		t.Fatalf("буфер = %d, хотим %d", opt.UDPSize, UpstreamEDNS)
	}
}

// Без EDNS0 в запросе клиента upstreamQuery не собирает OPT сама — только
// подставляет свой идентификатор. Второй кодировщик DNS в обход dnsmsg,
// которому сборка сообщений принадлежит по границе пакета, обошёлся бы
// дороже, чем чуть менее щедрый буфер апстриму без D-пункта, который бы это
// проверял.
func TestUpstreamQueryNoEDNSLeavesMessageAlone(t *testing.T) {
	raw := dnstest.BuildQuery(dnstest.QueryOpts{ID: 5, Name: "example.org", Type: dnstest.TypeA})
	q := parseTest(t, raw)

	r := &Resolver{}
	out, err := r.upstreamQuery(q, 123)
	if err != nil {
		t.Fatalf("upstreamQuery: %v", err)
	}

	want, err := dnsmsg.WithID(raw, 123)
	if err != nil {
		t.Fatalf("WithID: %v", err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("тело запроса изменилось без EDNS0:\nполучили %x\nхотим    %x", out, want)
	}
}

// upstreamQuery не имеет права патчить буфер клиента на месте: тот же срез
// делит кэш склейки запросов в полёте (Р24, Р23), и запись, испорченная
// одним клиентом, ушла бы всем остальным ждущим тот же вопрос.
func TestUpstreamQueryDoesNotMutateClientBuffer(t *testing.T) {
	raw := dnstest.BuildQuery(dnstest.QueryOpts{
		ID: 1, Name: "example.com", Type: dnstest.TypeA, EDNS0: true, BufSize: 512,
	})
	orig := append([]byte(nil), raw...)
	q := parseTest(t, raw)

	r := &Resolver{}
	if _, err := r.upstreamQuery(q, 2); err != nil {
		t.Fatalf("upstreamQuery: %v", err)
	}
	if !bytes.Equal(raw, orig) {
		t.Fatal("upstreamQuery испортила буфер клиента")
	}
}

// D48-смежное: synthesize не трогает никакие типы записей, кроме AAAA — в
// частности HTTPS/SVCB (тип 65), чей ipv6hint должен уехать клиенту как есть
// (Р19). synthesize здесь просто обязан промолчать (вернуть nil) и отдать
// вопрос обычному пути.
func TestSynthesizeIgnoresOtherTypes(t *testing.T) {
	r := &Resolver{}
	for _, qtype := range []uint16{dnsmsg.TypeA, dnsmsg.TypeHTTPS, dnsmsg.TypeSOA, dnsmsg.TypeNS} {
		q := parseTest(t, dnstest.BuildQuery(dnstest.QueryOpts{ID: 1, Name: "example.com", Type: qtype}))
		if got := r.synthesize(q); got != nil {
			t.Fatalf("тип %d: synthesize вернул %x, хотим nil", qtype, got)
		}
	}
}
