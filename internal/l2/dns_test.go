// Проверки шага 10 регистра резолвера (docs/verification-dns.md §7): T14 и
// T16 против настоящего резолвера, усечённый ответ через настоящий узел.
package l2

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time" //hop:realtime — стенд L2 работает в настоящем времени

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dnsmsg"
	"github.com/shafed/hop/internal/dnstest"
	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/fakenet"
	"github.com/shafed/hop/internal/faultinject"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/packettest"
	"github.com/shafed/hop/internal/phase"
	"github.com/shafed/hop/internal/resolver"
)

// resolverDialer — путь наверх резолвера через активный узел: тот же провод,
// что agent.dialer.resolverDialUDP/resolverDialTCP (internal/agent/dialer.go),
// только поверх h.eng/h.mgr стенда, а не связки.
type resolverDialer struct {
	mgr *health.Manager
	eng *engine.Engine
}

func (d *resolverDialer) dialUDP(ctx context.Context, _ netip.AddrPort) (net.PacketConn, error) {
	node := d.mgr.Snapshot().Active
	if node == "" {
		return nil, errors.New("l2: живого узла нет")
	}
	return d.eng.DialUDP(ctx, node)
}

func (d *resolverDialer) dialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	node := d.mgr.Snapshot().Active
	if node == "" {
		return nil, errors.New("l2: живого узла нет")
	}
	return d.eng.DialTCP(ctx, node, dst.String())
}

// dnsHarness — harness плюс настоящий резолвер §5.7 поверх тех же узлов и
// живости: L2-проверки шага 10 регистра (docs/verification-dns.md §7).
type dnsHarness struct {
	*harness
	up *dnstest.RealServer
	r  *resolver.Resolver

	evCh  chan health.SwitchEvent
	ackCh chan struct{}
	stop  chan struct{}
}

func newDNSHarness(t *testing.T, opt options) *dnsHarness {
	t.Helper()
	h := newHarness(t, opt)

	up, err := dnstest.NewRealServer()
	if err != nil {
		t.Fatalf("апстрим: %v", err)
	}
	t.Cleanup(func() { up.Close() })

	rd := &resolverDialer{mgr: h.mgr, eng: h.eng}
	d := &dnsHarness{
		harness: h,
		up:      up,
		evCh:    make(chan health.SwitchEvent),
		ackCh:   make(chan struct{}, 1),
		stop:    make(chan struct{}),
	}

	r, err := resolver.New(resolver.Config{
		Upstreams: []netip.AddrPort{up.Addr()},
		DialUDP:   rd.dialUDP,
		Dial:      rd.dialTCP,
		Phase:     func() phase.Traffic { return phase.Proxied },
		Events:    d.evCh,
		Acked:     func() { d.ackCh <- struct{}{} },
		Clock:     clock.System{},
	})
	if err != nil {
		t.Fatalf("резолвер: %v", err)
	}
	d.r = r
	t.Cleanup(func() { close(d.stop); r.Close() })

	go d.forward()
	return d
}

// forward прокидывает резолверу переключения, которые harness уже вычитала
// из h.mgr.Events(): у health.Manager.Events() один читатель на канал, и
// harness.collectEvents его уже заняла (harness_test.go). Вместо второй
// подписки на тот же канал — опрос уже накопленной истории harness.events().
func (d *dnsHarness) forward() {
	seen := 0
	tick := time.NewTicker(5 * time.Millisecond) //hop:realtime
	defer tick.Stop()
	for {
		select {
		case <-d.stop:
			return
		case <-tick.C:
			all := d.harness.events()
			for _, ev := range all[seen:] {
				select {
				case d.evCh <- ev:
				case <-d.stop:
					return
				}
				select {
				case <-d.ackCh:
				case <-d.stop:
					return
				}
			}
			seen = len(all)
		}
	}
}

// resolve спрашивает резолвер по UDP и возвращает первый адрес A-записи.
func (d *dnsHarness) resolve(t *testing.T, name string) netip.Addr {
	t.Helper()
	type result struct {
		resp []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := d.r.Query(clientQuery(name), netip.AddrPort{}, netip.AddrPort{})
		ch <- result{resp, err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("резолв %s: %v", name, res.err)
		}
		return firstA(t, parseAnswer(t, res.resp))
	case <-time.After(budget): //hop:realtime сторож
		t.Fatalf("резолв %s не ответил за %v", name, budget)
		return netip.Addr{}
	}
}

// waitCacheFlushed ждёт, пока Generation резолвера не вырастет относительно
// before: признак того, что d.forward уже доставила событие переключения и
// резолвер его обработал (§5.7в).
func (d *dnsHarness) waitCacheFlushed(t *testing.T, before uint64) {
	t.Helper()
	deadline := time.After(budget)               //hop:realtime
	tick := time.NewTicker(5 * time.Millisecond) //hop:realtime
	defer tick.Stop()
	for {
		if d.r.Snapshot().Generation > before {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("кэш не сброшен за %v после переключения", budget)
		case <-tick.C:
		}
	}
}

func clientQuery(name string) []byte {
	return dnstest.BuildQuery(dnstest.QueryOpts{ID: 0x7E15, Name: name, Type: dnstest.TypeA})
}

func parseAnswer(t *testing.T, raw []byte) dnsmsg.Msg {
	t.Helper()
	m, err := dnsmsg.Parse(raw)
	if err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	return m
}

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

func answerA(name string, ttl uint32, ip netip.Addr) dnstest.Behavior {
	return dnstest.Behavior{Func: func(q []byte) []byte {
		return dnstest.ResponseA(dnstest.QueryID(q), name, ttl, ip)
	}}
}

// truncatedThenFull — апстрим, отвечающий по UDP усечённо, а по TCP полно.
// Локальный двойник одноимённого хелпера в
// internal/resolver/upstream_test.go — тот же приём (порядок вызовов
// отличает UDP от TCP, поскольку dnstest.Behavior транспорт не несёт),
// импортировать между пакетами нельзя.
func truncatedThenFull(name string, ips []netip.Addr) dnstest.Behavior {
	var calls atomic.Int32
	short := func(id uint16) []byte { return dnstest.ResponseA(id, name, 300, ips[0]) }
	full := func(id uint16) []byte {
		var rrs []dnstest.RR
		for _, ip := range ips {
			rrs = append(rrs, dnstest.RR{Name: name, Type: dnstest.TypeA, TTL: 300, Data: ip.AsSlice()})
		}
		return dnstest.BuildResponse(dnstest.ResponseOpts{
			ID: id, QName: name, QType: dnstest.TypeA,
			Flags:  dnstest.Flags{RD: true, RA: true},
			Answer: rrs,
		})
	}
	return dnstest.Behavior{Func: func(q []byte) []byte {
		id := dnstest.QueryID(q)
		if calls.Add(1) == 1 {
			return dnstest.WithTC(short(id))
		}
		return full(id)
	}}
}

// udpEndpoints разбирает IPv4/UDP пакет ровно настолько, чтобы проверить,
// откуда и куда он идёт, и достать полезную нагрузку. У internal/netstack
// есть эквивалентный неэкспортированный parse() — отсюда его не позвать, а
// тащить весь netstack ради разбора одного пакета в тесте не за чем.
func udpEndpoints(p []byte) (src, dst netip.AddrPort, payload []byte, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	ihl := int(p[0]&0x0F) * 4
	if len(p) < ihl+8 || p[9] != 17 { // 17 = UDP
		return
	}
	var srcB, dstB [4]byte
	copy(srcB[:], p[12:16])
	copy(dstB[:], p[16:20])
	udp := p[ihl:]
	srcPort := uint16(udp[0])<<8 | uint16(udp[1])
	dstPort := uint16(udp[2])<<8 | uint16(udp[3])
	ulen := int(udp[4])<<8 | int(udp[5])
	if ulen < 8 || ihl+ulen > len(p) {
		return
	}
	return netip.AddrPortFrom(netip.AddrFrom4(srcB), srcPort),
		netip.AddrPortFrom(netip.AddrFrom4(dstB), dstPort),
		p[ihl+8 : ihl+ulen], true
}

// TestT14SwitchResolvesToNewIP — T14 (L2, docs/verification-dns.md §5.3):
// домен резолвится в IP1, пока активен один узел, и в IP2 — после
// переключения на другой. Отличается от TestD19SwitchBumpsGeneration
// (internal/resolver) тем, что смотрит на результат резолва, а не на
// Generation, и идёт через настоящий узел, а не поддельный апстрим.
func TestT14SwitchResolvesToNewIP(t *testing.T) {
	d := newDNSHarness(t, options{})
	active := d.waitAnyActive(budget)
	spare := d.other(active)

	const name = "switch.example"
	ip1 := netip.MustParseAddr("203.0.113.11")
	ip2 := netip.MustParseAddr("203.0.113.22")

	d.up.Program(answerA(name, 300, ip1))

	beforeActive := d.node[active].inj.Conns()
	if got := d.resolve(t, name); got != ip1 {
		t.Fatalf("резолв через %s дал %s, хотели %s", active, got, ip1)
	}
	if after := d.node[active].inj.Conns(); after <= beforeActive {
		t.Errorf("запрос наверх не прошёл через активный узел %s: %d → %d", active, beforeActive, after)
	}

	genBefore := d.r.Snapshot().Generation
	d.up.Program(answerA(name, 300, ip2))
	d.node[active].inj.SetMode(faultinject.ModeBlackhole)
	d.waitActive(spare, budget)
	d.waitCacheFlushed(t, genBefore)

	beforeSpare := d.node[spare].inj.Conns()
	if got := d.resolve(t, name); got != ip2 {
		t.Fatalf("после переключения резолв дал %s, хотели %s (кэш не сброшен?)", got, ip2)
	}
	if after := d.node[spare].inj.Conns(); after <= beforeSpare {
		t.Errorf("запрос наверх не прошёл через новый активный узел %s: %d → %d", spare, beforeSpare, after)
	}
}

// TestD33TruncatedAnswerRetriesOverTCPRealNode — D33 (L2,
// docs/verification-dns.md §5.4): апстрим за настоящим узлом отвечает по UDP
// усечённо и по TCP полно, резолвер обязан повторить по TCP и вернуть полный
// RRset. Отличие от TestD33TruncatedAnswerRetriesOverTCP (internal/resolver)
// — путь наверх настоящий: движок, VLESS, freedom outbound, а не сокет в
// памяти процесса.
func TestD33TruncatedAnswerRetriesOverTCPRealNode(t *testing.T) {
	d := newDNSHarness(t, options{})
	active := d.waitAnyActive(budget)

	const name = "big.example"
	ips := []netip.Addr{
		netip.MustParseAddr("203.0.113.1"),
		netip.MustParseAddr("203.0.113.2"),
		netip.MustParseAddr("203.0.113.3"),
	}
	d.up.Program(truncatedThenFull(name, ips))

	before := d.node[active].inj.Conns()

	type result struct {
		resp []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := d.r.Query(clientQuery(name), netip.AddrPort{}, netip.AddrPort{})
		ch <- result{resp, err}
	}()
	var res result
	select {
	case res = <-ch:
	case <-time.After(budget): //hop:realtime сторож
		t.Fatalf("резолв не ответил за %v", budget)
	}
	if res.err != nil {
		t.Fatalf("резолв %s: %v", name, res.err)
	}

	m := parseAnswer(t, res.resp)
	if m.Header.Truncated() {
		t.Fatal("клиенту ушёл ответ с TC — полный RRset меньше буфера по умолчанию")
	}
	if got := countAnswers(t, m); got != len(ips) {
		t.Fatalf("записей в ANSWER %d, хотим полный RRset из %d", got, len(ips))
	}
	if st := d.r.Snapshot(); st.TCPRetry != 1 {
		t.Fatalf("TCPRetry = %d, хотим 1", st.TCPRetry)
	}
	if after := d.node[active].inj.Conns(); after <= before {
		t.Errorf("повтор по TCP не прошёл через настоящий узел %s: %d → %d", active, before, after)
	}
}

// TestT16DNSToLocalRouterIsHijackedRealResolver — T16 (L2,
// docs/verification-dns.md §5.1): DNS-запрос на локальный роутер обслужен
// настоящим резолвером через настоящий узел. Отличие от
// TestT16DNSToLocalRouterIsHijacked (internal/netstack) — Resolver здесь
// настоящий: тот тест доказывает только то, что запрос доехал до
// Config.Resolver, этот — что за ним стоит рабочий резолв через живой узел.
func TestT16DNSToLocalRouterIsHijackedRealResolver(t *testing.T) {
	d := newDNSHarness(t, options{})
	active := d.waitAnyActive(budget)

	const name = "router.example"
	ip := netip.MustParseAddr("203.0.113.42")
	d.up.Program(answerA(name, 300, ip))

	dev := packettest.NewFake(1500)
	byp := fakenet.NewBypass()
	st, err := netstack.New(netstack.Config{
		Device:   dev,
		Resolver: d.r,
		Bypass:   byp,
		Clock:    clock.System{},
		Healthy:  func() bool { return d.mgr.Snapshot().Active != "" },
	})
	if err != nil {
		t.Fatalf("netstack: %v", err)
	}
	t.Cleanup(st.Close)
	go st.Run()

	client := netip.MustParseAddrPort("10.255.0.2:5000")
	router53 := netip.MustParseAddrPort("192.168.1.1:53")
	dev.Inject(packettest.UDP(client, router53, clientQuery(name)))

	got := dev.WaitEmitted(t, 1)
	src, dst, payload, ok := udpEndpoints(got[0])
	if !ok {
		t.Fatal("ответ — не IPv4/UDP пакет")
	}
	if src != router53 || dst != client {
		t.Fatalf("ответ пришёл %v → %v, ожидалось %v → %v", src, dst, router53, client)
	}
	if got := firstA(t, parseAnswer(t, payload)); got != ip {
		t.Fatalf("в ответе адрес %s, ожидался %s: резолв через настоящий узел не состоялся", got, ip)
	}

	if pkts := byp.Packets(); len(pkts) != 0 {
		t.Fatalf("DNS-запрос ушёл в локальную сеть: %d пакетов", len(pkts))
	}
	if n := d.node[active].inj.Conns(); n == 0 {
		t.Error("резолв не прошёл через настоящий узел")
	}
}
