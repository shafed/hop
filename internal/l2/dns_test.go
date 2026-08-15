package l2

import (
	"net/netip"
	"sync"
	"testing"
	"time" //hop:realtime

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dnstest"
	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/faultinject"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/packettest"
	"github.com/shafed/hop/internal/resolver"
)

// Стенд §5.7 на настоящих узлах: у каждого узла свой DNS-сервер за выходом,
// резолвер ходит через активный узел, и никакого мока между ними нет.
//
// Клиент спрашивает один и тот же публичный адрес (upstream ниже); на какой
// сервер он попадёт, решает узел — правило «порт 53 в выход dns» внутри
// инбаунда. Это и есть «через A» и «через B» из T14: разные резолверы за
// выходами в разных странах.
const (
	dnsName  = "example.test"
	addrViaA = "203.0.113.1"
	addrViaB = "198.51.100.2"
)

// upstream — адрес, который резолвер называет апстримом. Куда попадёт запрос,
// решает узел, а не этот адрес.
var upstream = netip.MustParseAddrPort("1.1.1.1:53")

type dnsHarness struct {
	*harness
	srv map[string]*dnstest.Server
	res *resolver.Resolver
}

func newDNSHarness(t *testing.T) *dnsHarness {
	t.Helper()

	srv := map[string]*dnstest.Server{}
	redirect := map[string]string{}
	answers := map[string]string{"A": addrViaA, "B": addrViaB}
	for _, id := range []string{"A", "B"} {
		s, err := dnstest.New()
		if err != nil {
			t.Fatalf("DNS-сервер узла %s: %v", id, err)
		}
		t.Cleanup(s.Close)
		s.Set(dnsName, time.Hour, netip.MustParseAddr(answers[id]))
		srv[id] = s
		redirect[id] = s.Addr().String()
	}

	h := newHarness(t, options{nodes: []string{"A", "B"}, redirect: redirect})
	active := func() string { return h.mgr.Snapshot().Active }
	res := resolver.New(resolver.Config{
		Transport:  resolver.NewNodeTransport(engine.NewOutbound(h.eng, active)),
		Servers:    []netip.AddrPort{upstream},
		Clock:      clock.System{},
		Healthy:    h.mgr.Healthy,
		ActiveNode: active,
	})
	return &dnsHarness{harness: h, srv: srv, res: res}
}

// resolve задаёт вопрос так, как его задал бы netstack, и разбирает ответ.
func (h *dnsHarness) resolve(t *testing.T, name string) *dnsmessage.Message {
	t.Helper()
	answer, err := h.res.Query(dnsQuery(t, name, 0x2b2b),
		netip.MustParseAddrPort("10.255.0.2:5300"), netip.MustParseAddrPort("10.255.0.1:53"))
	if err != nil {
		t.Fatalf("резолв %s: %v", name, err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(answer); err != nil {
		t.Fatalf("ответ не разобрался: %v", err)
	}
	return &m
}

func dnsQuery(t *testing.T, name string, id uint16) []byte {
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

func firstAddr(t *testing.T, m *dnsmessage.Message) netip.Addr {
	t.Helper()
	for _, a := range m.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			return netip.AddrFrom4(r.A)
		}
	}
	t.Fatalf("в ответе нет ни одной A-записи: rcode %v", m.Header.RCode)
	return netip.Addr{}
}

func addrVia(node string) netip.Addr {
	if node == "A" {
		return netip.MustParseAddr(addrViaA)
	}
	return netip.MustParseAddr(addrViaB)
}

// TestT14CacheDoesNotSurviveSwitchOnRealNodes — T14 §8.2 на настоящем железе
// стенда и второй охраняющий тест политики dns_cache_flush_on_switch.
//
// Отличие от L1-варианта в internal/resolver: переключение здесь не
// подставляется тестом, а происходит само — узел ломается инжектором, health
// это видит и выбирает другой. Запись кэша при этом живее живых: TTL час,
// время настоящее, и единственное, что делает ответ несвежим, — смена узла.
func TestT14CacheDoesNotSurviveSwitchOnRealNodes(t *testing.T) {
	h := newDNSHarness(t)

	active := h.waitAnyActive(5 * time.Second)
	if got := firstAddr(t, h.resolve(t, dnsName)); got != addrVia(active) {
		t.Fatalf("через %s пришло %v", active, got)
	}

	spare := h.other(active)
	h.node[active].inj.SetMode(faultinject.ModeBlackhole)
	h.waitActive(spare, 15*time.Second)

	if got := firstAddr(t, h.resolve(t, dnsName)); got != addrVia(spare) {
		t.Fatalf("после переключения на %s пришло %v — кэш пережил смену узла", spare, got)
	}
	if n := h.srv[spare].QueriesFor(dnsName); n == 0 {
		t.Fatalf("узел %s не получил ни одного запроса", spare)
	}
}

// TestT16DNSToLocalRouterIsHijackedThroughNode — T16 §8.2, перегнанный против
// настоящего резолвера, как того требует план этапа 6.
//
// Клиент спрашивает локальный роутер — самый частый случай, потому что
// системный DNS обычно и есть роутер. Запрос обязан уйти в наш резолвер и
// дальше через узел, а не в локальную сеть; ответ обязан прийти с адреса
// роутера, иначе резолвер клиента его не примет.
//
// От netstack-овского T16 отличается тем, что за вердиктом стоит не заглушка:
// ответ приходит с настоящего DNS-сервера, добытый через настоящий VLESS-узел.
func TestT16DNSToLocalRouterIsHijackedThroughNode(t *testing.T) {
	h := newDNSHarness(t)
	active := h.waitAnyActive(5 * time.Second)

	dev := packettest.NewFake(1500)
	byp := &countingSink{}
	st, err := netstack.New(netstack.Config{
		Device:   dev,
		Resolver: h.res,
		Bypass:   byp,
		Clock:    clock.System{},
		Healthy:  h.mgr.Healthy,
	})
	if err != nil {
		t.Fatalf("стек: %v", err)
	}
	t.Cleanup(st.Close)
	go st.Run()

	client := netip.MustParseAddrPort("10.255.0.2:5300")
	router := netip.MustParseAddrPort("192.168.1.1:53")
	dev.Inject(packettest.UDP(client, router, dnsQuery(t, dnsName, 0x7a7a)))

	got := dev.WaitEmitted(t, 1)
	if n := byp.count(); n != 0 {
		t.Fatalf("DNS-запрос ушёл в локальную сеть: %d пакетов", n)
	}

	src, dst, payload := udpOf(t, got[0])
	if src != router || dst != client {
		t.Fatalf("ответ пришёл %v → %v, ожидалось %v → %v", src, dst, router, client)
	}
	var m dnsmessage.Message
	if err := m.Unpack(payload); err != nil {
		t.Fatalf("ответ не разобрался: %v", err)
	}
	if m.Header.ID != 0x7a7a {
		t.Fatalf("id ответа %#x, ожидался %#x", m.Header.ID, 0x7a7a)
	}
	if a := firstAddr(t, &m); a != addrVia(active) {
		t.Fatalf("резолв дал %v, а через узел %s положено %v", a, active, addrVia(active))
	}
	if n := h.srv[active].QueriesFor(dnsName); n != 1 {
		t.Fatalf("сервер за узлом %s получил %d запросов, ожидался один", active, n)
	}
}

// TestFailCloseStopsResolvingOnRealNodes — §5.7б на настоящих узлах: когда
// живых узлов не осталось, резолв прекращается. Без этого приложение получает
// адрес и упирается в отказ уже на connect — то есть узнаёт об отсутствии сети
// на секунду позже и куда невнятнее.
func TestFailCloseStopsResolvingOnRealNodes(t *testing.T) {
	h := newDNSHarness(t)
	active := h.waitAnyActive(5 * time.Second)
	h.resolve(t, dnsName)

	for id := range h.node {
		h.node[id].inj.SetMode(faultinject.ModeBlackhole)
	}
	h.waitFor("живые узлы не кончились", 20*time.Second, func() bool { return !h.mgr.Healthy() })

	m := h.resolve(t, dnsName)
	if m.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode %v, ожидался SERVFAIL (активен был %s)", m.Header.RCode, active)
	}
}

// countingSink — «локальная сеть» для netstack: сюда попадает всё, что ушло
// мимо туннеля.
type countingSink struct {
	mu sync.Mutex
	n  int
}

func (c *countingSink) Send(pkt []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return nil
}

func (c *countingSink) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// udpOf разбирает эмитированный пакет обратно в адреса и полезную нагрузку.
func udpOf(t *testing.T, pkt []byte) (src, dst netip.AddrPort, payload []byte) {
	t.Helper()
	ip := header.IPv4(pkt)
	if len(pkt) < header.IPv4MinimumSize || !ip.IsValid(len(pkt)) {
		t.Fatalf("эмитирован не IPv4-пакет: %d байт", len(pkt))
	}
	if ip.Protocol() != uint8(header.UDPProtocolNumber) {
		t.Fatalf("эмитирован протокол %d, ожидался UDP", ip.Protocol())
	}
	u := header.UDP(ip.Payload())
	s, _ := netip.AddrFromSlice(ip.SourceAddressSlice())
	d, _ := netip.AddrFromSlice(ip.DestinationAddressSlice())
	return netip.AddrPortFrom(s, u.SourcePort()), netip.AddrPortFrom(d, u.DestinationPort()), u.Payload()
}
