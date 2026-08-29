package netstack

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/fakenet"
	"github.com/shafed/hop/internal/packettest"
)

// Адреса стенда. Клиент — за туннелем, «интернет» — документационная сеть
// RFC 5737, локальный роутер — RFC 1918.
var (
	client   = netip.MustParseAddrPort("10.255.0.2:5000")
	web      = netip.MustParseAddrPort("203.0.113.7:80")
	udpPeerA = netip.MustParseAddrPort("203.0.113.1:9999")
	udpPeerB = netip.MustParseAddrPort("203.0.113.2:9999")
	udpPeerC = netip.MustParseAddrPort("203.0.113.3:9999")
	udpPeerD = netip.MustParseAddrPort("203.0.113.4:9999")
	router53 = netip.MustParseAddrPort("192.168.1.1:53")
	mdns     = netip.MustParseAddrPort("224.0.0.251:5353")
)

type harness struct {
	dev    *packettest.FakeDevice
	st     *Stack
	dialer *fakenet.Dialer
	res    *fakenet.Resolver
	byp    *fakenet.Bypass
	alive  *atomic.Bool
}

// newHarness поднимает стек поверх поддельного PacketDevice (§8.1): без TUN,
// без прав, на всех трёх ОС.
//
// opts правят Config до сборки стека — ими пользуется T32, которому нужны
// списки §6.10 из конфигурации, а не умолчания.
func newHarness(t *testing.T, healthy bool, opts ...func(*Config)) *harness {
	t.Helper()
	h := &harness{
		dev:    packettest.NewFake(1500),
		dialer: fakenet.NewDialer(false),
		res:    &fakenet.Resolver{},
		byp:    fakenet.NewBypass(),
		alive:  new(atomic.Bool),
	}
	h.alive.Store(healthy)

	cfg := Config{
		Device:   h.dev,
		Dialer:   h.dialer,
		Resolver: h.res,
		Bypass:   h.byp,
		Clock:    clock.NewFake(time.Unix(1, 0)),
		Healthy:  h.alive.Load,
	}
	for _, o := range opts {
		o(&cfg)
	}

	st, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.st = st

	done := make(chan error, 1)
	go func() { done <- st.Run() }()
	t.Cleanup(func() {
		h.dev.Close()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
		st.Close()
	})
	return h
}

// T12. Все узлы мертвы, TCP-запрос наружу: клиент получил RST, не таймаут, и
// соединений к «интернету» не было ни одного.
//
// Охраняет reject_mode. При reject_mode=drop ответа нет вовсе, и тест ждёт
// полный таймаут WaitEmitted — ровно то поведение, из-за которого §5.6
// запрещает молчаливое закрытие.
func TestT12FailCloseAnswersRST(t *testing.T) {
	h := newHarness(t, false)

	h.dev.Inject(packettest.TCPSyn(client, web, 42))
	got := h.dev.WaitEmitted(t, 1)

	tcp, ok := tcpOf(got[0])
	if !ok {
		t.Fatalf("ответ не TCP: % x", got[0])
	}
	if tcp.Flags()&header.TCPFlagRst == 0 {
		t.Fatalf("ожидался RST, флаги %#x", tcp.Flags())
	}
	if src, dst := endpoints(got[0]); src != web || dst != client {
		t.Fatalf("RST адресован %v → %v, ожидалось %v → %v", src, dst, web, client)
	}
	if dialed := h.dialer.TCPDialed(); len(dialed) != 0 {
		t.Fatalf("fail-close выпустил соединения наружу: %v", dialed)
	}
}

// T13. То же для UDP: ICMP port unreachable, а не молчание.
func TestT13FailCloseAnswersICMP(t *testing.T) {
	h := newHarness(t, false)

	h.dev.Inject(packettest.UDP(client, udpPeerA, []byte("hello")))
	got := h.dev.WaitEmitted(t, 1)

	typ, code, ok := icmpOf(got[0])
	if !ok || typ != header.ICMPv4DstUnreachable {
		t.Fatalf("ответ не ICMP unreachable: % x", got[0])
	}
	if code != byte(header.ICMPv4PortUnreachable) {
		t.Fatalf("код ICMP %d, ожидался %d", code, header.ICMPv4PortUnreachable)
	}
	if h.dialer.Conn(client) != nil {
		t.Fatal("fail-close завёл исходящий UDP-сокет")
	}
}

// T15. UDP от одного исходного порта на три разных адреса: одна NAT-запись,
// ответы дошли со всех трёх.
//
// Плюс то, что full-cone, собственно, и означает: ответ приходит и с адреса, на
// который клиент не слал. §8.3 обещает, что при NAT по паре src+dst «ответы
// потеряются», но три ответа от трёх контактированных адресов дойдут при любом
// ключе — теряется именно четвёртый. Обе половины краснеют при nat_key=src+dst:
// записей становится три, а ответ от D не находит записи.
func TestT15FullConeKeepsOneEntry(t *testing.T) {
	h := newHarness(t, true)

	for _, peer := range []netip.AddrPort{udpPeerA, udpPeerB, udpPeerC} {
		h.dev.Inject(packettest.UDP(client, peer, []byte("q")))
	}
	conn := h.dialer.WaitConn(client)
	conn.WaitSent(3)

	if n := h.st.Stats().NATEntries; n != 1 {
		t.Fatalf("NAT-записей %d, ожидалась одна на исходный порт", n)
	}
	if n := h.st.Stats().NATSockets; n != 1 {
		t.Fatalf("исходящих сокетов %d, core.DialUDP даёт один на исходный порт", n)
	}

	for _, peer := range []netip.AddrPort{udpPeerA, udpPeerB, udpPeerC, udpPeerD} {
		conn.Reply(peer, []byte("a"))
	}
	got := h.dev.WaitEmitted(t, 4)

	seen := map[netip.AddrPort]bool{}
	for _, p := range got {
		src, dst := endpoints(p)
		if dst != client {
			t.Fatalf("ответ адресован %v, ожидался клиент %v", dst, client)
		}
		seen[src] = true
	}
	for _, peer := range []netip.AddrPort{udpPeerA, udpPeerB, udpPeerC, udpPeerD} {
		if !seen[peer] {
			t.Fatalf("ответ от %v до клиента не дошёл", peer)
		}
	}
}

// T16. DNS-запрос на 192.168.1.1:53 ушёл в наш резолвер, а не в локальную сеть.
//
// Охраняет verdict_order. Адрес приватный, то есть подходит под bypass; при
// обратном порядке (verdict_order=bypass_first) запрос уходит провайдеру мимо
// резолвера при формально работающем перехвате.
func TestT16DNSToLocalRouterIsHijacked(t *testing.T) {
	h := newHarness(t, true)
	h.res.Answer = []byte("answer")

	h.dev.Inject(packettest.UDP(client, router53, []byte("query")))
	got := h.dev.WaitEmitted(t, 1)

	if pkts := h.byp.Packets(); len(pkts) != 0 {
		t.Fatalf("DNS-запрос ушёл в локальную сеть: %d пакетов", len(pkts))
	}
	asks := h.res.Asks()
	if len(asks) != 1 {
		t.Fatalf("резолвер увидел %d запросов, ожидался один", len(asks))
	}
	if asks[0].Server != router53 || asks[0].Client != client {
		t.Fatalf("резолвер увидел %v → %v", asks[0].Client, asks[0].Server)
	}
	if src, dst := endpoints(got[0]); src != router53 || dst != client {
		t.Fatalf("ответ пришёл %v → %v, ожидалось %v → %v", src, dst, router53, client)
	}
}

// T17. mDNS-запрос на 224.0.0.251:5353 ушёл в локальную сеть: не заблокирован и
// не в туннель. Без этого правила ломаются Bonjour, AirPlay, AirPrint и поиск
// принтеров.
func TestT17MDNSGoesToLocalNetwork(t *testing.T) {
	h := newHarness(t, true)

	h.dev.Inject(packettest.UDP(client, mdns, []byte("_services")))
	pkts := h.byp.WaitPackets(1)

	if src, dst := endpoints(pkts[0]); src != client || dst != mdns {
		t.Fatalf("в локальную сеть ушло %v → %v", src, dst)
	}
	if st := h.st.Stats(); st.Blocked != 0 || st.Rejected != 0 {
		t.Fatalf("mDNS заблокирован или отвергнут: %+v", st)
	}
	if h.dialer.Conn(client) != nil {
		t.Fatal("mDNS ушёл в туннель")
	}
}

// Отказ приёмника bypass (нет физического интерфейса, политика выключена и
// т.п.) — это дроп, наблюдаемый через Stats.Blocked, а не тишина: до этого
// теста ошибка Send терялась на месте (netstack.go, handle/case Bypass).
//
// Синхронизация без часов — тот же приём, что у TestIPv6IsBlocked: насос
// один, второй пакет (unhealthy → reject_mode отвечает RST/ICMP синхронно)
// подтверждает, что первый уже обработан.
func TestBypassSendErrorCountsAsBlocked(t *testing.T) {
	h := newHarness(t, false)
	h.byp.SetErr(errors.New("нет физического интерфейса"))

	h.dev.Inject(packettest.UDP(client, mdns, []byte("_services")))
	h.dev.Inject(packettest.UDP(client, udpPeerA, []byte("после")))
	h.dev.WaitEmitted(t, 1)

	if st := h.st.Stats(); st.Blocked != 1 {
		t.Fatalf("заблокировано %d пакетов, ожидался один отказ bypass: %+v", st.Blocked, st)
	}
	if pkts := h.byp.Packets(); len(pkts) != 0 {
		t.Fatalf("пакет ушёл в локальную сеть, хотя Send отказал: %d пакетов", len(pkts))
	}
}

// Вердикт принимается на первом пакете и дальше не пересматривается (§3.4).
// Смерть последнего узла посреди установленного потока не превращает его
// следующий пакет в RST: fail-close отвергает новые потоки, а не чужие.
func TestVerdictIsTakenOnceOnTheFirstPacket(t *testing.T) {
	h := newHarness(t, true)

	h.dev.Inject(packettest.UDP(client, udpPeerA, []byte("first")))
	conn := h.dialer.WaitConn(client)
	conn.WaitSent(1)

	h.alive.Store(false)
	h.dev.Inject(packettest.UDP(client, udpPeerA, []byte("second")))
	conn.WaitSent(2)

	if st := h.st.Stats(); st.Rejected != 0 {
		t.Fatalf("установленный поток отвергнут после смерти узлов: %+v", st)
	}

	// А новый поток — отвергается.
	h.dev.Inject(packettest.UDP(client, udpPeerB, []byte("new")))
	h.dev.WaitEmitted(t, 1)
}

// IPv6, дошедший до устройства, дальше стека не идёт: второй рубеж §6.9.
// Первый — правило маршрутизации `ipv6_block` (internal/platform, T28), и он
// же несущий: утечка идёт мимо туннеля, где стека нет. Здесь проверяется
// ровно то, что стек не выпустит IPv6 в bypass, если тот всё-таки прилетел.
//
// Синхронизация без часов: насос один, пакеты разбираются по порядку, поэтому
// ответ на второй пакет означает, что первый уже обработан.
func TestIPv6IsBlocked(t *testing.T) {
	h := newHarness(t, false)

	v6 := make([]byte, header.IPv6MinimumSize)
	v6[0] = 6 << 4
	h.dev.Inject(v6)
	h.dev.Inject(packettest.UDP(client, udpPeerA, []byte("после")))
	h.dev.WaitEmitted(t, 1)

	if st := h.st.Stats(); st.Blocked != 1 {
		t.Fatalf("заблокировано %d пакетов, ожидался один IPv6: %+v", st.Blocked, st)
	}
	if pkts := h.byp.Packets(); len(pkts) != 0 {
		t.Fatalf("IPv6 ушёл мимо туннеля: %d пакетов", len(pkts))
	}
}

func tcpOf(p []byte) (header.TCP, bool) {
	ip := header.IPv4(p)
	if len(p) < header.IPv4MinimumSize || ip.Protocol() != uint8(header.TCPProtocolNumber) {
		return nil, false
	}
	payload := ip.Payload()
	if len(payload) < header.TCPMinimumSize {
		return nil, false
	}
	return header.TCP(payload), true
}

func icmpOf(p []byte) (header.ICMPv4Type, byte, bool) {
	ip := header.IPv4(p)
	if len(p) < header.IPv4MinimumSize || ip.Protocol() != uint8(header.ICMPv4ProtocolNumber) {
		return 0, 0, false
	}
	payload := ip.Payload()
	if len(payload) < header.ICMPv4MinimumSize {
		return 0, 0, false
	}
	icmp := header.ICMPv4(payload)
	return icmp.Type(), byte(icmp.Code()), true
}

// endpoints — src и dst пакета вместе с портами.
func endpoints(p []byte) (src, dst netip.AddrPort) {
	f, ok := parse(p)
	if !ok {
		return netip.AddrPort{}, netip.AddrPort{}
	}
	return f.src, f.dst
}
