package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/fakenet"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/packettest"
)

// Адреса стенда. Клиент — за туннелем, «системный» резолвер — локальный роутер
// (§3.4: перехват :53 стоит выше bypass), адреса ответов — документационные
// сети RFC 5737.
var (
	client       = netip.MustParseAddrPort("10.255.0.2:5000")
	router53     = netip.MustParseAddrPort("192.168.1.1:53")
	upstreamAddr = netip.MustParseAddrPort("1.1.1.1:53")
	bootAddr     = netip.MustParseAddrPort("9.9.9.9:53")

	ipA = netip.MustParseAddr("203.0.113.10") // как домен виден через узел A
	ipB = netip.MustParseAddr("198.51.100.10")

	epoch = time.Unix(1700000000, 0)
)

func alive() bool { return true }
func dead() bool  { return false }

// errNodeDown — отказ исходящего до старта движка (§5.6: fail-open запрещён,
// пока узла нет, Dial обязан вернуть ошибку).
var errNodeDown = errors.New("узел не поднят")

// upstream — поддельный DNS-сервер стенда: отвечает A-записью на любой вопрос.
// Что именно он отдаёт, тест меняет на ходу — так выглядит один и тот же домен,
// увиденный через другой узел (T14).
type upstream struct {
	mu       sync.Mutex
	addr     netip.Addr
	ttl      uint32
	truncate bool // по UDP отвечать усечённо: проверка перехода на TCP
	down     bool // диалер отказывает вовсе
	udp, tcp int
}

func (u *upstream) set(addr netip.Addr) {
	u.mu.Lock()
	u.addr = addr
	u.mu.Unlock()
}

func (u *upstream) calls() (udp, tcp int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.udp, u.tcp
}

func (u *upstream) dialUDP(context.Context, netip.AddrPort) (net.Conn, error) {
	return u.dial(false)
}

func (u *upstream) dialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return u.dial(true)
}

// dial отдаёт соединение с одноразовым сервером на том конце. Счётчик растёт до
// проверки down: тест про bootstrap доказывает, что через туннель не ходили
// вовсе, и молчаливый отказ такую попытку скрыл бы.
func (u *upstream) dial(framed bool) (net.Conn, error) {
	u.mu.Lock()
	if framed {
		u.tcp++
	} else {
		u.udp++
	}
	addr, ttl, trunc, down := u.addr, u.ttl, u.truncate && !framed, u.down
	u.mu.Unlock()

	if down {
		return nil, errNodeDown
	}

	near, far := net.Pipe()
	go func() {
		defer far.Close()
		query, err := readMsg(far, framed)
		if err != nil {
			return
		}
		answer, err := answerFor(query, addr, ttl, trunc)
		if err != nil {
			return
		}
		_ = writeMsg(far, answer, framed)
	}()
	return near, nil
}

// answerFor — ответ апстрима: тот же вопрос плюс одна A-запись. Усечённый ответ
// приходит с флагом TC и без записей — так выглядит набор, не влезший в
// датаграмму.
func answerFor(query []byte, addr netip.Addr, ttl uint32, trunc bool) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		RecursionDesired:   h.RecursionDesired,
		RecursionAvailable: true,
		Truncated:          trunc,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if trunc {
		return b.Finish()
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	rh := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl}
	if err := b.AResource(rh, dnsmessage.AResource{A: addr.As4()}); err != nil {
		return nil, err
	}
	return b.Finish()
}

func readMsg(c net.Conn, framed bool) ([]byte, error) {
	if !framed {
		buf := make([]byte, maxReply)
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(c, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeMsg(c net.Conn, msg []byte, framed bool) error {
	if !framed {
		_, err := c.Write(msg)
		return err
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	_, err := c.Write(out)
	return err
}

func newResolver(t *testing.T, cfg Config) *Resolver {
	t.Helper()
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func question(host string) dnsmessage.Question {
	return dnsmessage.Question{
		Name:  dnsmessage.MustNewName(fqdn(host)),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
}

// resolve прогоняет перехваченный запрос и возвращает первый адрес ответа.
// Идентификатор каждый раз новый, и addrsOf его сверяет: ответ из кэша обязан
// нести идентификатор того, кто спросил сейчас.
func resolve(t *testing.T, r *Resolver, host string) netip.Addr {
	t.Helper()
	query, id, err := buildQuery(question(host))
	if err != nil {
		t.Fatalf("сборка запроса: %v", err)
	}
	answer, err := r.Query(query, client, router53)
	if err != nil {
		t.Fatalf("Query(%s): %v", host, err)
	}
	addrs, err := addrsOf(answer, id)
	if err != nil {
		t.Fatalf("ответ на %s: %v", host, err)
	}
	return addrs[0]
}

// T14. Домен резолвится в один адрес через узел A и в другой через B; после
// переключения следующий резолв обязан дать адрес B.
//
// Охраняет dns_cache_flush_on_switch. При выключенной политике OnNodeSwitch
// ничего не делает, кэш переживает смену узла, и трафик идёт в CDN чужого
// региона (§5.7в).
func TestT14CacheFlushedOnSwitch(t *testing.T) {
	up := &upstream{addr: ipA, ttl: 300}
	r := newResolver(t, Config{
		Upstream: []netip.AddrPort{upstreamAddr},
		Dial:     up.dialTCP,
		DialUDP:  up.dialUDP,
		Healthy:  alive,
		Clock:    clock.NewFake(epoch),
	})

	if got := resolve(t, r, "example.com"); got != ipA {
		t.Fatalf("через узел A получено %v, ожидалось %v", got, ipA)
	}

	up.set(ipB)
	if got := resolve(t, r, "example.com"); got != ipA {
		t.Fatalf("кэш не сработал: получено %v, в кэше лежало %v", got, ipA)
	}

	r.OnNodeSwitch()

	if got := resolve(t, r, "example.com"); got != ipB {
		t.Fatalf("после смены узла получено %v, ожидалось %v: кэш пережил переключение (§5.7в)", got, ipB)
	}
}

// Bootstrap. Имя узла резолвится мимо туннеля (§5.7а).
//
// Охраняет bootstrap. При выключенной политике запрос уходит через туннель, а
// туннеля ещё нет — старт замыкается сам на себя.
func TestBootstrapGoesDirect(t *testing.T) {
	direct := &upstream{addr: ipA, ttl: 300}
	tunnel := &upstream{addr: ipB, ttl: 300, down: true}

	r := newResolver(t, Config{
		Upstream:   []netip.AddrPort{upstreamAddr},
		Bootstrap:  []netip.AddrPort{bootAddr},
		Dial:       tunnel.dialTCP,
		DialUDP:    tunnel.dialUDP,
		DialDirect: direct.dialTCP,
		// Живого узла нет: bootstrap работает именно в этот момент.
		Healthy: dead,
		Clock:   clock.NewFake(epoch),
	})

	addrs, err := r.LookupHost(context.Background(), "node.example.com")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	if addrs[0] != ipA {
		t.Fatalf("получено %v, ожидалось %v (ответ bootstrap-резолвера)", addrs[0], ipA)
	}
	if udp, tcp := tunnel.calls(); udp+tcp != 0 {
		t.Fatalf("резолв имени узла ушёл через туннель (udp=%d, tcp=%d) — петля §5.7а", udp, tcp)
	}
	if _, tcp := direct.calls(); tcp == 0 {
		t.Fatal("bootstrap-резолвер не опрошен вовсе")
	}
}

// Кэш живёт ровно столько, сколько сказал TTL ответа (§5.7в). Часы фейковые:
// интервалы в этом продукте не берутся из настоящего времени (§8.1).
func TestCacheExpiresOnTTL(t *testing.T) {
	clk := clock.NewFake(epoch)
	up := &upstream{addr: ipA, ttl: 60}
	r := newResolver(t, Config{
		Upstream: []netip.AddrPort{upstreamAddr},
		Dial:     up.dialTCP,
		DialUDP:  up.dialUDP,
		Healthy:  alive,
		Clock:    clk,
	})

	if got := resolve(t, r, "example.com"); got != ipA {
		t.Fatalf("получено %v, ожидалось %v", got, ipA)
	}
	up.set(ipB)

	clk.Advance(59 * time.Second)
	if got := resolve(t, r, "example.com"); got != ipA {
		t.Fatalf("запись выброшена раньше TTL: получено %v", got)
	}

	clk.Advance(2 * time.Second)
	if got := resolve(t, r, "example.com"); got != ipB {
		t.Fatalf("после истечения TTL получено %v, ожидалось %v", got, ipB)
	}
}

// Усечённый ответ по UDP перезапрашивается по TCP (RFC 1035 §4.2.1): иначе от
// набора записей остаётся начало, и приложение получает не тот адрес.
func TestTruncatedFallsBackToTCP(t *testing.T) {
	up := &upstream{addr: ipA, ttl: 60, truncate: true}
	r := newResolver(t, Config{
		Upstream: []netip.AddrPort{upstreamAddr},
		Dial:     up.dialTCP,
		DialUDP:  up.dialUDP,
		Healthy:  alive,
		Clock:    clock.NewFake(epoch),
	})

	if got := resolve(t, r, "example.com"); got != ipA {
		t.Fatalf("получено %v, ожидалось %v", got, ipA)
	}
	udp, tcp := up.calls()
	if udp != 1 {
		t.Fatalf("запросов по UDP %d, ожидался один", udp)
	}
	if tcp != 1 {
		t.Fatalf("запросов по TCP %d, ожидался один: усечённый ответ принят как окончательный", tcp)
	}
}

// §5.7б. Живого узла нет — резолвер отвечает SERVFAIL и никуда не ходит.
// Молчание здесь запрещено наравне с обходом туннеля: приложение, не получившее
// ответа, ждёт таймаута своего резолвера (§5.6).
func TestServfailWithoutAliveNode(t *testing.T) {
	up := &upstream{addr: ipA, ttl: 60}
	r := newResolver(t, Config{
		Upstream: []netip.AddrPort{upstreamAddr},
		Dial:     up.dialTCP,
		DialUDP:  up.dialUDP,
		Healthy:  dead,
		Clock:    clock.NewFake(epoch),
	})

	query, id, err := buildQuery(question("example.com"))
	if err != nil {
		t.Fatalf("сборка запроса: %v", err)
	}
	answer, err := r.Query(query, client, router53)
	if err != nil {
		t.Fatalf("fail-close промолчал вместо отказа: %v", err)
	}

	var p dnsmessage.Parser
	h, err := p.Start(answer)
	if err != nil {
		t.Fatalf("ответ неразбираем: %v", err)
	}
	if h.ID != id {
		t.Fatalf("ответ с идентификатором %d, спрашивали %d", h.ID, id)
	}
	if h.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("код ответа %v, ожидался SERVFAIL", h.RCode)
	}
	if udp, tcp := up.calls(); udp+tcp != 0 {
		t.Fatalf("fail-close выпустил запрос наружу (udp=%d, tcp=%d)", udp, tcp)
	}
}

// Ответ приходит с того адреса, на который слал клиент. Проверяется сквозь
// netstack, потому что адрес источника проставляет он: резолвер отдаёт только
// сообщение. Заодно это T16 против настоящего резолвера — запрос на локальный
// роутер обязан быть перехвачен, а не уйти в локальную сеть (§3.4).
func TestReplyComesFromServerAddr(t *testing.T) {
	up := &upstream{addr: ipA, ttl: 60}
	r := newResolver(t, Config{
		Upstream: []netip.AddrPort{upstreamAddr},
		Dial:     up.dialTCP,
		DialUDP:  up.dialUDP,
		Healthy:  alive,
		Clock:    clock.NewFake(epoch),
	})

	dev := packettest.NewFake(1500)
	byp := fakenet.NewBypass()
	st, err := netstack.New(netstack.Config{
		Device:   dev,
		Dialer:   fakenet.NewDialer(false),
		Resolver: r,
		Bypass:   byp,
		Clock:    clock.NewFake(epoch),
		Healthy:  alive,
	})
	if err != nil {
		t.Fatalf("netstack.New: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- st.Run() }()
	t.Cleanup(func() {
		dev.Close()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
		st.Close()
	})

	query, id, err := buildQuery(question("example.com"))
	if err != nil {
		t.Fatalf("сборка запроса: %v", err)
	}
	dev.Inject(packettest.UDP(client, router53, query))
	got := dev.WaitEmitted(t, 1)

	src, dst, payload, ok := udpOf(got[0])
	if !ok {
		t.Fatalf("ответ не UDP: % x", got[0])
	}
	if src != router53 || dst != client {
		t.Fatalf("ответ пришёл %v → %v, а клиент слал на %v", src, dst, router53)
	}
	addrs, err := addrsOf(payload, id)
	if err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if addrs[0] != ipA {
		t.Fatalf("получено %v, ожидалось %v", addrs[0], ipA)
	}
	if n := len(byp.Packets()); n != 0 {
		t.Fatalf("запрос на локальный роутер ушёл мимо резолвера, пакетов %d (§3.4)", n)
	}
}

func udpOf(pkt []byte) (src, dst netip.AddrPort, payload []byte, ok bool) {
	if len(pkt) < header.IPv4MinimumSize {
		return src, dst, nil, false
	}
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) || ip.Protocol() != uint8(header.UDPProtocolNumber) {
		return src, dst, nil, false
	}
	u := header.UDP(ip.Payload())
	if len(u) < header.UDPMinimumSize {
		return src, dst, nil, false
	}
	sa, ok1 := netip.AddrFromSlice(ip.SourceAddressSlice())
	da, ok2 := netip.AddrFromSlice(ip.DestinationAddressSlice())
	if !ok1 || !ok2 {
		return src, dst, nil, false
	}
	return netip.AddrPortFrom(sa, u.SourcePort()), netip.AddrPortFrom(da, u.DestinationPort()), u.Payload(), true
}
