package bypass

import (
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/packet"
	"github.com/shafed/hop/internal/packettest"
)

// countingControl — Control, который считает вызовы вместо настоящей
// привязки к физическому интерфейсу. Привязку проверяет L3 (реальный
// интерфейс есть не на всякой машине CI); здесь важно, что Control зовётся
// ровно на каждый новый сокет.
func countingControl(calls *int32) ControlFunc {
	return func(_ string, _ string, c syscall.RawConn) error {
		atomic.AddInt32(calls, 1)
		return c.Control(func(uintptr) {})
	}
}

// newListener — «физический» пир: обычный UDP-сокет на loopback, слушающий
// то, что NAT отправит наружу.
func newListener(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func addrPortOf(t *testing.T, a net.Addr) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		t.Fatalf("ParseAddrPort(%s): %v", a, err)
	}
	return ap
}

const readTimeout = 2 * time.Second

var client = netip.MustParseAddrPort("10.0.0.5:41000")

func TestBypassSendsDatagramFromBoundSocket(t *testing.T) {
	listener := newListener(t)

	var calls int32
	n, err := New(Config{Control: countingControl(&calls), Reply: func([]byte) {}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.Close()

	listenerAddr := addrPortOf(t, listener.LocalAddr())
	payload := []byte("_services._dns-sd._udp.local")
	if err := n.Send(packettest.UDP(client, listenerAddr, payload)); err != nil {
		t.Fatalf("Send: %v", err)
	}

	buf := make([]byte, 1500)
	listener.SetReadDeadline(time.Now().Add(readTimeout)) //hop:realtime
	nRead, _, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("нагрузка не дошла до слушателя: %v", err)
	}
	if got := string(buf[:nRead]); got != string(payload) {
		t.Fatalf("нагрузка = %q, ожидалась %q", got, payload)
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("Control позван %d раз(а), ожидался 1 — на новый сокет", got)
	}
}

func TestBypassReplyReturnsToClient(t *testing.T) {
	listener := newListener(t)

	replies := make(chan []byte, 1)
	n, err := New(Config{
		Control: countingControl(new(int32)),
		Reply:   func(pkt []byte) { replies <- pkt },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.Close()

	listenerAddr := addrPortOf(t, listener.LocalAddr())
	if err := n.Send(packettest.UDP(client, listenerAddr, []byte("query"))); err != nil {
		t.Fatalf("Send: %v", err)
	}

	buf := make([]byte, 1500)
	listener.SetReadDeadline(time.Now().Add(readTimeout)) //hop:realtime
	nRead, from, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("запрос не дошёл до слушателя: %v", err)
	}

	answer := []byte("answer")
	if _, err := listener.WriteToUDP(answer, from); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}
	_ = nRead

	select {
	case pkt := <-replies:
		src, dst, payload, ok := packet.ParseUDP4(pkt)
		if !ok {
			t.Fatalf("Reply получил неразбираемый пакет: % x", pkt)
		}
		if src != listenerAddr {
			t.Fatalf("src = %v, ожидался адрес слушателя %v", src, listenerAddr)
		}
		if dst != client {
			t.Fatalf("dst = %v, ожидался адрес клиента %v", dst, client)
		}
		if string(payload) != string(answer) {
			t.Fatalf("нагрузка ответа = %q, ожидалась %q", payload, answer)
		}
	case <-time.After(readTimeout): //hop:realtime
		t.Fatal("Reply не позван за отведённое время")
	}
}

// TestBypassAcceptsReplyFromAnotherAddress — форма mDNS (§5.3): респондер
// отвечает с собственного unicast-адреса, а не с адреса, на который клиент
// слал запрос (multicast-группа). Full-cone обязан принять такой ответ.
func TestBypassAcceptsReplyFromAnotherAddress(t *testing.T) {
	group := newListener(t)     // адрес, на который клиент "слал" (аналог 224.0.0.251:5353)
	responder := newListener(t) // адрес, с которого реально пришёл ответ

	replies := make(chan []byte, 1)
	n, err := New(Config{
		Control: countingControl(new(int32)),
		Reply:   func(pkt []byte) { replies <- pkt },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.Close()

	groupAddr := addrPortOf(t, group.LocalAddr())
	if err := n.Send(packettest.UDP(client, groupAddr, []byte("query"))); err != nil {
		t.Fatalf("Send: %v", err)
	}

	buf := make([]byte, 1500)
	group.SetReadDeadline(time.Now().Add(readTimeout)) //hop:realtime
	_, from, err := group.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("запрос не дошёл до group: %v", err)
	}
	natAddr := from // локальный адрес NAT-сокета, увиденный слушателем

	answer := []byte("unicast answer")
	if _, err := responder.WriteToUDP(answer, natAddr); err != nil {
		t.Fatalf("WriteToUDP от responder: %v", err)
	}

	select {
	case pkt := <-replies:
		src, dst, payload, ok := packet.ParseUDP4(pkt)
		if !ok {
			t.Fatalf("Reply получил неразбираемый пакет: % x", pkt)
		}
		responderAddr := addrPortOf(t, responder.LocalAddr())
		if src != responderAddr {
			t.Fatalf("src = %v, ожидался адрес респондера %v (full-cone)", src, responderAddr)
		}
		if dst != client {
			t.Fatalf("dst = %v, ожидался адрес клиента %v", dst, client)
		}
		if string(payload) != string(answer) {
			t.Fatalf("нагрузка ответа = %q, ожидалась %q", payload, answer)
		}
	case <-time.After(readTimeout): //hop:realtime
		t.Fatal("ответ с другого адреса потерян — full-cone не сработал")
	}
}

func TestBypassRefusesTCP(t *testing.T) {
	listener := newListener(t)

	// atomic: Reply зовётся из горутины receive, тело теста читает из своей —
	// без этого запись гонялась бы с чтением незамеченной ровно тогда, когда
	// это стало бы важно (TCP получил бы Reply).
	var replied atomic.Bool
	n, err := New(Config{
		Control: countingControl(new(int32)),
		Reply:   func([]byte) { replied.Store(true) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.Close()

	listenerAddr := addrPortOf(t, listener.LocalAddr())
	err = n.Send(packettest.TCPSyn(client, listenerAddr, 1))
	if err != ErrUnsupported {
		t.Fatalf("ошибка = %v, ожидалась ErrUnsupported", err)
	}

	listener.SetReadDeadline(time.Now().Add(200 * time.Millisecond)) //hop:realtime
	buf := make([]byte, 64)
	if _, _, rerr := listener.ReadFromUDP(buf); rerr == nil {
		t.Fatal("TCP-пакет всё же ушёл наружу")
	}
	if replied.Load() {
		t.Fatal("Reply позван для отказавшего TCP")
	}
}

// Простой дольше Idle закрывает сокет, и делает это Send, а не Stats.
//
// Проверяется через второго клиента: он заводит свой сокет и тем самым
// прокручивает уборку, после чего сокет остаётся ровно один — его. Раньше тест
// смотрел на Stats после сдвига часов и проходил за счёт уборки внутри самого
// геттера; теперь Stats — чистое чтение (см. её doc), и опереться на неё
// значило бы проверять то, чего в продукте нет: снимок счётчиков трафика не
// двигает.
func TestBypassIdleClosesSocket(t *testing.T) {
	listener := newListener(t)
	clk := clock.NewFake(time.Unix(0, 0))

	n, err := New(Config{
		Control: countingControl(new(int32)),
		Reply:   func([]byte) {},
		Clock:   clk,
		Idle:    2 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.Close()

	listenerAddr := addrPortOf(t, listener.LocalAddr())
	if err := n.Send(packettest.UDP(client, listenerAddr, []byte("hi"))); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := n.Stats().Sockets; got != 1 {
		t.Fatalf("Sockets = %d сразу после Send, ожидался 1", got)
	}

	clk.Advance(3 * time.Second)
	other := netip.AddrPortFrom(client.Addr(), client.Port()+1)
	if err := n.Send(packettest.UDP(other, listenerAddr, []byte("hi"))); err != nil {
		t.Fatalf("Send второго клиента: %v", err)
	}
	if got := n.Stats().Sockets; got != 1 {
		t.Fatalf("Sockets = %d после простоя дольше Idle, ожидался 1 — сокет первого клиента не убран", got)
	}
}

func TestBypassCloseStopsGoroutines(t *testing.T) {
	listener := newListener(t)
	before := runtime.NumGoroutine()

	var mu sync.Mutex
	var replies int
	n, err := New(Config{
		Control: countingControl(new(int32)),
		Reply:   func([]byte) { mu.Lock(); replies++; mu.Unlock() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	listenerAddr := addrPortOf(t, listener.LocalAddr())
	if err := n.Send(packettest.UDP(client, listenerAddr, []byte("hi"))); err != nil {
		t.Fatalf("Send: %v", err)
	}
	buf := make([]byte, 1500)
	listener.SetReadDeadline(time.Now().Add(readTimeout)) //hop:realtime
	if _, _, err := listener.ReadFromUDP(buf); err != nil {
		t.Fatalf("запрос не дошёл до слушателя: %v", err)
	}

	n.Close()

	if err := n.Send(packettest.UDP(client, listenerAddr, []byte("after close"))); err != errClosed {
		t.Fatalf("Send после Close = %v, ожидался errClosed", err)
	}

	// Close уже дожидается n.wg внутри, так что receive к этому моменту
	// вернулась — опрос с ограниченным временем нужен только на случай гонки
	// рантайма между Done() и фактическим снятием горутины со стека, не как
	// замена ожиданию. Без этой проверки утечка горутины не падает здесь, а
	// проявляется зависанием какого-то другого, ни к чему не обязанного теста.
	deadline := time.Now().Add(readTimeout) //hop:realtime
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) { //hop:realtime
			t.Fatalf("горутины не остановились после Close: сейчас %d, было %d", runtime.NumGoroutine(), before)
		}
		time.Sleep(5 * time.Millisecond) //hop:realtime
	}
}
