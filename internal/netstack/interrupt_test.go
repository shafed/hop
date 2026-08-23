package netstack

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gstack "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/fakenet"
	"github.com/shafed/hop/internal/packettest"
)

// Недостающая проверка под W8/W14 (docs/verification-agent.md): ни A18
// (health), ни T9/T10 (l2) не проходят через настоящий tcpStack.pipe — оба
// разрывают через стенд. Здесь — реестр релеев netstack против настоящего
// TCP-рукопожатия через gvisor.
//
// clientRig — второй gvisor-стек по другую сторону настоящего netstack.Stack:
// то, чем в проде было бы приложение и ядро клиента. Мост — тот же
// packettest.FakeDevice, что и остальные тесты пакета, а не граница ОС
// (internal/bench): здесь важно настоящее рукопожатие через forwarder, а не
// сама труба.

const clientNIC = tcpip.NICID(1)

type clientLink struct {
	dev *packettest.FakeDevice
	mtu uint32

	mu   sync.RWMutex
	disp gstack.NetworkDispatcher
}

func (l *clientLink) inject(pkt []byte) {
	l.mu.RLock()
	d := l.disp
	l.mu.RUnlock()
	if d == nil {
		return
	}
	pb := gstack.NewPacketBuffer(gstack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	d.DeliverNetworkPacket(header.IPv4ProtocolNumber, pb)
	pb.DecRef()
}

func (l *clientLink) WritePackets(pkts gstack.PacketBufferList) (int, tcpip.Error) {
	list := pkts.AsSlice()
	views := make([]*buffer.View, 0, len(list))
	out := make([][]byte, 0, len(list))
	for _, pkt := range list {
		v := pkt.ToView()
		views = append(views, v)
		out = append(out, v.AsSlice())
	}
	l.dev.Inject(out...)
	for _, v := range views {
		v.Release()
	}
	return len(list), nil
}

func (l *clientLink) Attach(d gstack.NetworkDispatcher) {
	l.mu.Lock()
	l.disp = d
	l.mu.Unlock()
}

func (l *clientLink) IsAttached() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.disp != nil
}

func (l *clientLink) MTU() uint32                             { return l.mtu }
func (l *clientLink) SetMTU(mtu uint32)                       { l.mtu = mtu }
func (l *clientLink) MaxHeaderLength() uint16                 { return 0 }
func (l *clientLink) LinkAddress() tcpip.LinkAddress          { return "" }
func (l *clientLink) SetLinkAddress(tcpip.LinkAddress)        {}
func (l *clientLink) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (l *clientLink) AddHeader(*gstack.PacketBuffer)          {}
func (l *clientLink) ParseHeader(*gstack.PacketBuffer) bool   { return true }
func (l *clientLink) Wait()                                   {}
func (l *clientLink) Close()                                  {}
func (l *clientLink) SetOnCloseAction(func())                 {}
func (l *clientLink) Capabilities() gstack.LinkEndpointCapabilities {
	return gstack.CapabilityRXChecksumOffload
}

// clientRig держит клиентский стек и насос, перекладывающий то, что
// netstack.Stack записал в FakeDevice, обратно в клиентский link — иначе
// SYN-ACK и данные сервера некуда было бы доставить.
type clientRig struct {
	s    *gstack.Stack
	link *clientLink
	stop chan struct{}
	wg   sync.WaitGroup
}

func newClientRig(t *testing.T, dev *packettest.FakeDevice, addr netip.Addr) *clientRig {
	t.Helper()

	r := &clientRig{stop: make(chan struct{})}
	r.link = &clientLink{dev: dev, mtu: uint32(dev.MTU())}
	r.s = gstack.New(gstack.Options{
		NetworkProtocols:   []gstack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []gstack.TransportProtocolFactory{tcp.NewProtocol},
	})
	if err := r.s.CreateNIC(clientNIC, r.link); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	pa := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(addr.As4()).WithPrefix(),
	}
	if err := r.s.AddProtocolAddress(clientNIC, pa, gstack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	r.s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: clientNIC}})

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			select {
			case <-dev.Written():
				for _, p := range dev.Emitted() {
					r.link.inject(p)
				}
			case <-r.stop:
				return
			}
		}
	}()

	t.Cleanup(func() {
		close(r.stop)
		r.s.Close()
		r.s.Wait()
		r.wg.Wait()
	})
	return r
}

func (r *clientRig) dial(dst netip.AddrPort) (*gonet.TCPConn, error) {
	return gonet.DialContextTCP(context.Background(), r.s, tcpip.FullAddress{
		NIC:  clientNIC,
		Addr: tcpip.AddrFrom4(dst.Addr().As4()),
		Port: dst.Port(),
	}, ipv4.ProtocolNumber)
}

// interruptHarness — netstack.Stack поверх FakeDevice, живой узел, без насоса
// bypass/резолвера: только то, что нужно рукопожатию TCP через proxy.
type interruptHarness struct {
	dev    *packettest.FakeDevice
	st     *Stack
	dialer *fakenet.Dialer
}

func newInterruptHarness(t *testing.T) *interruptHarness {
	t.Helper()
	h := &interruptHarness{
		dev:    packettest.NewFake(1500),
		dialer: fakenet.NewDialer(false),
	}
	st, err := New(Config{
		Device:  h.dev,
		Dialer:  h.dialer,
		Clock:   clock.NewFake(time.Unix(1, 0)),
		Healthy: func() bool { return true },
	})
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

// Живое TCP-соединение через настоящий узел, разрыв на уровне Stack обязан
// закрыть сокет клиента (§5.5, W8/W14). fakenet.Dialer.DialTCP отдаёт
// эхо-соединение — им и проверяется, что реле живо до разрыва.
func TestInterruptTCPClosesLiveConnection(t *testing.T) {
	h := newInterruptHarness(t)
	rig := newClientRig(t, h.dev, client.Addr())

	conn, err := rig.dial(web)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("ping")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("эхо не пришло: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("эхо %q, ожидалось %q", got, msg)
	}

	if n := h.st.InterruptTCP(); n != 1 {
		t.Fatalf("InterruptTCP вернул %d, ожидалась ровно одна разорванная связь", n)
	}

	if err := conn.SetReadDeadline(time.Now().Add(packettest.WaitTimeout)); err != nil { //hop:realtime сторож
		t.Fatalf("дедлайн чтения: %v", err)
	}
	if _, err := conn.Read(got); err == nil {
		t.Fatal("соединение осталось открытым после InterruptTCP")
	}
}

// Несколько живых соединений: InterruptTCP считает и рвёт их все, а не первое
// попавшееся.
func TestInterruptTCPCountsAllOpenRelays(t *testing.T) {
	h := newInterruptHarness(t)
	rig := newClientRig(t, h.dev, client.Addr())

	const n = 3
	conns := make([]*gonet.TCPConn, n)
	for i := range conns {
		conn, err := rig.dial(web)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer conn.Close()

		// Эхо, а не просто дозвон: реле встаёт в реестр внутри pipe(), уже
		// после accept, и дозвон диалера этого не гарантирует. Дошедшее эхо —
		// доказательство, что обе горутины io.Copy уже подняты и relay
		// зарегистрирован.
		msg := []byte{byte('a' + i)}
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("соединение %d: write: %v", i, err)
		}
		got := make([]byte, 1)
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("соединение %d: эхо не пришло: %v", i, err)
		}
		conns[i] = conn
	}

	if got := h.st.InterruptTCP(); got != n {
		t.Fatalf("InterruptTCP вернул %d, ожидалось %d", got, n)
	}

	for i, conn := range conns {
		if err := conn.SetReadDeadline(time.Now().Add(packettest.WaitTimeout)); err != nil { //hop:realtime сторож
			t.Fatalf("соединение %d: дедлайн чтения: %v", i, err)
		}
		var b [1]byte
		if _, err := conn.Read(b[:]); err == nil {
			t.Fatalf("соединение %d осталось открытым после InterruptTCP", i)
		}
	}
}

// Соединений нет — рвать нечего, и это не ошибка.
func TestInterruptTCPWithNoConnectionsReturnsZero(t *testing.T) {
	h := newInterruptHarness(t)
	if n := h.st.InterruptTCP(); n != 0 {
		t.Fatalf("InterruptTCP вернул %d при отсутствии соединений, ожидался 0", n)
	}
}
