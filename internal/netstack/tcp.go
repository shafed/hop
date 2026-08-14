package netstack

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID = tcpip.NICID(1)
	// maxInFlight — сколько рукопожатий gvisor держит одновременно. Верхняя
	// граница памяти на полуоткрытые соединения, не политика.
	maxInFlight = 1024
)

// tcpStack — gvisor поверх устройства. Только TCP: UDP через gvisor не идёт,
// потому что его forwarder отдаёт connected-эндпоинт на пару (src, dst).
type tcpStack struct {
	s    *Stack
	gv   *stack.Stack
	link *linkEndpoint

	mu   sync.Mutex
	live map[*liveFlow]struct{}
}

// liveFlow — живой проксированный поток. Держим его только ради ResetFlows:
// закрыть соединение может лишь тот, кто его держит, а §5.5 требует уметь
// закрыть все разом.
type liveFlow struct {
	stop func()
}

func newTCPStack(s *Stack) (*tcpStack, error) {
	mtu := s.dev.MTU()
	if mtu <= 0 {
		mtu = 1500
	}

	t := &tcpStack{s: s, live: make(map[*liveFlow]struct{})}
	t.link = &linkEndpoint{s: s, mtu: uint32(mtu)}
	t.gv = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	if err := t.gv.CreateNIC(nicID, t.link); err != nil {
		return nil, errTCPIP("CreateNIC", err)
	}
	// Адреса назначения принадлежат кому угодно: стек их терминирует, а не
	// владеет ими. Отсюда promiscuous (принимать пакеты на чужой адрес) и
	// spoofing (отвечать с чужого адреса).
	if err := t.gv.SetPromiscuousMode(nicID, true); err != nil {
		return nil, errTCPIP("SetPromiscuousMode", err)
	}
	if err := t.gv.SetSpoofing(nicID, true); err != nil {
		return nil, errTCPIP("SetSpoofing", err)
	}
	t.gv.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	fwd := tcp.NewForwarder(t.gv, 0, maxInFlight, t.onTCP)
	t.gv.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	return t, nil
}

func (t *tcpStack) inject(pkt []byte) { t.link.inject(pkt) }

func (t *tcpStack) close() {
	t.gv.Close()
	t.gv.Wait()
}

// onTCP — единственное место, где потоку TCP даётся ход.
//
// Вердикт здесь уже принят: он лежит в flowTable с того момента, как SYN прошёл
// насос, то есть **до** того, как gvisor увидел пакет. Форвардер добавляет к
// этому второе свойство: SYN-ACK уходит только из CreateEndpoint, поэтому
// исходящее соединение устанавливается раньше рукопожатия с приложением, и
// неудача наружу превращается в RST, а не в повисшее «соединение установлено».
func (t *tcpStack) onTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	f := flow{
		proto: uint8(header.TCPProtocolNumber),
		src:   addrPortOf(id.RemoteAddress, id.RemotePort),
		dst:   addrPortOf(id.LocalAddress, id.LocalPort),
	}

	switch t.s.flows.peek(f) {
	case Proxy:
		t.proxy(r, f)
	case HijackDNS:
		t.dnsOverTCP(r, f)
	default:
		// Потока нет в таблице — значит, пакет попал в стек мимо насоса.
		// Довериться нечему, отказываем.
		r.Complete(true)
	}
}

func (t *tcpStack) proxy(r *tcp.ForwarderRequest, f flow) {
	if t.s.cfg.Dialer == nil {
		r.Complete(true)
		return
	}
	remote, err := t.s.cfg.Dialer.DialTCP(f.dst)
	if err != nil {
		r.Complete(true)
		return
	}
	local, ok := t.accept(r)
	if !ok {
		_ = remote.Close()
		return
	}
	t.pipe(local, remote)
}

// accept завершает рукопожатие с приложением.
func (t *tcpStack) accept(r *tcp.ForwarderRequest) (net.Conn, bool) {
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return nil, false
	}
	r.Complete(false)
	return gonet.NewTCPConn(&wq, ep), true
}

// pipe перекладывает байты в обе стороны и закрывает обе стороны, как только
// умолкла любая из них.
func (t *tcpStack) pipe(a, b net.Conn) {
	var once sync.Once
	f := &liveFlow{}
	f.stop = func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}

	t.mu.Lock()
	t.live[f] = struct{}{}
	t.mu.Unlock()

	// Поток, кончившийся сам, уходит из списка: иначе список растёт всё время
	// работы агента и «сколько соединений разорвано» перестаёт быть правдой.
	done := func() {
		t.mu.Lock()
		delete(t.live, f)
		t.mu.Unlock()
		f.stop()
	}

	t.s.wg.Add(2)
	go func() {
		defer t.s.wg.Done()
		defer done()
		_, _ = io.Copy(a, b)
	}()
	go func() {
		defer t.s.wg.Done()
		defer done()
		_, _ = io.Copy(b, a)
	}()
}

// reset закрывает живые потоки и возвращает их число (§5.5).
func (t *tcpStack) reset() int {
	t.mu.Lock()
	live := make([]*liveFlow, 0, len(t.live))
	for f := range t.live {
		live = append(live, f)
	}
	clear(t.live)
	t.mu.Unlock()

	// Закрываем вне замка: stop будит копирующие горутины, а они лезут за тем
	// же замком, чтобы вычеркнуть себя из списка.
	for _, f := range live {
		f.stop()
	}
	return len(live)
}

// dnsOverTCP — §3.4 говорит «dst-порт 53 (UDP или TCP)». Поток надо
// терминировать, чтобы добраться до запроса: DNS поверх TCP несёт запрос с
// двухбайтовым префиксом длины (RFC 1035 §4.2.2).
func (t *tcpStack) dnsOverTCP(r *tcp.ForwarderRequest, f flow) {
	if t.s.cfg.Resolver == nil {
		r.Complete(true)
		return
	}
	conn, ok := t.accept(r)
	if !ok {
		return
	}
	t.s.wg.Add(1)
	go func() {
		defer t.s.wg.Done()
		defer conn.Close()
		var hdr [2]byte
		for {
			if _, err := io.ReadFull(conn, hdr[:]); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(hdr[:]))
			if _, err := io.ReadFull(conn, query); err != nil {
				return
			}
			answer, err := t.s.cfg.Resolver.Query(query, f.src, f.dst)
			if err != nil {
				return
			}
			binary.BigEndian.PutUint16(hdr[:], uint16(len(answer)))
			if _, err := conn.Write(append(hdr[:], answer...)); err != nil {
				return
			}
		}
	}()
}

// linkEndpoint — stack.LinkEndpoint поверх PacketDevice. Своя реализация, а не
// link/channel: у channel исходящая очередь ограничена и роняет пакеты при
// переполнении, а замер RTT поверх стека именно этого и не должен видеть.
type linkEndpoint struct {
	s   *Stack
	mtu uint32

	mu      sync.RWMutex
	disp    stack.NetworkDispatcher
	onClose func()
}

func (e *linkEndpoint) inject(pkt []byte) {
	e.mu.RLock()
	d := e.disp
	e.mu.RUnlock()
	if d == nil {
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	d.DeliverNetworkPacket(header.IPv4ProtocolNumber, pb)
	pb.DecRef()
}

func (e *linkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	list := pkts.AsSlice()
	views := make([]*buffer.View, 0, len(list))
	out := make([][]byte, 0, len(list))
	for _, pkt := range list {
		v := pkt.ToView()
		views = append(views, v)
		out = append(out, v.AsSlice())
	}
	e.s.write(out...)
	for _, v := range views {
		v.Release()
	}
	return len(list), nil
}

func (e *linkEndpoint) Attach(d stack.NetworkDispatcher) {
	e.mu.Lock()
	e.disp = d
	e.mu.Unlock()
}

func (e *linkEndpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.disp != nil
}

func (e *linkEndpoint) MTU() uint32       { return e.mtu }
func (e *linkEndpoint) SetMTU(mtu uint32) { e.mtu = mtu }

// Канального заголовка нет: через границу идут сырые IP-пакеты (§3.2).
func (e *linkEndpoint) MaxHeaderLength() uint16          { return 0 }
func (e *linkEndpoint) LinkAddress() tcpip.LinkAddress   { return "" }
func (e *linkEndpoint) SetLinkAddress(tcpip.LinkAddress) {}
func (e *linkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}
func (e *linkEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (e *linkEndpoint) AddHeader(*stack.PacketBuffer)           {}
func (e *linkEndpoint) ParseHeader(*stack.PacketBuffer) bool    { return true }
func (e *linkEndpoint) Wait()                                   {}

func (e *linkEndpoint) Close() {
	e.mu.Lock()
	f := e.onClose
	e.mu.Unlock()
	if f != nil {
		f()
	}
}

func (e *linkEndpoint) SetOnCloseAction(f func()) {
	e.mu.Lock()
	e.onClose = f
	e.mu.Unlock()
}

func addrPortOf(a tcpip.Address, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4(a.As4()), port)
}

type tcpipError struct {
	op  string
	err tcpip.Error
}

func (e tcpipError) Error() string { return "netstack: " + e.op + ": " + e.err.String() }

func errTCPIP(op string, err tcpip.Error) error { return tcpipError{op, err} }
