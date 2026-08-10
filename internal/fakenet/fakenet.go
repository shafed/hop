// Package fakenet — подставное исходящее для этапа 3: диалер, который никуда не
// ходит, UDP-сокеты с управляемыми ответами и резолвер-заглушка.
//
// На этапе 4 всё это заменится на core.Dial / core.DialUDP и настоящие
// VLESS-инбаунды; интерфейсы netstack.Dialer и netstack.Resolver для того и
// существуют.
//
// Пакет намеренно **не импортирует testing**: им пользуется не только L2-тест,
// но и бенчмарк, а тестовые флаги в бинаре бенчмарка не нужны — по той же
// причине, по которой FakePacketDevice живёт отдельно от internal/packet.
package fakenet

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ErrRefused — отказ исходящего соединения. Этап 4 положит сюда классификацию
// §6.15; здесь достаточно самого факта.
var ErrRefused = errors.New("fakenet: соединение отвергнуто")

// Dialer реализует netstack.Dialer.
type Dialer struct {
	mu   sync.Mutex
	fail bool
	cond *sync.Cond
	tcp  []netip.AddrPort
	udp  map[netip.AddrPort]*PacketConn
	auto bool
}

// NewDialer создаёт диалер. autoEcho включает эхо на UDP: каждая отправка
// немедленно возвращается ответом с того же адреса.
func NewDialer(autoEcho bool) *Dialer {
	d := &Dialer{udp: make(map[netip.AddrPort]*PacketConn), auto: autoEcho}
	d.cond = sync.NewCond(&d.mu)
	return d
}

// FailTCP заставляет DialTCP отказывать: так проверяется, что рукопожатие с
// приложением не начинается раньше исходящего соединения.
func (d *Dialer) FailTCP(fail bool) {
	d.mu.Lock()
	d.fail = fail
	d.mu.Unlock()
}

// DialTCP отдаёт эхо-соединение: что записали, то и прочитали обратно.
func (d *Dialer) DialTCP(dst netip.AddrPort) (net.Conn, error) {
	d.mu.Lock()
	if d.fail {
		d.mu.Unlock()
		return nil, ErrRefused
	}
	d.tcp = append(d.tcp, dst)
	d.mu.Unlock()

	near, far := net.Pipe()
	go func() {
		defer far.Close()
		_, _ = io.Copy(far, far)
	}()
	return near, nil
}

// DialUDP отдаёт один сокет на исходный порт клиента — ровно то, что даёт
// core.DialUDP (§5.3).
func (d *Dialer) DialUDP(src netip.AddrPort) (net.PacketConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := newPacketConn(src, d.auto)
	d.udp[src] = c
	d.cond.Broadcast()
	return c, nil
}

// WaitConn ждёт, пока для исходного порта заведётся сокет.
//
// Ожидание, а не опрос со сном: настоящее время в продукте и тестах живёт
// только в internal/clock (§8.1), а зависший тест снимает таймаут go test.
func (d *Dialer) WaitConn(src netip.AddrPort) *PacketConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	for d.udp[src] == nil {
		d.cond.Wait()
	}
	return d.udp[src]
}

// TCPDialed — куда звонили по TCP.
func (d *Dialer) TCPDialed() []netip.AddrPort {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]netip.AddrPort(nil), d.tcp...)
}

// Conn — сокет, заведённый для исходного порта клиента. nil, если не заводился.
func (d *Dialer) Conn(src netip.AddrPort) *PacketConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.udp[src]
}

// Datagram — одна датаграмма с адресом второй стороны.
type Datagram struct {
	Peer netip.AddrPort
	Data []byte
}

// inboxSize — сколько ответов сокет держит непрочитанными. Больше — только
// маскировать отставание читателя.
const inboxSize = 4096

// PacketConn — подставной net.PacketConn.
type PacketConn struct {
	src  netip.AddrPort
	auto bool

	mu     sync.Mutex
	cond   *sync.Cond
	sent   []Datagram
	closed bool

	in   chan Datagram
	done chan struct{}
	once sync.Once
}

func newPacketConn(src netip.AddrPort, auto bool) *PacketConn {
	c := &PacketConn{
		src:  src,
		auto: auto,
		in:   make(chan Datagram, inboxSize),
		done: make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ap, ok := toAddrPort(addr)
	if !ok {
		return 0, errors.New("fakenet: адрес не IPv4")
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.sent = append(c.sent, Datagram{Peer: ap, Data: append([]byte(nil), p...)})
	c.cond.Broadcast()
	c.mu.Unlock()

	if c.auto {
		c.Reply(ap, p)
	}
	return len(p), nil
}

func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case d := <-c.in:
		n := copy(p, d.Data)
		return n, net.UDPAddrFromAddrPort(d.Peer), nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

// Reply кладёт ответ с адреса peer. Именно этим проверяется full-cone: ответ
// может прийти с адреса, на который клиент никогда не слал.
func (c *PacketConn) Reply(peer netip.AddrPort, data []byte) {
	d := Datagram{Peer: peer, Data: append([]byte(nil), data...)}
	select {
	case c.in <- d:
	case <-c.done:
	default: // читатель отстал; для замера это уже деградация, не потеря NAT
	}
}

// Sent — что ушло наружу.
func (c *PacketConn) Sent() []Datagram {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Datagram(nil), c.sent...)
}

// WaitSent ждёт, пока наружу уйдёт n датаграмм.
func (c *PacketConn) WaitSent(n int) []Datagram {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.sent) < n {
		c.cond.Wait()
	}
	return append([]Datagram(nil), c.sent...)
}

func (c *PacketConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		close(c.done)
	})
	return nil
}

func (c *PacketConn) LocalAddr() net.Addr              { return net.UDPAddrFromAddrPort(c.src) }
func (c *PacketConn) SetDeadline(time.Time) error      { return nil }
func (c *PacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *PacketConn) SetWriteDeadline(time.Time) error { return nil }

// Resolver — заглушка перехваченного DNS. Этап 6 поставит сюда настоящий.
type Resolver struct {
	// Answer — что отдавать. Пусто — вернуть запрос как есть: этапу 3 хватает
	// того, что запрос дошёл до резолвера, а не ушёл в сеть.
	Answer []byte

	mu   sync.Mutex
	seen []Asked
}

// Asked — один дошедший запрос.
type Asked struct {
	Query  []byte
	Client netip.AddrPort
	Server netip.AddrPort
}

func (r *Resolver) Query(query []byte, client, server netip.AddrPort) ([]byte, error) {
	r.mu.Lock()
	r.seen = append(r.seen, Asked{append([]byte(nil), query...), client, server})
	answer := r.Answer
	r.mu.Unlock()
	if len(answer) == 0 {
		return query, nil
	}
	return answer, nil
}

// Asks — дошедшие до резолвера запросы.
func (r *Resolver) Asks() []Asked {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Asked(nil), r.seen...)
}

// Bypass — приёмник того, что ушло мимо туннеля (§6.10).
type Bypass struct {
	mu   sync.Mutex
	cond *sync.Cond
	pkts [][]byte
}

// NewBypass создаёт приёмник.
func NewBypass() *Bypass {
	b := &Bypass{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *Bypass) Send(pkt []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pkts = append(b.pkts, append([]byte(nil), pkt...))
	b.cond.Broadcast()
	return nil
}

// Packets — всё, что выпущено в локальную сеть.
func (b *Bypass) Packets() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([][]byte(nil), b.pkts...)
}

// WaitPackets ждёт, пока в локальную сеть уйдёт n пакетов.
func (b *Bypass) WaitPackets(n int) [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.pkts) < n {
		b.cond.Wait()
	}
	return append([][]byte(nil), b.pkts...)
}

func toAddrPort(a net.Addr) (netip.AddrPort, bool) {
	u, ok := a.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := u.AddrPort()
	addr := ap.Addr().Unmap()
	if !addr.Is4() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, ap.Port()), true
}
