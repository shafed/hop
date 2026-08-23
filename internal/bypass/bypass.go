// Package bypass — то, что §6.10 выпускает мимо туннеля, выпускается на самом
// деле: через сокет агента, привязанный к физическому интерфейсу (§6.8).
package bypass

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/packet"
	"github.com/shafed/hop/internal/policy"
)

// ControlFunc — привязка свежего сокета к физическому интерфейсу (§6.8).
// В продукте это outbound.Selector.Control.
type ControlFunc func(network, address string, c syscall.RawConn) error

// Config — всё, от чего зависит NAT.
type Config struct {
	Control ControlFunc      // обязателен
	Reply   func(pkt []byte) // обратный путь: собранный IPv4/UDP-пакет в туннель
	Clock   clock.Clock      // nil → clock.System{}
	Idle    time.Duration    // 0 → 60 с, как netstack.defaultUDPIdle
}

// defaultIdle — то же значение, что netstack.defaultUDPIdle: простой UDP §5.3
// в обеих таблицах трактуется одинаково.
const defaultIdle = 60 * time.Second

// ErrDisabled — политика bypass_sink выключена: прежнее поведение молчаливого
// дропа (§6.10). Send ничего не отправляет.
var ErrDisabled = errors.New("bypass: политика bypass_sink выключена")

// ErrUnsupported — пакет не IPv4/UDP, в том числе TCP в локальную сеть.
// TCP-путь bypass не реализован в этом заходе: вердикт Bypass для TCP
// (RFC1918/loopback/link-local, internal/netstack/verdict.go) остаётся
// дропом — честный путь означал бы терминацию потока в gvisor и попадание
// релея в реестр §5.5, чья семантика «рвём соединения при смерти узла» для
// bypass неверна (см. «Решения» плана bypass-sink-nat).
var ErrUnsupported = errors.New("bypass: поддерживается только IPv4/UDP")

// errClosed — NAT закрыт, Send отказывает.
var errClosed = errors.New("bypass: NAT закрыт")

// socket — исходящий сокет. Один на исходный addr:port клиента: full-cone,
// ключа с адресом назначения нет вовсе (см. «Решения» плана — ответ mDNS
// приходит с unicast-адреса респондера, а не с адреса, на который слали).
type socket struct {
	conn net.PacketConn
	src  netip.AddrPort
	seen time.Time
}

// NAT — full-cone UDP NAT для вердикта bypass (§6.10). Та же форма, что
// natTable (internal/netstack/udp.go): сокет на исходный порт клиента,
// горутина чтения ответов на каждый сокет, уборка простоя по часам. Отличия —
// сокет всегда привязан к физическому интерфейсу через Control, а не заведён
// диалером Xray, и ключа с dst нет: bypass всегда full-cone.
type NAT struct {
	cfg  Config
	clk  clock.Clock
	idle time.Duration

	mu       sync.Mutex
	socks    map[netip.AddrPort]*socket
	orphaned int64
	closed   bool
	swept    time.Time

	closeOnce sync.Once
	wg        sync.WaitGroup
}

// New заводит NAT. Control и Reply обязательны: без Control новому сокету
// не к чему привязаться (петля §6.8), без Reply обратному пути некуда
// возвращаться.
func New(cfg Config) (*NAT, error) {
	if cfg.Control == nil {
		return nil, errors.New("bypass: Control обязателен")
	}
	if cfg.Reply == nil {
		return nil, errors.New("bypass: Reply обязателен")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.Idle <= 0 {
		cfg.Idle = defaultIdle
	}
	return &NAT{
		cfg:   cfg,
		clk:   cfg.Clock,
		idle:  cfg.Idle,
		socks: make(map[netip.AddrPort]*socket),
		swept: cfg.Clock.Now(),
	}, nil
}

// Send реализует netstack.BypassSink. Выключенная политика или пакет не
// IPv4/UDP — отказ, ничего не уходит наружу; иначе датаграмма уходит через
// сокет, заведённый или найденный по исходному addr:port клиента.
func (n *NAT) Send(pkt []byte) error {
	if !policy.BypassSink.On() {
		return ErrDisabled
	}
	src, dst, payload, ok := packet.ParseUDP4(pkt)
	if !ok {
		return ErrUnsupported
	}

	sock, err := n.socketFor(src)
	if err != nil {
		return err
	}
	_, err = sock.conn.WriteTo(payload, net.UDPAddrFromAddrPort(dst))
	return err
}

// socketFor отдаёт сокет на исходный порт клиента, заводя его при первой
// встрече. Отказ Control (нет физического интерфейса, outbound.ErrNoInterface)
// — отказ всего Send, а не непривязанный сокет: непривязанный сокет здесь и
// есть петля, ради предотвращения которой §6.8 написан.
func (n *NAT) socketFor(src netip.AddrPort) (*socket, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, errClosed
	}

	now := n.clk.Now()
	n.sweepLocked(now)

	if sock, ok := n.socks[src]; ok {
		sock.seen = now
		return sock, nil
	}

	conn, err := (&net.ListenConfig{Control: n.cfg.Control}).ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		return nil, err
	}
	sock := &socket{conn: conn, src: src, seen: now}
	n.socks[src] = sock
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.receive(sock)
	}()
	return sock, nil
}

// receive — обратный путь. full-cone (§5.3): ответ принимается с любого
// адреса, не только с того, на который клиент слал, — mDNS-респондер отвечает
// с собственного unicast-адреса, а не с multicast-адреса запроса.
func (n *NAT) receive(sock *socket) {
	buf := make([]byte, 65535)
	for {
		read, from, err := sock.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		peer, ok := addrPort(from)
		if !ok {
			n.mu.Lock()
			n.orphaned++
			n.mu.Unlock()
			continue
		}
		n.mu.Lock()
		sock.seen = n.clk.Now()
		n.mu.Unlock()
		n.cfg.Reply(packet.BuildUDP(peer, sock.src, buf[:read]))
	}
}

// sweepLocked закрывает сокеты, простоявшие без трафика дольше Idle. Тот же
// приём, что у natTable.sweepLocked: срабатывает не чаще раза на Idle/2,
// чтобы не гонять карту на каждом пакете.
func (n *NAT) sweepLocked(now time.Time) {
	if now.Sub(n.swept) < n.idle/2 {
		return
	}
	n.swept = now
	for src, sock := range n.socks {
		if now.Sub(sock.seen) >= n.idle {
			delete(n.socks, src)
			_ = sock.conn.Close()
		}
	}
}

// Close закрывает все сокеты и дожидается их горутин чтения. После Close
// Send отказывает.
func (n *NAT) Close() {
	n.closeOnce.Do(func() {
		n.mu.Lock()
		n.closed = true
		for src, sock := range n.socks {
			delete(n.socks, src)
			_ = sock.conn.Close()
		}
		n.mu.Unlock()
	})
	n.wg.Wait()
}

// Stats — наблюдаемость, как у natTable: сколько сокетов сейчас держит NAT и
// сколько ответов пришло с адреса, не годного для обратного пакета (IPv6-пир,
// которому в IPv4-туннель дороги нет).
type Stats struct {
	Sockets  int
	Orphaned int64
}

// Stats попутно подчищает простаивающие сокеты: у NAT нет фонового тикера —
// Send зовётся с насоса пакетов, а не по расписанию, — и без этого совмещения
// сокет, простоявший без трафика, пережил бы Idle до следующего пакета на
// каком-то другом порту.
func (n *NAT) Stats() Stats {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sweepLocked(n.clk.Now())
	return Stats{Sockets: len(n.socks), Orphaned: n.orphaned}
}

// addrPort — адрес отвечающего в виде, пригодном для обратного пакета.
// IPv6 сюда не попадает: собрать из него IPv4-датаграмму нечем (§6.9).
func addrPort(a net.Addr) (netip.AddrPort, bool) {
	udpAddr, ok := a.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := udpAddr.AddrPort()
	addr := ap.Addr().Unmap()
	if !addr.Is4() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, ap.Port()), true
}
