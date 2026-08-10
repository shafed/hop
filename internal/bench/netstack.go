// Замеры этапа 3: то, что живёт поверх netstack, а не поверх голой границы.
//
// B1 (этап 1) мерил трубу и показал, что на 1400 байтах и батче 128 стоимость
// границы тонет в пропускной способности. Он же сказал, где она всплывёт: на
// интерактивном трафике мелкими пакетами, где за один RTT границу пересекают
// дважды, и мерить это надо поверх стека. Здесь это и меряется.
//
// Стенд собирается из настоящей границы этой ОС (named pipe на Windows,
// socketpair на Unix) и двух стеков по её сторонам: наш netstack на стороне
// агента и обычный gvisor на стороне «приложения и ядра». Порога нет — это
// базовая линия, как B1 на Unix.
package bench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"sync"
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
	"github.com/shafed/hop/internal/framing"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/packet"
)

// Адреса стенда: клиент за туннелем, «интернет» — документационная сеть.
var (
	benchClient = netip.MustParseAddr("10.255.0.2")
	benchServer = netip.MustParseAddr("203.0.113.7")
)

const benchNIC = tcpip.NICID(1)

// NetstackConfig — параметры замеров этапа 3.
type NetstackConfig struct {
	MTU       int
	Connects  int // сколько соединений мерить на рукопожатие
	Exchanges int // сколько запрос-ответов мерить на установленном соединении
	Payload   int // размер запроса, байт

	// B3: одновременные исходящие порты и адресов на порт.
	Ports  int
	Fanout int
	Rounds int
}

// pipeDevice — PacketDevice поверх настоящей границы.
//
// ReadPackets копирует в буферы вызывающего, а не отдаёт срезы внутрь буфера
// читателя: это контракт §3.2, и это та же копия, которую понесёт реализация на
// Windows. Замер обязан её включать, иначе он мерит не то, что поедет.
type pipeDevice struct {
	r       *framing.Reader
	scratch [][]byte
	mtu     int

	mu sync.Mutex
	w  *framing.Writer
}

func newPipeDevice(p Pipe, back Pipe, mtu, batch int) *pipeDevice {
	return &pipeDevice{
		r:       framing.NewReader(p.R, 256<<10),
		w:       framing.NewWriter(back.W, batch*(mtu+framing.HeaderLen)+64),
		scratch: make([][]byte, batch),
		mtu:     mtu,
	}
}

func (d *pipeDevice) MTU() int { return d.mtu }

func (d *pipeDevice) ReadPackets(bufs [][]byte) (int, error) {
	if len(d.scratch) < len(bufs) {
		d.scratch = make([][]byte, len(bufs))
	}
	n, err := d.r.ReadBatch(d.scratch[:len(bufs)])
	for i := 0; i < n; i++ {
		bufs[i] = bufs[i][:copy(bufs[i][:cap(bufs[i])], d.scratch[i])]
	}
	return n, err
}

func (d *pipeDevice) WritePackets(bufs [][]byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.w.WriteBatch(bufs)
}

// devStack — «приложение и ядро» на дальней стороне границы: обычный gvisor с
// собственным адресом, который открывает соединения и шлёт по ним запросы.
//
// Своя реализация LinkEndpoint, а не link/channel: у channel исходящая очередь
// ограничена и молча роняет пакеты при переполнении, что в замере латентности
// выглядело бы как всплеск p99 неизвестного происхождения.
type devStack struct {
	s    *gstack.Stack
	dev  *pipeDevice
	link *devLink
	done chan struct{}
	wg   sync.WaitGroup
}

func newDevStack(dev *pipeDevice, addr netip.Addr) (*devStack, error) {
	d := &devStack{dev: dev, done: make(chan struct{})}
	d.link = &devLink{dev: dev, mtu: uint32(dev.MTU())}
	d.s = gstack.New(gstack.Options{
		NetworkProtocols:   []gstack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []gstack.TransportProtocolFactory{tcp.NewProtocol},
	})
	if err := d.s.CreateNIC(benchNIC, d.link); err != nil {
		return nil, fmt.Errorf("CreateNIC: %s", err)
	}
	pa := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(addr.As4()).WithPrefix(),
	}
	if err := d.s.AddProtocolAddress(benchNIC, pa, gstack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("AddProtocolAddress: %s", err)
	}
	d.s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: benchNIC}})

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.pump()
	}()
	return d, nil
}

func (d *devStack) pump() {
	mtu := d.dev.MTU()
	store := make([]byte, 64*mtu)
	bufs := make([][]byte, 64)
	for i := range bufs {
		bufs[i] = store[i*mtu : (i+1)*mtu]
	}
	for {
		for i := range bufs {
			bufs[i] = bufs[i][:mtu]
		}
		n, err := d.dev.ReadPackets(bufs)
		for _, p := range bufs[:n] {
			d.link.inject(p)
		}
		if err != nil {
			return
		}
	}
}

func (d *devStack) dial(dst netip.AddrPort) (*gonet.TCPConn, error) {
	return gonet.DialContextTCP(context.Background(), d.s, tcpip.FullAddress{
		NIC:  benchNIC,
		Addr: tcpip.AddrFrom4(dst.Addr().As4()),
		Port: dst.Port(),
	}, ipv4.ProtocolNumber)
}

func (d *devStack) close() {
	close(d.done)
	d.s.Close()
	d.s.Wait()
}

type devLink struct {
	dev *pipeDevice
	mtu uint32

	mu   sync.RWMutex
	disp gstack.NetworkDispatcher
	onCl func()
}

func (e *devLink) inject(pkt []byte) {
	e.mu.RLock()
	d := e.disp
	e.mu.RUnlock()
	if d == nil {
		return
	}
	pb := gstack.NewPacketBuffer(gstack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	d.DeliverNetworkPacket(header.IPv4ProtocolNumber, pb)
	pb.DecRef()
}

func (e *devLink) WritePackets(pkts gstack.PacketBufferList) (int, tcpip.Error) {
	list := pkts.AsSlice()
	views := make([]*buffer.View, 0, len(list))
	out := make([][]byte, 0, len(list))
	for _, pkt := range list {
		v := pkt.ToView()
		views = append(views, v)
		out = append(out, v.AsSlice())
	}
	err := e.dev.WritePackets(out)
	for _, v := range views {
		v.Release()
	}
	if err != nil {
		return 0, &tcpip.ErrClosedForSend{}
	}
	return len(list), nil
}

func (e *devLink) Attach(d gstack.NetworkDispatcher) {
	e.mu.Lock()
	e.disp = d
	e.mu.Unlock()
}

func (e *devLink) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.disp != nil
}

func (e *devLink) MTU() uint32                             { return e.mtu }
func (e *devLink) SetMTU(mtu uint32)                       { e.mtu = mtu }
func (e *devLink) MaxHeaderLength() uint16                 { return 0 }
func (e *devLink) LinkAddress() tcpip.LinkAddress          { return "" }
func (e *devLink) SetLinkAddress(tcpip.LinkAddress)        {}
func (e *devLink) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (e *devLink) AddHeader(*gstack.PacketBuffer)          {}
func (e *devLink) ParseHeader(*gstack.PacketBuffer) bool   { return true }
func (e *devLink) Wait()                                   {}
func (e *devLink) SetOnCloseAction(f func())               { e.mu.Lock(); e.onCl = f; e.mu.Unlock() }
func (e *devLink) Capabilities() gstack.LinkEndpointCapabilities {
	return gstack.CapabilityRXChecksumOffload
}

func (e *devLink) Close() {
	e.mu.RLock()
	f := e.onCl
	e.mu.RUnlock()
	if f != nil {
		f()
	}
}

// rig — стенд: граница, наш стек на стороне агента, обычный стек на стороне
// приложения.
// У устройства ровно один читатель — так же, как в продукте. Отсюда withClient:
// замеру RTT нужен стек-приложение на дальней стороне, а B3 читает устройство
// сам, и второй читатель растащил бы поток кадров пополам.
type rig struct {
	b         *Boundary
	agent     *netstack.Stack
	clientDev *pipeDevice
	client    *devStack
	dialer    *fakenet.Dialer
	clk       *clock.Fake
	runErr    chan error
}

func newRig(cfg NetstackConfig, autoEcho, withClient bool) (*rig, error) {
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1500
	}
	b, err := NewBoundary()
	if err != nil {
		return nil, err
	}

	agentDev := newPipeDevice(b.ServiceToAgent, b.AgentToService, mtu, 64)

	r := &rig{b: b, dialer: fakenet.NewDialer(autoEcho), clk: clock.NewFake(time.Unix(1, 0))}
	r.clientDev = newPipeDevice(b.AgentToService, b.ServiceToAgent, mtu, 64)
	r.agent, err = netstack.New(netstack.Config{
		Device:  agentDev,
		Dialer:  r.dialer,
		Clock:   r.clk,
		Healthy: func() bool { return true },
	})
	if err != nil {
		b.Close()
		return nil, err
	}
	r.runErr = make(chan error, 1)
	go func() { r.runErr <- r.agent.Run() }()

	if withClient {
		if r.client, err = newDevStack(r.clientDev, benchClient); err != nil {
			r.close()
			return nil, err
		}
	}
	return r, nil
}

func (r *rig) close() {
	if r.client != nil {
		r.client.close()
	}
	r.b.Close()
	if r.agent != nil {
		r.agent.Close()
	}
}

// NetstackRTT — базовая линия латентности поверх стека.
//
// Два числа, а не одно. Рукопожатие проходит весь путь этапа 3: вердикт по
// первому пакету, исходящее соединение, только потом SYN-ACK. Обмен на
// установленном соединении — то самое «интерактивный трафик мелкими пакетами»,
// ради которого замер и отложили с этапа 1.
func NetstackRTT(cfg NetstackConfig) ([]Result, error) {
	if cfg.Connects <= 0 {
		cfg.Connects = 200
	}
	if cfg.Exchanges <= 0 {
		cfg.Exchanges = 2000
	}
	if cfg.Payload <= 0 {
		cfg.Payload = 64
	}

	r, err := newRig(cfg, false, true)
	if err != nil {
		return nil, err
	}
	defer r.close()

	dst := netip.AddrPortFrom(benchServer, 80)

	// Рукопожатие.
	connects := make([]time.Duration, 0, cfg.Connects)
	cpu0 := processCPU()
	start := wall.Now()
	for i := 0; i < cfg.Connects; i++ {
		t0 := hiresNow()
		conn, err := r.client.dial(dst)
		if err != nil {
			return nil, fmt.Errorf("connect %d: %w", i, err)
		}
		connects = append(connects, hiresNow()-t0)
		conn.Close()
	}
	connectRes := latencyResult("L netstack connect", connects, wall.Now().Sub(start), processCPU()-cpu0, cfg.Payload)
	connectRes.Note = "рукопожатие: вердикт §3.4, исходящее соединение, потом SYN-ACK; " + crossingNote()

	// Обмен на установленном соединении.
	conn, err := r.client.dial(dst)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := make([]byte, cfg.Payload)
	for i := range req {
		req[i] = byte(i)
	}
	ack := make([]byte, cfg.Payload)

	rtts := make([]time.Duration, 0, cfg.Exchanges)
	cpu0 = processCPU()
	start = wall.Now()
	for i := 0; i < cfg.Exchanges; i++ {
		t0 := hiresNow()
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(conn, ack); err != nil {
			return nil, err
		}
		rtts = append(rtts, hiresNow()-t0)
	}
	exchangeRes := latencyResult("L netstack обмен", rtts, wall.Now().Sub(start), processCPU()-cpu0, cfg.Payload)
	exchangeRes.Note = "запрос-ответ на установленном соединении; " + crossingNote()

	return []Result{connectRes, exchangeRes}, nil
}

// crossingNote — почему число зависит от ОС. На Unix границу пересекает
// дескриптор, а не копия; на Windows за один RTT её пересекают дважды.
func crossingNote() string {
	return fmt.Sprintf("граница — %s, шаг часов %v", BoundaryName(), hiresResolution())
}

func latencyResult(name string, d []time.Duration, elapsed, cpu time.Duration, pkt int) Result {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return Result{
		Name: name, OS: osName(), Batch: 1, PktSize: pkt,
		Packets: int64(len(d)), Bytes: int64(len(d)) * int64(pkt),
		Wall: elapsed, CPU: cpu,
		P50: d[len(d)*50/100], P99: d[len(d)*99/100],
	}
}

// FullCone — B3 (§8.6): 500 одновременных исходящих UDP-портов, каждый на
// несколько адресов.
//
// Проверяется не скорость, а таблица: сколько записей заводится, сколько
// исходящих сокетов, сколько ответов не нашло записи и убывает ли всё это по
// простою. При nat_key=src+dst записей становится Fanout-кратно больше — это и
// есть «рост таблицы в B3».
func FullCone(cfg NetstackConfig) ([]Result, error) {
	if cfg.Ports <= 0 {
		cfg.Ports = 500
	}
	if cfg.Fanout <= 0 {
		cfg.Fanout = 3
	}
	if cfg.Rounds <= 0 {
		cfg.Rounds = 20
	}

	r, err := newRig(cfg, true, false) // autoEcho: каждый адрес отвечает сам
	if err != nil {
		return nil, err
	}
	defer r.close()

	mtu := r.clientDev.MTU()
	got := newCounter()
	go func() {
		store := make([]byte, 64*mtu)
		bufs := make([][]byte, 64)
		for i := range bufs {
			bufs[i] = store[i*mtu : (i+1)*mtu]
		}
		for {
			for i := range bufs {
				bufs[i] = bufs[i][:mtu]
			}
			n, err := r.clientDev.ReadPackets(bufs)
			got.add(n)
			if err != nil {
				got.stop()
				return
			}
		}
	}()

	peers := make([]netip.AddrPort, cfg.Fanout)
	for i := range peers {
		peers[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}), 9999)
	}
	payload := make([]byte, 64)

	w := framing.NewWriter(r.b.ServiceToAgent.W, 64*(mtu+framing.HeaderLen)+64)
	batch := make([][]byte, 0, 64)
	sent := 0

	cpu0 := processCPU()
	start := wall.Now()
	for round := 0; round < cfg.Rounds; round++ {
		for p := 0; p < cfg.Ports; p++ {
			src := netip.AddrPortFrom(benchClient, uint16(10000+p))
			for _, peer := range peers {
				batch = append(batch, packet.BuildUDP(src, peer, payload))
				if len(batch) == cap(batch) {
					if err := w.WriteBatch(batch); err != nil {
						return nil, err
					}
					sent += len(batch)
					batch = batch[:0]
				}
			}
		}
	}
	if len(batch) > 0 {
		if err := w.WriteBatch(batch); err != nil {
			return nil, err
		}
		sent += len(batch)
	}

	if err := got.wait(sent); err != nil {
		return nil, fmt.Errorf("ответов дошло меньше отправленного: %w", err)
	}
	elapsed := wall.Now().Sub(start)
	cpu := processCPU() - cpu0

	loaded := r.agent.Stats()

	// Простой: часы фейковые, поэтому «прошла минута» наступает мгновенно.
	// Уборка идёт на следующем пакете — своих горутин у таблицы нет.
	r.clk.Advance(5 * time.Minute)
	cold := netip.AddrPortFrom(benchClient, 60000)
	if err := w.WriteBatch([][]byte{packet.BuildUDP(cold, peers[0], payload)}); err != nil {
		return nil, err
	}
	if err := got.wait(sent + 1); err != nil {
		return nil, err
	}
	after := r.agent.Stats()

	res := Result{
		Name: "B3 UDP full-cone", OS: osName(), Batch: cfg.Fanout, PktSize: len(payload),
		Packets: int64(sent), Bytes: int64(sent) * int64(len(payload)),
		Wall: elapsed, CPU: cpu,
		Note: fmt.Sprintf(
			"%d портов × %d адресов × %d раундов; под нагрузкой: NAT-записей %d, сокетов %d, вердиктов %d, ответов без записи %d; после простоя: %d / %d / %d",
			cfg.Ports, cfg.Fanout, cfg.Rounds,
			loaded.NATEntries, loaded.NATSockets, loaded.Flows, loaded.NATOrphaned,
			after.NATEntries, after.NATSockets, after.Flows),
	}
	if loaded.NATOrphaned != 0 {
		return []Result{res}, fmt.Errorf("full-cone потерял %d ответов", loaded.NATOrphaned)
	}
	return []Result{res}, nil
}

// counter — сколько пакетов уже вернулось. Ожидание по условию, а не по
// времени: настоящее время живёт в internal/clock (§8.1), а зависший замер
// снимает таймаут вызывающего.
type counter struct {
	mu     sync.Mutex
	cond   *sync.Cond
	n      int
	closed bool
}

func newCounter() *counter {
	c := &counter{}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *counter) add(n int) {
	c.mu.Lock()
	c.n += n
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *counter) stop() {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *counter) wait(want int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.n < want {
		if c.closed {
			return errors.New("устройство закрылось")
		}
		c.cond.Wait()
	}
	return nil
}
