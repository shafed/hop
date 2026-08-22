package netstack

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

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
}

func newTCPStack(s *Stack) (*tcpStack, error) {
	mtu := s.dev.MTU()
	if mtu <= 0 {
		mtu = 1500
	}

	t := &tcpStack{s: s}
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
		// Стартовое окно §5.6: SYN остаётся без ответа, клиент повторит его
		// сам. Complete(false) освобождает место в форвардере, не посылая RST.
		r.Complete(!errors.Is(err, ErrNotReady))
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
	stop := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	t.s.wg.Add(2)
	go func() {
		defer t.s.wg.Done()
		defer stop()
		_, _ = io.Copy(a, b)
	}()
	go func() {
		defer t.s.wg.Done()
		defer stop()
		_, _ = io.Copy(b, a)
	}()
}

// Границы одного соединения DNS поверх TCP.
const (
	// dnsStreamIdle — сколько соединение живёт без запросов. RFC 7766 §6.2.1
	// требует закрывать простаивающие соединения и называет «несколько секунд»
	// разумным сроком для сервера без сигнала edns-tcp-keepalive.
	dnsStreamIdle = 10 * time.Second
	// dnsStreamInFlight — сколько запросов одного соединения обслуживается
	// параллельно. Потолок есть потому, что конвейер RFC 7766 позволяет клиенту
	// прислать сколько угодно запросов, не читая ответов; сверх потолка мы
	// просто перестаём читать, и дальше клиента тормозит TCP-окно.
	dnsStreamInFlight = 64
	// dnsStreamMax — потолок сообщения: префикс длины двухбайтовый
	// (RFC 1035 §4.2.2).
	dnsStreamMax = 0xFFFF
)

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
	t.serveDNSStream(conn, f)
}

// serveDNSStream обслуживает одно соединение DNS поверх TCP. Возвращается
// сразу: работа живёт в горутинах, привязанных к wg стека.
//
// Три свойства, и каждое стоит своей сложности.
//
// Конвейер (RFC 7766 §6.2.1.1, D6). Ответы разрешено возвращать не в порядке
// запросов, и каждый запрос обслуживается своей горутиной, а не ждёт
// предыдущего: строгий порядок означал бы, что одно медленное имя держит всё
// соединение, то есть одно зависшее имя превращается в зависший DNS целиком.
// Цена — писателей в conn несколько, поэтому запись под замком и одним вызовом
// Write: два ответа, перемешанные в потоке байт, необратимо ломают разбор по
// префиксу длины у клиента.
//
// Таймаут простоя по clock.Clock, а не через SetReadDeadline (D7). Дедлайн
// сокета живёт в настоящем времени, и модельные часы его не двигают — §8.1 и
// требование 4 регистра. Отсюда разделение на читателя и распорядителя: чтение
// блокирующее и живёт в отдельной горутине, а срок выбирается селектом вместе с
// прочитанным; из блокирующего чтения читателя будит только закрытие conn — им
// таймаут и заканчивается.
//
// Порядок сдвига срока. Срок — это момент времени, и первый ставится здесь, до
// старта горутин, а следующий — на приёме запроса и **до** того, как ответ
// уйдёт клиенту. Это не косметика: проверка на фейковых часах, дождавшаяся
// ответа, тем самым знает, что срок уже сдвинут, и её Advance не пролетает мимо
// незаведённого таймера. Запрос в полёте срок не продлевает — бюджет
// клиентского запроса 5 с (§4 регистра), и десятисекундный срок его
// перекрывает.
func (t *tcpStack) serveDNSStream(conn net.Conn, f flow) {
	// Транспорт резолверу сообщается один раз на соединение, а не на запрос.
	stream, _ := t.s.cfg.Resolver.(StreamResolver)

	var once sync.Once
	closed := make(chan struct{})
	stop := func() {
		once.Do(func() {
			close(closed)
			_ = conn.Close()
		})
	}

	// Срок простоя живёт как момент времени, а таймер на соединение — ровно
	// один. Заводить новый After на каждом запросе было бы короче, но
	// clock.Clock не умеет отменять уже заведённое: на конвейере RFC 7766, где
	// клиент вправе прислать тысячи запросов подряд, это тысячи живых таймеров
	// на соединение (и столько же waiters у clock.Fake). Поэтому запрос двигает
	// только deadline, а сработавший таймер, увидев срок в будущем,
	// перезаводится на остаток. Цена — лишний оборот селекта раз в dnsStreamIdle
	// на живом соединении.
	deadline := t.s.cfg.Clock.Now().Add(dnsStreamIdle)
	idle := t.s.cfg.Clock.After(dnsStreamIdle)
	queries := make(chan []byte) // без буфера: читатель не забегает вперёд

	t.s.wg.Add(2)
	go t.readDNSStream(conn, queries, closed, stop)
	go func() {
		defer t.s.wg.Done()
		defer stop()

		var wmu sync.Mutex
		slots := make(chan struct{}, dnsStreamInFlight)
		for {
			select {
			case query := <-queries:
				deadline = t.s.cfg.Clock.Now().Add(dnsStreamIdle)
				select {
				case slots <- struct{}{}:
				case <-closed:
					return
				case <-t.s.done:
					return
				}
				t.s.wg.Add(1)
				go func() {
					defer t.s.wg.Done()
					defer func() { <-slots }()
					t.answerDNSStream(conn, &wmu, stream, query, f, stop)
				}()
			case <-idle:
				// Остаток отсчитывается от Now, а не от времени срабатывания:
				// After отмеряет от текущего момента, и сложить его со временем
				// срабатывания значило бы отодвинуть срок на то, на что часы
				// успели уйти вперёд.
				if rest := deadline.Sub(t.s.cfg.Clock.Now()); rest > 0 {
					idle = t.s.cfg.Clock.After(rest)
					continue
				}
				return // stop() в defer: простой освобождает и горутины, и conn
			case <-closed:
				return
			case <-t.s.done:
				return
			}
		}
	}()
}

// readDNSStream разбирает поток на сообщения. Отдельная горутина именно потому,
// что ReadFull блокирующий: селект распорядителя с ним не совмещается.
func (t *tcpStack) readDNSStream(conn net.Conn, queries chan<- []byte, closed <-chan struct{}, stop func()) {
	defer t.s.wg.Done()
	defer stop()

	var hdr [2]byte
	for {
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		select {
		case queries <- query:
		case <-closed:
			return
		}
	}
}

// answerDNSStream отвечает на один запрос и кладёт ответ в поток целиком.
func (t *tcpStack) answerDNSStream(conn net.Conn, wmu *sync.Mutex, stream StreamResolver, query []byte, f flow, stop func()) {
	var (
		answer []byte
		err    error
	)
	if stream != nil {
		answer, err = stream.QueryStream(query, f.src, f.dst)
	} else {
		answer, err = t.s.cfg.Resolver.Query(query, f.src, f.dst)
	}
	if err != nil || len(answer) == 0 || len(answer) > dnsStreamMax {
		// Резолвер выражает отказ кодом ответа, а не ошибкой (§5.6), поэтому
		// ошибка здесь — поломка, а не ответ, и сказать её клиенту в потоке
		// нечем. Закрываем соединение: обрыв клиент заметит и повторит, а
		// молчание в открытом потоке он от медленного ответа не отличит. Цена —
		// вместе с этим ответом теряются и соседние, ещё летящие.
		stop()
		return
	}

	out := make([]byte, 2+len(answer))
	binary.BigEndian.PutUint16(out[:2], uint16(len(answer)))
	copy(out[2:], answer)

	// Один Write на сообщение и под замком: см. цену конвейера в serveDNSStream.
	wmu.Lock()
	_, werr := conn.Write(out)
	wmu.Unlock()
	if werr != nil {
		stop()
	}
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
