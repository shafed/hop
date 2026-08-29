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

// InterfaceFunc — имя текущего физического интерфейса по умолчанию (§6.8).
// В продукте это outbound.Selector.Interface: тот же rtnetlink-наблюдатель,
// чей ответ Control кладёт свежему сокету в SO_BINDTODEVICE. Форма совпадает с
// engine.InterfaceFunc — связка передаёт сюда ровно то же значение
// (agent.Config.Physical).
type InterfaceFunc func() (string, error)

// Config — всё, от чего зависит NAT.
type Config struct {
	Control ControlFunc      // обязателен
	Reply   func(pkt []byte) // обратный путь: собранный IPv4/UDP-пакет в туннель
	Clock   clock.Clock      // nil → clock.System{}
	Idle    time.Duration    // 0 → 60 с, как netstack.defaultUDPIdle
	// Interface — чем NAT узнаёт, что интерфейс сменился («следствие первое»
	// §6.8). Не обязателен: nil означает «сравнивать не с чем», и сокеты
	// живут как до этой политики — до Idle или до Close. Обязательным не
	// сделан намеренно, потому что Config.Bypass у связки старше и тесты
	// подставляют NAT без всякого физического интерфейса; проводку в
	// продукте держит отдельная проверка шва (W47).
	Interface InterfaceFunc
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
	// iface — имя интерфейса, к которому Control привязал этот сокет.
	// Привязка неизменна (§6.8), поэтому поле пишется один раз при создании
	// и дальше только сравнивается с нынешним интерфейсом.
	iface string
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
	rebound  int64
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
	// Опрос интерфейса — до захвата n.mu: колбэк чужой (в продукте это
	// outbound.Selector под своим RWMutex), и звать его под своим замком
	// незачем.
	iface, known := n.currentInterface()

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, errClosed
	}

	now := n.clk.Now()
	n.sweepLocked(now)
	if known {
		n.rebindLocked(iface)
	}

	if sock, ok := n.socks[src]; ok {
		sock.seen = now
		return sock, nil
	}

	conn, err := (&net.ListenConfig{Control: n.cfg.Control}).ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		return nil, err
	}
	// iface здесь — то, что Interface вернул на входе в socketFor, а Control
	// внутри ListenPacket спросил его ещё раз. Разойтись они могут только
	// если интерфейс сменился ровно между этими двумя чтениями; тогда
	// следующий Send закроет свежий сокет как устаревший. Лишний передозвон
	// раз в жизни такого совпадения дешевле, чем блокировка на время
	// ListenPacket. При known == false здесь пусто — так currentInterface и
	// отвечает.
	sock := &socket{conn: conn, src: src, seen: now, iface: iface}
	n.socks[src] = sock
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.receive(sock)
	}()
	return sock, nil
}

// currentInterface — нынешний исходящий интерфейс и признак того, что ответ
// вообще получен. Ложь означает «сравнивать не с чем»: колбэка нет либо
// default route сейчас нет вовсе. Второе — законное переходное состояние
// ноутбука (§6.8, outbound.New), и рвать по нему живой сокет значило бы
// превращать мгновенную неготовность в жёсткий отказ.
func (n *NAT) currentInterface() (string, bool) {
	if n.cfg.Interface == nil {
		return "", false
	}
	name, err := n.cfg.Interface()
	if err != nil || name == "" {
		return "", false
	}
	return name, true
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

// rebindLocked закрывает сокеты, привязанные не к нынешнему исходящему
// интерфейсу. «Следствие первое» §6.8: привязка свежего сокета неизменна —
// перепривязать его нельзя даже с правами, поэтому смена сети означает
// передозвон, а не переустановку SO_BINDTODEVICE. Следующий Send заведёт
// сокет заново, уже с нынешней привязкой.
//
// Закрываются все чужие по привязке сокеты, а не только тот, за которым
// пришли. Событие общее: интерфейс сменился для всей машины, и оставленный
// сокет продолжал бы не только слать через прежний интерфейс, но и принимать
// на нём ответы своей горутиной receive, отдавая их в туннель.
//
// Уборка простоя тут ни при чём и заменить это не может: sock.seen
// обновляется на каждый Send, и клиент, ретраящий обнаружение служб, держит
// мёртвый по привязке сокет вечно молодым.
//
// Пустое sock.iface означает «привязка неизвестна» — так выглядит сокет,
// заведённый без Config.Interface. Сравнивать его не с чем, и трогать его
// нельзя: это в точности прежнее поведение, которое Config.Interface == nil и
// обещает.
func (n *NAT) rebindLocked(iface string) {
	if !policy.BypassRebind.On() {
		return
	}
	for src, sock := range n.socks {
		if sock.iface == "" || sock.iface == iface {
			continue
		}
		delete(n.socks, src)
		_ = sock.conn.Close()
		n.rebound++
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
	// Rebound — сколько сокетов закрыто из-за того, что их интерфейс перестал
	// быть исходящим (§6.8, политика bypass_rebind). Растущее значение при
	// стоящей сети означало бы, что Interface отвечает неустойчиво.
	Rebound int64
}

// Stats — чистый снимок: читает и ничего не меняет. Уборка простоя едет
// только на Send.
//
// Раньше Stats попутно прокручивала уборку, и доводом было «то же совмещение,
// что у natTable.Stats()». Довод был неверен вдвойне. natTable.stats()
// (internal/netstack/udp.go) — чистое чтение под замком, а принудительная
// прокрутка у неё вынесена в отдельный natTable.Sweep(); замер B3 так и
// поступает — двигает часы и шлёт ещё один пакет, а не надеется на снимок.
// Второе: пока Stats никто не звал, совмещение было безвредным, но теперь его
// подмешивает Stack.Stats() — и наблюдение стало бы менять наблюдаемое. Время
// жизни сокета зависело бы от того, открыт ли у пользователя экран состояния,
// а половинки одного снимка означали бы разное: числа natTable — «на момент
// последнего пакета», числа bypass — «на сейчас».
//
// Цена решения названа: после того как трафик прекратился, сокеты bypass
// доживают до Close. Это ровно та же участь, что у natTable, и закрывается она
// фоновым тикером — то есть поведением, которому по правилам этого репозитория
// полагается свой флаг и свой краснеющий тест, а не побочным эффектом геттера.
func (n *NAT) Stats() Stats {
	n.mu.Lock()
	defer n.mu.Unlock()
	return Stats{Sockets: len(n.socks), Orphaned: n.orphaned, Rebound: n.rebound}
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
