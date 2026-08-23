// Package netstack — «PacketDevice → потоки TCP/UDP, вердикт на первом пакете»
// из §3.4.
//
// Устройство читает один насос. По первому пакету потока принимается вердикт в
// порядке §3.4 — hijack-dns → bypass → reject → proxy, — и дальше пакет идёт по
// своей ветке:
//
//	hijack-dns  → Resolver (на этапе 3 — заглушка, настоящий резолвер — этап 6)
//	bypass      → Bypass, мимо туннеля (§6.10)
//	reject      → internal/reject, тот же код, что обслуживает orphaned (§6.2)
//	proxy       → Dialer (на этапе 3 — фейк, на этапе 4 — core.Dial/core.DialUDP)
//
// Кто чем занят. TCP терминируется gvisor (`tcpip`): нужна машина состояний,
// окна и сборка потока. UDP не проходит через gvisor вовсе: его forwarder
// отдаёт **connected**-эндпоинт на пару (src, dst), то есть NAT по паре, а §5.3
// требует full-cone по source addr:port. Подробности и цена — в «Deviations».
package netstack

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/packet"
	"github.com/shafed/hop/internal/policy"
	"github.com/shafed/hop/internal/reject"
)

// ErrNotReady — «узла ещё нет, но это незнание, а не отказ».
//
// Диалер возвращает её в стартовом окне §5.6: ни один узел не проверен, бюджет
// не истёк. Стек тогда не отвечает на SYN вовсе — ни рукопожатием, ни RST, — и
// клиент повторяет его сам. Это и есть «трафик ждёт» из §5.6, причём даром:
// ожидание держит TCP клиента, а не наша горутина.
//
// Отвечать RST здесь нельзя: §5.6 называет ровно этот отказ («иначе первое же
// приложение получает RST в те секунды, пока идёт стартовый обход подписки»).
// Блокировать диалер тоже нельзя: он вызывается из обработчика форвардера,
// то есть с цикла чтения устройства, и ожидание в нём остановило бы весь
// туннель. Молчание здесь не нарушает §5.6: тот запрещает молчание там, где
// решение принято, а здесь оно ещё не принято.
var ErrNotReady = errors.New("netstack: живого узла ещё нет, стартовое окно")

// Dialer — исходящее. На этапе 3 это фейк за интерфейсом; на этапе 4 сюда
// встают core.Dial и core.DialUDP (`core/functions.go:49`, `:76`).
//
// DialUDP получает **исходный** адрес клиента, а не назначение: core.DialUDP
// отдаёт net.PacketConn, один на исходный порт, и это ровно то, из чего
// получается full-cone (§5.3). Типы возврата — стандартные net.Conn и
// net.PacketConn, чтобы этап 4 был подстановкой, а не переписыванием.
type Dialer interface {
	DialTCP(dst netip.AddrPort) (net.Conn, error)
	DialUDP(src netip.AddrPort) (net.PacketConn, error)
}

// Resolver — перехваченный DNS (§5.7). Этап 3 доводит запрос до заглушки;
// настоящий резолвер, кэш и bootstrap — этап 6.
type Resolver interface {
	// Query отвечает на DNS-запрос. server — адрес, на который клиент слал:
	// ответ обязан прийти именно с него, иначе резолвер клиента его не примет.
	Query(query []byte, client, server netip.AddrPort) ([]byte, error)
}

// StreamResolver — резолвер, знающий, что клиент пришёл потоком.
//
// Клиенту по UDP ответ длиннее его буфера EDNS0 вернуть нельзя — ему уходит
// флаг TC (§5.7, У4 регистра); клиенту по TCP тот же ответ можно и нужно отдать
// целым RRset. Различить эти два случая обязан резолвер, а Query транспорта не
// несёт. Интерфейс Resolver заморожен с этапа 3, поэтому знание о транспорте
// приезжает отдельным интерфейсом: объявил метод — зовём его, не объявил —
// прежний Query. Тот же приём, что у FlushableResolver в связке.
type StreamResolver interface {
	Resolver
	QueryStream(query []byte, client, server netip.AddrPort) ([]byte, error)
}

// BypassSink — то, что уходит мимо туннеля, в локальную сеть (§6.10).
//
// В продукте таких пакетов на устройстве нет вовсе: исключения выражены
// правилами маршрутизации выше туннельного и в таблицу туннеля не заходят
// (§6.2). Здесь второй рубеж — на случай, если правило не встало.
//
// Срез действителен только на время вызова.
type BypassSink interface {
	Send(pkt []byte) error
}

// Config — всё, от чего зависит стек.
type Config struct {
	Device   packet.PacketDevice
	Dialer   Dialer
	Resolver Resolver
	Bypass   BypassSink
	Clock    clock.Clock

	// Healthy — есть ли живой узел (§5.6). На этапе 5 сюда придёт health.
	// nil означает «нет»: fail-close — консервативная сторона.
	Healthy func() bool

	// FlowIdle, UDPIdle — сколько запись живёт без трафика.
	FlowIdle time.Duration
	UDPIdle  time.Duration
}

// Стартовые значения. Потоку TCP хватает минуты простоя, чтобы вердикт по нему
// можно было забыть: сам поток к этому моменту держит gvisor.
const (
	defaultFlowIdle = 2 * time.Minute
	defaultUDPIdle  = 60 * time.Second
	readBatch       = 64
)

// Stats — наблюдаемость. Числа нужны B3 и тестам: «NAT-таблица не деградирует
// и не течёт» проверяется только счётчиками.
type Stats struct {
	Flows       int   // живых вердиктов
	NATEntries  int   // записей NAT
	NATSockets  int   // исходящих UDP-сокетов (один на исходный порт)
	Blocked     int64 // дропнуто по §6.9/§6.10
	Rejected    int64 // отвечено отказом
	NATOrphaned int64 // ответов, не нашедших записи NAT
}

// Stack — netstack поверх одного PacketDevice.
type Stack struct {
	cfg Config
	dev packet.PacketDevice

	wmu sync.Mutex // единственный писатель в устройство

	flows *flowTable
	nat   *natTable
	tcp   *tcpStack

	mu       sync.Mutex
	blocked  int64
	rejected int64

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// New собирает стек. Устройство не читается, пока не позван Run.
func New(cfg Config) (*Stack, error) {
	if cfg.Device == nil {
		return nil, errors.New("netstack: нет устройства")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.Healthy == nil {
		cfg.Healthy = func() bool { return false }
	}
	if cfg.FlowIdle <= 0 {
		cfg.FlowIdle = defaultFlowIdle
	}
	if cfg.UDPIdle <= 0 {
		cfg.UDPIdle = defaultUDPIdle
	}

	s := &Stack{
		cfg:   cfg,
		dev:   cfg.Device,
		flows: newFlowTable(cfg.Clock, cfg.FlowIdle),
		done:  make(chan struct{}),
	}
	s.nat = newNATTable(s, cfg.Clock, cfg.UDPIdle)
	t, err := newTCPStack(s)
	if err != nil {
		return nil, err
	}
	s.tcp = t
	return s, nil
}

// Run гоняет насос до закрытия устройства.
func (s *Stack) Run() error {
	mtu := s.dev.MTU()
	if mtu <= 0 {
		mtu = 1500
	}
	store := make([]byte, readBatch*mtu)
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = store[i*mtu : (i+1)*mtu]
	}

	for {
		for i := range bufs {
			bufs[i] = bufs[i][:mtu]
		}
		n, err := s.dev.ReadPackets(bufs)
		for _, p := range bufs[:n] {
			s.handle(p)
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			return err
		}
	}
}

// Close снимает стек: NAT-сокеты закрываются, релеи расходятся.
func (s *Stack) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.nat.close()
		s.tcp.close()
	})
	s.wg.Wait()
}

// InterruptTCP рвёт все сейчас открытые проксируемые TCP-соединения и
// возвращает их число (§5.5). Живость зовёт его через health.Config.Interrupt
// ровно при reason: dead, после того как Active() уже отдаёт новый узел —
// внутри решать «чьи» соединения рвать не нужно: узел соединения фиксирован
// на дозвоне и не меняется (Р30, internal/agent/dialer.go).
func (s *Stack) InterruptTCP() int {
	return s.tcp.closeAll()
}

// Stats — снимок счётчиков.
func (s *Stack) Stats() Stats {
	s.mu.Lock()
	st := Stats{Blocked: s.blocked, Rejected: s.rejected}
	s.mu.Unlock()
	st.Flows = s.flows.len()
	st.NATEntries, st.NATSockets, st.NATOrphaned = s.nat.stats()
	return st
}

// handle — один пакет. Срез живёт только до следующего чтения, поэтому всё,
// что уходит дальше насоса, копируется на месте.
func (s *Stack) handle(pkt []byte) {
	f, ok := parse(pkt)
	if !ok {
		// Сюда попадает и IPv6: §6.9 блокирует его, потому что частично
		// поднятый IPv6 хуже отсутствующего — трафик утекает молча.
		s.count(&s.blocked)
		return
	}

	switch s.flows.verdict(f, s.cfg.Healthy) {
	case HijackDNS:
		if f.proto == uint8(header.UDPProtocolNumber) {
			s.hijackUDP(f, udpPayload(pkt))
			return
		}
		s.tcp.inject(pkt) // DNS поверх TCP: поток надо сначала терминировать
	case Bypass:
		// Отказ Send (ErrDisabled, ErrUnsupported, ошибка сокета — включая
		// outbound.ErrNoInterface, «нет физического интерфейса, честнее
		// отказать, чем зациклить») — это дроп, а не тишина: doc-комментарий
		// Stats.Blocked («дропнуто по §6.9/§6.10») уже покрывает этот случай.
		if s.cfg.Bypass == nil {
			s.count(&s.blocked)
		} else if err := s.cfg.Bypass.Send(pkt); err != nil {
			s.count(&s.blocked)
		}
	case Block:
		s.count(&s.blocked)
	case Reject:
		// Тот же internal/reject, что обслуживает orphaned в сервисе (§6.2).
		// Политика §8: при reject_mode=drop ответа нет, и приложение висит до
		// таймаута — ровно это краснит T12 и T13.
		if !policy.RejectMode.On() {
			return
		}
		if r := reject.Reply(pkt); r != nil {
			s.count(&s.rejected)
			s.write(r)
		}
	case Proxy:
		if f.proto == uint8(header.UDPProtocolNumber) {
			s.nat.send(f, udpPayload(pkt))
			return
		}
		s.tcp.inject(pkt)
	}
}

// Deliver отдаёт клиенту готовый пакет из обратного пути bypass-NAT (§6.10).
// Единственный писатель в устройство остаётся один: Deliver идёт через тот же
// s.write, что ответы natTable и релеи gvisor.
func (s *Stack) Deliver(pkt []byte) { s.write(pkt) }

// write — единственный путь в устройство: писателей несколько (насос, релеи
// gvisor, ответы NAT), устройство одно.
func (s *Stack) write(pkts ...[]byte) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_ = s.dev.WritePackets(pkts)
}

func (s *Stack) count(p *int64) {
	s.mu.Lock()
	*p++
	s.mu.Unlock()
}

// parse достаёт из IPv4-пакета то, чего хватает вердикту. Всё остальное —
// не наше дело: фрагменты, IPv6, мусор.
func parse(pkt []byte) (flow, bool) {
	if len(pkt) < header.IPv4MinimumSize {
		return flow{}, false
	}
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) || ip.HeaderLength() < header.IPv4MinimumSize || ip.FragmentOffset() != 0 {
		return flow{}, false
	}
	src, ok1 := netip.AddrFromSlice(ip.SourceAddressSlice())
	dst, ok2 := netip.AddrFromSlice(ip.DestinationAddressSlice())
	if !ok1 || !ok2 {
		return flow{}, false
	}

	f := flow{proto: ip.Protocol()}
	payload := ip.Payload()
	switch f.proto {
	case uint8(header.TCPProtocolNumber):
		if len(payload) < header.TCPMinimumSize {
			return flow{}, false
		}
		t := header.TCP(payload)
		f.src = netip.AddrPortFrom(src, t.SourcePort())
		f.dst = netip.AddrPortFrom(dst, t.DestinationPort())
	case uint8(header.UDPProtocolNumber):
		if len(payload) < header.UDPMinimumSize {
			return flow{}, false
		}
		u := header.UDP(payload)
		f.src = netip.AddrPortFrom(src, u.SourcePort())
		f.dst = netip.AddrPortFrom(dst, u.DestinationPort())
	default:
		f.src = netip.AddrPortFrom(src, 0)
		f.dst = netip.AddrPortFrom(dst, 0)
	}
	return f, true
}

// udpPayload возвращает полезную нагрузку UDP-датаграммы.
func udpPayload(pkt []byte) []byte {
	ip := header.IPv4(pkt)
	u := header.UDP(ip.Payload())
	if len(u) < header.UDPMinimumSize {
		return nil
	}
	return u.Payload()
}
