package netstack

import (
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/shafed/hop/internal/bypass"
	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/packettest"
)

// statSink — приёмник bypass, умеющий отдать счётчики. Числа заведомо разные и
// не похожие ни на что: перепутанные местами поля так видно, а с нулями и
// единицами — нет.
type statSink struct {
	sent int64
	st   bypass.Stats
}

func (s *statSink) Send([]byte) error { s.sent++; return nil }

func (s *statSink) Stats() bypass.Stats { return s.st }

// Снимок стека несёт счётчики приёмника bypass, и каждое число попадает в своё
// поле. Без подмешивания в Stack.Stats() три счётчика bypass.NAT видны только
// изнутри пакета bypass, то есть в продукте не видны вовсе.
func TestStackStatsFoldsBypassSinkCounters(t *testing.T) {
	sink := &statSink{st: bypass.Stats{Sockets: 7, Orphaned: 9, Rebound: 11}}
	h := newHarness(t, true, func(c *Config) { c.Bypass = sink })

	st := h.st.Stats()
	if st.BypassSockets != 7 || st.BypassOrphaned != 9 || st.BypassRebound != 11 {
		t.Fatalf("счётчики bypass в снимке: %+v, ожидались 7/9/11", st)
	}
}

// W49 (§5.8 регистра). Тот же фолд, но на настоящем bypass.NAT: утверждение
// здесь — что приёмник продукта действительно попадает в необязательный
// интерфейс. Проверка типа промахивается молча (нулями), и один только тест с
// подставным приёмником зеленел бы при разъехавшейся сигнатуре Stats.
//
// Заодно проверяется Rebound: он растёт не от трафика, а от смены интерфейса,
// и именно ради него счётчики выводятся наружу — «сеть в порядке» от
// «интерфейс мигает» отличимо только по нему.
func TestStackStatsSeesRealBypassNAT(t *testing.T) {
	listener := newLoopbackListener(t)
	listenerAddr := netip.MustParseAddrPort(listener.LocalAddr().String())

	var iface atomic.Value
	iface.Store("hop-eth0")

	nat, err := bypass.New(bypass.Config{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(uintptr) {})
		},
		Reply:     func([]byte) {},
		Clock:     clock.NewFake(time.Unix(1, 0)),
		Interface: func() (string, error) { return iface.Load().(string), nil },
	})
	if err != nil {
		t.Fatalf("bypass.New: %v", err)
	}
	t.Cleanup(nat.Close)

	h := newHarness(t, true, func(c *Config) { c.Bypass = nat })

	h.dev.Inject(packettest.UDP(client, listenerAddr, []byte("раз")))
	waitDatagram(t, listener)

	if st := h.st.Stats(); st.BypassSockets != 1 || st.BypassRebound != 0 {
		t.Fatalf("после первой датаграммы: %+v, ожидались 1 сокет и 0 передозвонов", st)
	}

	// Интерфейс сменился — следующая датаграмма закрывает старый сокет и
	// заводит новый (§6.8).
	iface.Store("hop-wlan0")
	h.dev.Inject(packettest.UDP(client, listenerAddr, []byte("два")))
	waitDatagram(t, listener)

	if st := h.st.Stats(); st.BypassSockets != 1 || st.BypassRebound != 1 {
		t.Fatalf("после смены интерфейса: %+v, ожидались 1 сокет и 1 передозвон", st)
	}
}

// Отказ TCP с вердиктом bypass отличим в снимке от fail-close. Оба увеличивают
// Rejected, и по одному этому числу «узлы мертвы» неотличимо от «узлы живы, но
// в локальную сеть потоком нельзя» — а это разные неисправности.
func TestStackStatsSeparatesBypassTCPRejectFromFailClose(t *testing.T) {
	live := newHarness(t, true)
	live.dev.Inject(packettest.TCPSyn(client, lanHost, 4242))
	live.dev.ExpectRST(t)

	if st := live.st.Stats(); st.Rejected != 1 || st.BypassTCPRejected != 1 {
		t.Fatalf("отказ bypass-TCP: %+v, ожидались Rejected=1 и BypassTCPRejected=1", st)
	}

	dead := newHarness(t, false)
	dead.dev.Inject(packettest.TCPSyn(client, web, 42))
	dead.dev.WaitEmitted(t, 1)

	if st := dead.st.Stats(); st.Rejected != 1 || st.BypassTCPRejected != 0 {
		t.Fatalf("fail-close: %+v, ожидались Rejected=1 и BypassTCPRejected=0", st)
	}
}

// newLoopbackListener — «локальная сеть» стенда: настоящий UDP-сокет на
// 127.0.0.1, куда приёмник bypass реально шлёт. Вердикт для loopback — Bypass
// (verdict.go, alwaysBypass), поэтому multicast для этого не нужен.
func newLoopbackListener(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("слушатель не поднялся: %v", err)
	}
	conn := pc.(*net.UDPConn)
	t.Cleanup(func() { conn.Close() })
	return conn
}

// waitDatagram ждёт одну датаграмму. Это точка синхронизации: насос устройства
// работает своей горутиной, и до прихода датаграммы сокета в NAT ещё может не
// быть.
func waitDatagram(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //hop:realtime
	buf := make([]byte, 1500)
	if _, _, err := conn.ReadFromUDP(buf); err != nil {
		t.Fatalf("датаграмма не дошла до локальной сети: %v", err)
	}
}
