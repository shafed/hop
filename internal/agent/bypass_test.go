package agent

import (
	"bytes"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/packet"
	"github.com/shafed/hop/internal/packettest"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/tunnel"
)

// client — адрес приложения на туннельном интерфейсе, тот же, что шлёт
// пакеты в internal/netstack/netstack_test.go.
var bypassClient = netip.MustParseAddrPort("10.255.0.2:5000")

// TestBypassSinkCarriesDatagramAndReply — сквозная проверка проводки
// agent → netstack → bypass.NAT → физический сокет → обратно (§6.10, §6.8),
// на фейковом устройстве, без прав и без netns (задача 3 доказывает то же
// самое с настоящим физическим интерфейсом в netns).
//
// Адрес назначения — loopback: вердикт для него Bypass без всякого multicast
// (isBypass, a.IsLoopback()), а датаграмма при этом реально доходит до
// слушателя на 127.0.0.1. Multicast-путь (mDNS/SSDP) эта проверка не несёт —
// он L3 и проверяется задачей 3.
func TestBypassSinkCarriesDatagramAndReply(t *testing.T) {
	// Слушатель на loopback, отвечающий на всё, что получил, — та самая
	// "локальная сеть", в которую должен выпустить bypass-NAT.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("слушатель не поднялся: %v", err)
	}
	defer pc.Close()
	listener := pc.LocalAddr().(*net.UDPAddr).AddrPort()

	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			got := append([]byte(nil), buf[:n]...)
			select {
			case received <- got:
			default:
			}
			if _, err := pc.WriteTo(got, from); err != nil {
				return
			}
		}
	}()

	// Считающая обёртка вместо nil: тест обязан доказать, что Control
	// действительно позвали, а не что вызов молча пропущен.
	var controlCalls atomic.Int64
	control := func(_, _ string, c syscall.RawConn) error {
		controlCalls.Add(1)
		return c.Control(func(uintptr) {})
	}

	clk := clock.NewFake(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	st, err := store.Open(t.TempDir(), clk)
	if err != nil {
		t.Fatalf("стор не открылся: %v", err)
	}
	tr := newFakeTransport()

	// Без Config.Bypass — приёмник обязана собрать сама связка из
	// Config.BypassControl (задача 2). NewXray — фейк, тот же, что заводит
	// newRig: связка в этом пакете не поднимает настоящий Xray нигде
	// (harness_test.go), а нулевой набор узлов, при котором реальный Xray
	// сегодня стартовал бы тихо и дёшево, — случайность, а не гарантия.
	a, err := New(Config{
		Store:         st,
		Health:        health.New(health.Config{Clock: clk}),
		Trans:         tr,
		Clock:         clk,
		Params:        tunnel.Params{Name: "hop0", MTU: 1400, Addr: "10.255.0.1/24", Table: 8420},
		BypassControl: control,
		NewXray:       (&xrayLog{}).factory(),
	})
	if err != nil {
		t.Fatalf("связка не собралась: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	if err := a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	dev := tr.device()
	payload := []byte("_services._dns-sd._udp.local")
	dev.Inject(packettest.UDP(bypassClient, listener, payload))

	select {
	case got := <-received:
		if !bytes.Equal(got, payload) {
			t.Fatalf("слушатель получил %q, ожидалось %q", got, payload)
		}
	case <-time.After(packettest.WaitTimeout): //hop:realtime
		t.Fatal("слушатель не получил нагрузку за отведённое время")
	}

	pkts := dev.WaitEmitted(t, 1)
	src, dst, reply, ok := packet.ParseUDP4(pkts[0])
	if !ok {
		t.Fatalf("ответный пакет не разобрался как IPv4/UDP: % x", pkts[0])
	}
	if src != listener {
		t.Fatalf("src ответа %v, ожидался адрес слушателя %v", src, listener)
	}
	if dst != bypassClient {
		t.Fatalf("dst ответа %v, ожидался адрес клиента %v", dst, bypassClient)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatalf("нагрузка ответа %q, ожидалось эхо %q", reply, payload)
	}

	if n := controlCalls.Load(); n == 0 {
		t.Fatal("BypassControl ни разу не позван: сокет bypass-NAT не привязывался")
	}

	if err := a.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
}
