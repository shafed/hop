package agent

import (
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/packettest"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/tunnel"
)

// TestBypassSocketRebindsOnInterfaceChange — W47, шов Config.Physical →
// bypass.Config.Interface. Модульная проверка того же механизма живёт в
// internal/bypass; здесь проверяется ровно проброс: без него весь механизм
// в продукте мёртв при зелёном модульном тесте, потому что NAT сравнивать
// будет не с чем (bypass.Config.Interface не обязателен).
//
// Наблюдаемое — исходный порт, с которым датаграмма приходит слушателю на
// loopback: смена порта означает, что сокет NAT переоткрыт. Клиент не
// замолкает между инъекциями, поэтому уборка простоя объяснить смену не может.
func TestBypassSocketRebindsOnInterfaceChange(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("слушатель не поднялся: %v", err)
	}
	defer pc.Close()
	listener := pc.LocalAddr().(*net.UDPAddr).AddrPort()

	from := make(chan int, 8)
	go func() {
		buf := make([]byte, 1500)
		for {
			_, peer, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case from <- peer.(*net.UDPAddr).Port:
			default:
			}
		}
	}()

	// Физический интерфейс, который можно сменить на ходу: в продукте это
	// outbound.Selector под своим rtnetlink-наблюдателем.
	var mu sync.Mutex
	name := "wlan0"
	physical := func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		return name, nil
	}

	control := func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(uintptr) {})
	}

	clk := clock.NewFake(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	st, err := store.Open(t.TempDir(), clk)
	if err != nil {
		t.Fatalf("стор не открылся: %v", err)
	}
	tr := newFakeTransport()

	a, err := New(Config{
		Store:         st,
		Health:        health.New(health.Config{Clock: clk}),
		Trans:         tr,
		Clock:         clk,
		Params:        tunnel.Params{Name: "hop0", MTU: 1400, Addr: "10.255.0.1/24", Table: 8420},
		Physical:      physical,
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
	defer func() { _ = a.Down() }()

	dev := tr.device()
	inject := func(payload string) int {
		t.Helper()
		dev.Inject(packettest.UDP(bypassClient, listener, []byte(payload)))
		select {
		case port := <-from:
			return port
		case <-time.After(packettest.WaitTimeout): //hop:realtime
			t.Fatalf("слушатель не получил %q за отведённое время", payload)
			return 0
		}
	}

	first := inject("запрос по wlan0")
	if again := inject("второй запрос по wlan0"); again != first {
		t.Fatalf("сокет сменился (порт %d → %d) при неизменном интерфейсе", first, again)
	}

	mu.Lock()
	name = "eth0"
	mu.Unlock()

	if after := inject("запрос после смены интерфейса"); after == first {
		t.Fatalf("сокет остался прежним (порт %d) после смены интерфейса: "+
			"Config.Physical до bypass.Config.Interface не доходит", after)
	}
}
