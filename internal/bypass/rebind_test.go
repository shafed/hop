package bypass

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/packettest"
)

// errNoInterfaceForTest — местный двойник outbound.ErrNoInterface. Настоящий
// не импортируется намеренно: internal/bypass о платформенном пакете не знает
// и знать не должен, а важна здесь только форма ответа «интерфейса нет».
var errNoInterfaceForTest = errors.New("физический интерфейс по умолчанию не определён")

// physicalInterface — подмена outbound.Selector.Interface: имя исходящего
// интерфейса, которое можно поменять на ходу, ровно как это делает
// rtnetlink-наблюдатель селектора при переключении Wi-Fi → Ethernet.
type physicalInterface struct {
	mu   sync.Mutex
	name string
	err  error
}

func (p *physicalInterface) get() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.name, p.err
}

func (p *physicalInterface) set(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.name, p.err = name, nil
}

func (p *physicalInterface) fail(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.name, p.err = "", err
}

// sendFrom шлёт датаграмму через NAT и возвращает исходный порт, с которого
// её увидел слушатель, — то есть эфемерный порт сокета NAT. Смена этого порта
// и есть наблюдаемое «сокет переоткрылся»: настоящую привязку без настоящего
// второго интерфейса не увидеть (это делает L3, T31), а порт виден на любой
// машине.
func sendFrom(t *testing.T, n *NAT, listener *net.UDPConn, payload string) int {
	t.Helper()
	dst := addrPortOf(t, listener.LocalAddr())
	if err := n.Send(packettest.UDP(client, dst, []byte(payload))); err != nil {
		t.Fatalf("Send(%q): %v", payload, err)
	}
	buf := make([]byte, 1500)
	listener.SetReadDeadline(time.Now().Add(readTimeout)) //hop:realtime
	read, from, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("%q не дошло до слушателя: %v", payload, err)
	}
	if got := string(buf[:read]); got != payload {
		t.Fatalf("слушатель получил %q, ожидалось %q", got, payload)
	}
	return from.Port
}

// TestBypassInterfaceChangeRebindsSocket — охраняющая проверка bypass_rebind.
// «Следствие первое» §6.8: привязка сокета неизменна, поэтому смена сети
// означает не перепривязку, а передозвон. Сокет, привязанный к интерфейсу,
// который больше не исходящий, обязан перестать использоваться.
//
// Часы стоят намеренно. sweepLocked не срабатывает вовсе, пока часы не
// сдвинулись, так что зелёный этой проверки нельзя объяснить уборкой простоя:
// собрать сокет тут просто некому, кроме проверяемого механизма. Клиент при
// этом не замолкает ни на шаг — шлёт до смены, шлёт после, — потому что
// замолчавший клиент дал бы ровно ту ложную зелень, ради исключения которой
// часы и остановлены.
func TestBypassInterfaceChangeRebindsSocket(t *testing.T) {
	listener := newListener(t)
	clk := clock.NewFake(time.Unix(0, 0))
	iface := &physicalInterface{name: "wlan0"}

	var calls int32
	n, err := New(Config{
		Control:   countingControl(&calls),
		Interface: iface.get,
		Reply:     func([]byte) {},
		Clock:     clk,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.Close()

	first := sendFrom(t, n, listener, "запрос по wlan0")

	// Интерфейс тот же — сокет обязан остаться тем же: механизм не имеет
	// права срабатывать без причины, иначе он неотличим от «переоткрывать
	// сокет на каждый пакет», и NAT перестаёт быть NAT'ом.
	if again := sendFrom(t, n, listener, "второй запрос по wlan0"); again != first {
		t.Fatalf("сокет сменился (порт %d → %d) при неизменном интерфейсе", first, again)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("Control позван %d раз(а) до смены интерфейса, ожидался 1", got)
	}

	iface.set("eth0") // Wi-Fi → Ethernet; клиент продолжает слать

	after := sendFrom(t, n, listener, "запрос после смены интерфейса")
	if after == first {
		t.Fatalf("сокет остался прежним (порт %d) после смены интерфейса: "+
			"привязка §6.8 указывает на wlan0, туда же уходит и трафик", after)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("Control позван %d раз(а), ожидалось 2 — свежая привязка к eth0", got)
	}
	stats := n.Stats()
	if stats.Rebound != 1 {
		t.Fatalf("Rebound = %d, ожидался 1", stats.Rebound)
	}
	if stats.Sockets != 1 {
		t.Fatalf("Sockets = %d, ожидался 1: прежний закрыт, новый заведён", stats.Sockets)
	}
	if got := clk.Now(); !got.Equal(time.Unix(0, 0)) {
		t.Fatalf("часы сдвинулись на %v — в дело могла вмешаться уборка простоя, "+
			"и проверка перестала доказывать то, ради чего написана", got)
	}
}

// TestBypassKeepsSocketWhenInterfaceUnknown — консервативный край механизма.
// Отсутствие default route — законное переходное состояние ноутбука (§6.8,
// outbound.New: «Interface тогда возвращает ErrNoInterface»), а не сигнал о
// смене сети. Рвать по нему живой сокет значило бы превращать мгновенную
// неготовность в жёсткий отказ; сравнить всё равно не с чем.
func TestBypassKeepsSocketWhenInterfaceUnknown(t *testing.T) {
	listener := newListener(t)
	clk := clock.NewFake(time.Unix(0, 0))
	iface := &physicalInterface{name: "wlan0"}

	n, err := New(Config{
		Control:   countingControl(new(int32)),
		Interface: iface.get,
		Reply:     func([]byte) {},
		Clock:     clk,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.Close()

	first := sendFrom(t, n, listener, "запрос по wlan0")

	iface.fail(errNoInterfaceForTest)
	if again := sendFrom(t, n, listener, "запрос без default route"); again != first {
		t.Fatalf("сокет переоткрыт (порт %d → %d) на пропавшем default route: "+
			"переходное состояние принято за смену интерфейса", first, again)
	}

	// Маршрут вернулся тем же — сокет по-прежнему тот же.
	iface.set("wlan0")
	if again := sendFrom(t, n, listener, "маршрут вернулся"); again != first {
		t.Fatalf("сокет переоткрыт (порт %d → %d) при возврате того же интерфейса", first, again)
	}
	if got := n.Stats().Rebound; got != 0 {
		t.Fatalf("Rebound = %d, ожидался 0: интерфейс не менялся", got)
	}
}

// TestBypassIdleSweepNeverCollectsSocketUnderTraffic закрепляет ловушку, из-за
// которой уборка простоя не годится на роль механизма: sock.seen обновляется
// на каждый Send, а не на успешный обмен. Клиент, ретраящий mDNS/SSDP каждые
// несколько секунд — а обнаружение служб делает именно так, — держит сокет
// вечно молодым, и Idle до него не добирается никогда.
//
// Проверка не охраняет bypass_rebind: она зелена при любом его состоянии.
// Она объясняет, почему без bypass_rebind дыра не закрывается сама.
func TestBypassIdleSweepNeverCollectsSocketUnderTraffic(t *testing.T) {
	listener := newListener(t)
	clk := clock.NewFake(time.Unix(0, 0))
	iface := &physicalInterface{name: "wlan0"}

	const idle = 2 * time.Second
	n, err := New(Config{
		Control:   countingControl(new(int32)),
		Interface: iface.get,
		Reply:     func([]byte) {},
		Clock:     clk,
		Idle:      idle,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.Close()

	first := sendFrom(t, n, listener, "первый запрос")

	// Шаг в 3/4 Idle: короче Idle, но длиннее Idle/2, поэтому уборка
	// запускается на каждом Send и каждый раз находит сокет свежим.
	const retries = 10
	for i := 0; i < retries; i++ {
		clk.Advance(idle * 3 / 4)
		if got := sendFrom(t, n, listener, "ретрай"); got != first {
			t.Fatalf("сокет сменился на %d при неизменном интерфейсе: "+
				"проверка перестала показывать то, ради чего написана", got)
		}
	}

	// Прошло 7.5×Idle непрерывного трафика — сокет всё тот же и по-прежнему один.
	if got := n.Stats().Sockets; got != 1 {
		t.Fatalf("Sockets = %d после 7.5×Idle непрерывного трафика, ожидался 1", got)
	}
}
