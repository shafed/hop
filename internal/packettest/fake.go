// Package packettest — поддельный PacketDevice из §8.1: пара буферов в памяти,
// позволяющая гонять весь netstack, вердикты и fail-close без TUN и без прав.
package packettest

import (
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
)

// FakeDevice — реализация packet.PacketDevice поверх двух очередей.
//
// Inject кладёт пакет так, будто он пришёл из сети; Emitted возвращает всё,
// что агент записал в устройство.
type FakeDevice struct {
	mtu int

	mu       sync.Mutex
	closed   bool
	inbound  [][]byte
	outbound [][]byte
	arrived  chan struct{} // ёмкость 1, сигнал «в inbound что-то есть»
	written  chan struct{} // ёмкость 1, сигнал «в outbound что-то есть»
}

// NewFake создаёт устройство с заданным MTU.
func NewFake(mtu int) *FakeDevice {
	return &FakeDevice{
		mtu:     mtu,
		arrived: make(chan struct{}, 1),
		written: make(chan struct{}, 1),
	}
}

// WaitTimeout — сколько WaitEmitted ждёт ответа, прежде чем признать молчание.
// Тест на молчание должен падать быстро: он ждёт полный таймаут по построению.
const WaitTimeout = 2 * time.Second

// WaitEmitted ждёт, пока в устройство запишут n пакетов, и возвращает их.
//
// Отдельный метод, а не polling в тесте: проверяемое здесь свойство — «отказ
// вместо молчания», и отличить одно от другого можно только ожиданием с
// заведомым концом.
func (f *FakeDevice) WaitEmitted(t testing.TB, n int) [][]byte {
	t.Helper()
	deadline := clock.System{}.After(WaitTimeout)
	var got [][]byte
	for len(got) < n {
		got = append(got, f.Emitted()...)
		if len(got) >= n {
			break
		}
		select {
		case <-f.written:
		case <-deadline:
			t.Fatalf("за %v записано %d пакетов, ожидалось %d", WaitTimeout, len(got), n)
		}
	}
	return got
}

func (f *FakeDevice) MTU() int { return f.mtu }

// Written сигнализирует, что в устройство что-то дописано. Ёмкость 1: сигналы
// коалесцируются, и после каждого будильника надо слить весь Emitted(), а не
// один пакет. Тот же канал, которым живёт WaitEmitted — для стендов, которым
// нужен непрерывный насос, а не разовое ожидание известного числа пакетов.
func (f *FakeDevice) Written() <-chan struct{} { return f.written }

// Inject кладёт пакеты во входящую очередь.
func (f *FakeDevice) Inject(pkts ...[]byte) {
	f.mu.Lock()
	for _, p := range pkts {
		f.inbound = append(f.inbound, append([]byte(nil), p...))
	}
	f.mu.Unlock()
	select {
	case f.arrived <- struct{}{}:
	default:
	}
}

// Emitted возвращает и очищает всё, что было записано в устройство.
func (f *FakeDevice) Emitted() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.outbound
	f.outbound = nil
	return out
}

// Close будит читателя и переводит устройство в закрытое состояние.
func (f *FakeDevice) Close() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	for _, c := range []chan struct{}{f.arrived, f.written} {
		select {
		case c <- struct{}{}:
		default:
		}
	}
}

func (f *FakeDevice) ReadPackets(bufs [][]byte) (int, error) {
	for {
		f.mu.Lock()
		if n := f.drainLocked(bufs); n > 0 {
			f.mu.Unlock()
			return n, nil
		}
		closed := f.closed
		f.mu.Unlock()
		if closed {
			return 0, io.EOF
		}
		<-f.arrived
	}
}

func (f *FakeDevice) drainLocked(bufs [][]byte) int {
	n := 0
	for n < len(bufs) && n < len(f.inbound) {
		bufs[n] = bufs[n][:copy(bufs[n][:cap(bufs[n])], f.inbound[n])]
		n++
	}
	f.inbound = f.inbound[n:]
	return n
}

func (f *FakeDevice) WritePackets(bufs [][]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return io.ErrClosedPipe
	}
	for _, b := range bufs {
		f.outbound = append(f.outbound, append([]byte(nil), b...))
	}
	select {
	case f.written <- struct{}{}:
	default:
	}
	return nil
}

// ExpectRST требует, чтобы среди записанного нашёлся TCP-пакет с флагом RST
// (§5.6: закрытие — отказ, а не молчание).
func (f *FakeDevice) ExpectRST(t testing.TB) []byte {
	t.Helper()
	return f.expect(t, "RST", func(p []byte) bool {
		flags, ok := tcpFlags(p)
		return ok && flags&tcpRST != 0
	})
}

// ExpectICMPUnreach требует ICMP destination unreachable с заданным кодом
// (3 — port unreachable, 1 — host unreachable).
func (f *FakeDevice) ExpectICMPUnreach(t testing.TB, code byte) []byte {
	t.Helper()
	return f.expect(t, fmt.Sprintf("ICMP unreachable code=%d", code), func(p []byte) bool {
		typ, c, ok := icmpTypeCode(p)
		return ok && typ == icmpDestUnreach && c == code
	})
}

// expect ждёт пакет, удовлетворяющий want, не дольше WaitTimeout.
//
// Ждёт, а не смотрит на уже записанное: Emitted осушает очередь, поэтому
// «сначала WaitEmitted, потом ExpectRST» отдавало бы пустоту, а «сразу
// ExpectRST» гонялось бы с насосом. Ожидание с заведомым концом — то же
// свойство, ради которого написан WaitEmitted: отличить отказ от молчания
// можно только им.
func (f *FakeDevice) expect(t testing.TB, what string, want func([]byte) bool) []byte {
	t.Helper()
	deadline := clock.System{}.After(WaitTimeout)
	seen := 0
	for {
		emitted := f.Emitted()
		seen += len(emitted)
		for _, p := range emitted {
			if want(p) {
				return p
			}
		}
		select {
		case <-f.written:
		case <-deadline:
			t.Fatalf("%s не найден среди %d записанных пакетов за %v", what, seen, WaitTimeout)
			return nil
		}
	}
}
