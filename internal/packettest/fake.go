// Package packettest — поддельный PacketDevice из §8.1: пара буферов в памяти,
// позволяющая гонять весь netstack, вердикты и fail-close без TUN и без прав.
package packettest

import (
	"io"
	"sync"
	"testing"
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
}

// NewFake создаёт устройство с заданным MTU.
func NewFake(mtu int) *FakeDevice {
	return &FakeDevice{mtu: mtu, arrived: make(chan struct{}, 1)}
}

func (f *FakeDevice) MTU() int { return f.mtu }

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
	select {
	case f.arrived <- struct{}{}:
	default:
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
	return nil
}

// ExpectRST требует, чтобы среди записанного нашёлся TCP-пакет с флагом RST
// (§5.6: закрытие — отказ, а не молчание).
func (f *FakeDevice) ExpectRST(t testing.TB) []byte {
	t.Helper()
	emitted := f.Emitted()
	for _, p := range emitted {
		if flags, ok := tcpFlags(p); ok && flags&tcpRST != 0 {
			return p
		}
	}
	t.Fatalf("RST не найден среди %d записанных пакетов", len(emitted))
	return nil
}

// ExpectICMPUnreach требует ICMP destination unreachable с заданным кодом
// (3 — port unreachable, 1 — host unreachable).
func (f *FakeDevice) ExpectICMPUnreach(t testing.TB, code byte) []byte {
	t.Helper()
	emitted := f.Emitted()
	for _, p := range emitted {
		if typ, c, ok := icmpTypeCode(p); ok && typ == icmpDestUnreach && c == code {
			return p
		}
	}
	t.Fatalf("ICMP unreachable code=%d не найден среди %d записанных пакетов", code, len(emitted))
	return nil
}
