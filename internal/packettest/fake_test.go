package packettest

import (
	"bytes"
	"io"
	"testing"

	"github.com/shafed/hop/internal/packet"
)

var _ packet.PacketDevice = (*FakeDevice)(nil)

func bufs(n, size int) [][]byte {
	b := make([][]byte, n)
	for i := range b {
		b[i] = make([]byte, size)
	}
	return b
}

func TestInjectReadRoundTrip(t *testing.T) {
	d := NewFake(1500)
	p1 := []byte{1, 2, 3}
	p2 := bytes.Repeat([]byte{7}, 1400)
	d.Inject(p1, p2)

	b := bufs(4, 1500)
	n, err := d.ReadPackets(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("прочитано %d пакетов, ожидалось 2", n)
	}
	if !bytes.Equal(b[0], p1) || !bytes.Equal(b[1], p2) {
		t.Fatal("содержимое пакетов не совпало")
	}
}

func TestReadFillsAtMostLenBufs(t *testing.T) {
	d := NewFake(1500)
	d.Inject([]byte{1}, []byte{2}, []byte{3})

	b := bufs(2, 1500)
	if n, _ := d.ReadPackets(b); n != 2 {
		t.Fatalf("прочитано %d, ожидалось 2", n)
	}
	if n, _ := d.ReadPackets(b); n != 1 {
		t.Fatalf("во втором чтении %d, ожидался 1", n)
	}
}

func TestWriteThenEmitted(t *testing.T) {
	d := NewFake(1500)
	if err := d.WritePackets([][]byte{{1, 2}, {3}}); err != nil {
		t.Fatal(err)
	}
	got := d.Emitted()
	if len(got) != 2 {
		t.Fatalf("записано %d пакетов, ожидалось 2", len(got))
	}
	if len(d.Emitted()) != 0 {
		t.Fatal("Emitted не очистил очередь")
	}
}

func TestCloseWakesReader(t *testing.T) {
	d := NewFake(1500)
	done := make(chan error, 1)
	go func() {
		_, err := d.ReadPackets(bufs(1, 1500))
		done <- err
	}()
	d.Close()
	if err := <-done; err != io.EOF {
		t.Fatalf("ошибка %v, ожидался io.EOF", err)
	}
}

func TestExpectRST(t *testing.T) {
	d := NewFake(1500)
	if err := d.WritePackets([][]byte{udpPacket(), tcpPacket(tcpRST)}); err != nil {
		t.Fatal(err)
	}
	d.ExpectRST(t)
}

func TestExpectICMPUnreach(t *testing.T) {
	d := NewFake(1500)
	if err := d.WritePackets([][]byte{icmpPacket(icmpDestUnreach, 3)}); err != nil {
		t.Fatal(err)
	}
	d.ExpectICMPUnreach(t, 3)
}

// Разборщик не должен принимать пакет с чужим флагом за RST.
func TestTCPFlagsDiscriminates(t *testing.T) {
	if f, ok := tcpFlags(tcpPacket(0x10)); !ok || f&tcpRST != 0 {
		t.Fatalf("ACK опознан как RST (flags=%#x ok=%v)", f, ok)
	}
	if _, ok := tcpFlags(udpPacket()); ok {
		t.Fatal("UDP разобран как TCP")
	}
	if _, _, ok := icmpTypeCode(tcpPacket(tcpRST)); ok {
		t.Fatal("TCP разобран как ICMP")
	}
}

func ipv4Header(proto byte, payloadLen int) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	total := 20 + payloadLen
	h[2], h[3] = byte(total>>8), byte(total)
	h[8] = 64
	h[9] = proto
	copy(h[12:16], []byte{10, 0, 0, 1})
	copy(h[16:20], []byte{10, 0, 0, 2})
	return h
}

func tcpPacket(flags byte) []byte {
	tcp := make([]byte, 20)
	tcp[12] = 0x50
	tcp[13] = flags
	return append(ipv4Header(protoTCP, len(tcp)), tcp...)
}

func udpPacket() []byte {
	udp := make([]byte, 8)
	return append(ipv4Header(17, len(udp)), udp...)
}

func icmpPacket(typ, code byte) []byte {
	icmp := make([]byte, 8)
	icmp[0], icmp[1] = typ, code
	return append(ipv4Header(protoICMP, len(icmp)), icmp...)
}
