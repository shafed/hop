package bench

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// Разбор GSO-суперрамки — единственная нетривиальная логика в контрольном
// замере: ошибка здесь завысила бы цену возврата GSO молча.
func TestSplitVirtioUDPSuperframe(t *testing.T) {
	const (
		segPayload = 1372
		segs       = 45
	)
	body := udpSuperframe(segs * segPayload)
	in := append(virtioHdr(unix.VIRTIO_NET_HDR_GSO_UDP_L4, segPayload), body...)

	out := make([][]byte, 128)
	for i := range out {
		out[i] = make([]byte, 65535)
	}

	n, nbytes, gso, err := splitVirtio(in, out)
	if err != nil {
		t.Fatal(err)
	}
	if !gso {
		t.Fatal("суперрамка не опознана как GSO")
	}
	if n != segs {
		t.Fatalf("сегментов %d, ожидалось %d", n, segs)
	}
	if want := segs * (segPayload + 28); nbytes != want {
		t.Fatalf("байт %d, ожидалось %d", nbytes, want)
	}
	for i, seg := range out[:n] {
		if len(seg) != segPayload+28 {
			t.Fatalf("сегмент %d длиной %d, ожидалось %d", i, len(seg), segPayload+28)
		}
		if got := binary.BigEndian.Uint16(seg[2:4]); int(got) != segPayload+28 {
			t.Fatalf("сегмент %d: IP total length %d", i, got)
		}
		if got := binary.BigEndian.Uint16(seg[24:26]); int(got) != segPayload+8 {
			t.Fatalf("сегмент %d: UDP length %d", i, got)
		}
	}
}

// Хвостовой сегмент короче gso_size — частый случай, и его легко потерять.
func TestSplitVirtioRagged(t *testing.T) {
	const segPayload = 1000
	body := udpSuperframe(2*segPayload + 137)
	in := append(virtioHdr(unix.VIRTIO_NET_HDR_GSO_UDP_L4, segPayload), body...)

	out := make([][]byte, 8)
	for i := range out {
		out[i] = make([]byte, 65535)
	}
	n, _, _, err := splitVirtio(in, out)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("сегментов %d, ожидалось 3", n)
	}
	if len(out[2]) != 137+28 {
		t.Fatalf("хвостовой сегмент %d байт, ожидалось %d", len(out[2]), 137+28)
	}
}

func TestSplitVirtioPlainPacket(t *testing.T) {
	body := udpSuperframe(200)
	in := append(virtioHdr(unix.VIRTIO_NET_HDR_GSO_NONE, 0), body...)

	out := [][]byte{make([]byte, 65535)}
	n, nbytes, gso, err := splitVirtio(in, out)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || gso {
		t.Fatalf("n=%d gso=%v, ожидалось 1/false", n, gso)
	}
	if nbytes != len(body) {
		t.Fatalf("байт %d, ожидалось %d", nbytes, len(body))
	}
}

func virtioHdr(gsoType byte, gsoSize int) []byte {
	h := make([]byte, virtioNetHdrLen)
	h[1] = gsoType
	binary.LittleEndian.PutUint16(h[4:6], uint16(gsoSize))
	return h
}

// udpSuperframe — IPv4+UDP с полезной нагрузкой в payloadLen байт.
func udpSuperframe(payloadLen int) []byte {
	p := make([]byte, 28+payloadLen)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[9] = unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(p[24:26], uint16(8+payloadLen))
	for i := 28; i < len(p); i++ {
		p[i] = byte(i)
	}
	return p
}
