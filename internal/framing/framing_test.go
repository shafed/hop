package framing

import (
	"bytes"
	"io"
	"testing"
)

// packets даёт батч с разными длинами и разным содержимым: без префиксов длины
// такой поток восстановить нельзя, и именно это делает тест охраняющим.
func packets(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		size := 40 + i*37%1361 // 40..1400
		p := make([]byte, size)
		for j := range p {
			p[j] = byte(i*31 + j)
		}
		out[i] = p
	}
	return out
}

func readAll(t *testing.T, r *Reader, want int) [][]byte {
	t.Helper()
	var got [][]byte
	buf := make([][]byte, 16)
	for len(got) < want {
		n, err := r.ReadBatch(buf)
		if err != nil {
			t.Fatalf("после %d пакетов из %d: %v", len(got), want, err)
		}
		for _, p := range buf[:n] {
			got = append(got, append([]byte(nil), p...))
		}
	}
	return got
}

// TestBatchRoundTrip — охраняющий тест политики packet_framing (§8):
// батч из N пакетов читается как ровно N пакетов побайтово.
func TestBatchRoundTrip(t *testing.T) {
	const n = 64
	want := packets(n)

	var wire bytes.Buffer
	if err := NewWriter(&wire, 256<<10).WriteBatch(want); err != nil {
		t.Fatal(err)
	}

	got := readAll(t, NewReader(&wire, 256<<10), n)

	if len(got) != n {
		t.Fatalf("прочитано %d пакетов, записано %d", len(got), n)
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("пакет %d не совпал: %d байт против %d", i, len(got[i]), len(want[i]))
		}
	}
}

// Кадр, разорванный между двумя Read, должен собираться.
func TestFrameSplitAcrossReads(t *testing.T) {
	want := packets(8)

	var wire bytes.Buffer
	if err := NewWriter(&wire, 256<<10).WriteBatch(want); err != nil {
		t.Fatal(err)
	}

	got := readAll(t, NewReader(&chunkReader{data: wire.Bytes(), chunk: 7}, 256<<10), len(want))
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("пакет %d не совпал при чтении по 7 байт", i)
		}
	}
}

func TestOversizePacketRejected(t *testing.T) {
	err := NewWriter(io.Discard, 1<<10).WriteBatch([][]byte{make([]byte, MaxPacket+1)})
	if err != ErrTooLong {
		t.Fatalf("ошибка %v, ожидалась ErrTooLong", err)
	}
}

// Кадр крупнее буфера чтения — это ошибка, а не молчаливое зависание.
func TestReaderBufferTooSmall(t *testing.T) {
	var wire bytes.Buffer
	if err := NewWriter(&wire, 4<<10).WriteBatch([][]byte{make([]byte, 2000)}); err != nil {
		t.Fatal(err)
	}
	_, err := NewReader(&wire, 512).ReadBatch(make([][]byte, 4))
	if err != ErrNoRoom {
		t.Fatalf("ошибка %v, ожидалась ErrNoRoom", err)
	}
}

type chunkReader struct {
	data  []byte
	chunk int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := min(min(c.chunk, len(p)), len(c.data))
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}
