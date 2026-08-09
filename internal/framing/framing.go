// Package framing — байтовый режим границы с явным length-prefix и батчингом
// (этап 1).
//
// Message-режим named pipe сохранил бы границы пакетов сам, но стоит один
// syscall на пакет. Framing даёт N пакетов на одну запись; чтение идёт крупным
// буфером и нарезается на срезы без копирования внутри батча.
//
// Кадр: uint16 big-endian длина + полезная нагрузка.
package framing

import (
	"errors"
	"io"

	"github.com/shafed/hop/internal/policy"
)

// HeaderLen — размер префикса длины.
const HeaderLen = 2

// MaxPacket — предел, представимый в префиксе.
const MaxPacket = 1<<16 - 1

var (
	ErrTooLong  = errors.New("framing: пакет длиннее MaxPacket")
	ErrNoRoom   = errors.New("framing: кадр не помещается в буфер чтения")
	ErrBadFrame = errors.New("framing: нулевая длина кадра")
)

// Writer собирает батч в один буфер и отдаёт его одной записью.
type Writer struct {
	w   io.Writer
	buf []byte
}

// NewWriter создаёт писателя с буфером на capacity байт.
func NewWriter(w io.Writer, capacity int) *Writer {
	return &Writer{w: w, buf: make([]byte, 0, capacity)}
}

// WriteBatch пишет все пакеты одной операцией.
func (w *Writer) WriteBatch(pkts [][]byte) error {
	// Политика §8: без framing запись теряет границы пакетов, и читатель
	// восстановить их не может. Ровно это и должен показать TestBatchRoundTrip.
	framed := policy.PacketFraming.On()

	w.buf = w.buf[:0]
	for _, p := range pkts {
		if len(p) > MaxPacket {
			return ErrTooLong
		}
		if framed {
			w.buf = append(w.buf, byte(len(p)>>8), byte(len(p)))
		}
		w.buf = append(w.buf, p...)
	}
	_, err := w.w.Write(w.buf)
	return err
}

// Reader нарезает поток на пакеты. Срезы, которые он возвращает, смотрят
// внутрь его собственного буфера и живут до следующего ReadBatch.
type Reader struct {
	r        io.Reader
	buf      []byte
	off, end int
}

// NewReader создаёт читателя с буфером на size байт.
func NewReader(r io.Reader, size int) *Reader {
	return &Reader{r: r, buf: make([]byte, size)}
}

// ReadBatch заполняет out срезами пакетов и возвращает их число.
func (r *Reader) ReadBatch(out [][]byte) (int, error) {
	for {
		if n := r.slice(out); n > 0 {
			return n, nil
		}
		if err := r.fill(); err != nil {
			return 0, err
		}
	}
}

func (r *Reader) slice(out [][]byte) int {
	n := 0
	for n < len(out) {
		avail := r.end - r.off
		if avail < HeaderLen {
			break
		}
		l := int(r.buf[r.off])<<8 | int(r.buf[r.off+1])
		if avail < HeaderLen+l {
			break
		}
		out[n] = r.buf[r.off+HeaderLen : r.off+HeaderLen+l]
		r.off += HeaderLen + l
		n++
	}
	return n
}

func (r *Reader) fill() error {
	if r.off > 0 {
		r.end = copy(r.buf, r.buf[r.off:r.end])
		r.off = 0
	}
	if r.end == len(r.buf) {
		return ErrNoRoom
	}
	n, err := r.r.Read(r.buf[r.end:])
	r.end += n
	if n == 0 && err != nil {
		return err
	}
	return nil
}
