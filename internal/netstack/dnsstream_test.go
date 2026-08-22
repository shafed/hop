package netstack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/fakenet"
	"github.com/shafed/hop/internal/packettest"
)

// streamWatchdog — сторож красного теста: любое чтение и любая запись в стенде
// обязаны завершиться сразу, и настоящая секунда здесь только для того, чтобы
// сломанный код падал, а не висел.
const streamWatchdog = 2 * time.Second

// dnsStream — одно соединение DNS поверх TCP на фейковых часах.
//
// Стек собирается настоящим New поверх поддельного устройства, но насос не
// запускается: проверяется обслуживание уже принятого соединения, а рукопожатие
// TCP к этому свойству ничего не добавляет. Клиентский конец — net.Pipe:
// синхронная труба без буферов делает «ответ дошёл» наблюдаемым событием, а не
// вопросом планировщика.
type dnsStream struct {
	st   *Stack
	clk  *clock.Fake
	conn net.Conn
}

func newDNSStream(t *testing.T, res Resolver) *dnsStream {
	t.Helper()

	clk := clock.NewFake(time.Unix(1, 0))
	st, err := New(Config{
		Device:   packettest.NewFake(1500),
		Resolver: res,
		Clock:    clk,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	local, remote := net.Pipe()
	st.tcp.serveDNSStream(remote, flow{
		proto: uint8(header.TCPProtocolNumber),
		src:   client,
		dst:   router53,
	})

	t.Cleanup(func() {
		_ = local.Close()
		st.Close()
	})
	return &dnsStream{st: st, clk: clk, conn: local}
}

// ask отправляет сообщение с префиксом длины (RFC 1035 §4.2.2).
func (s *dnsStream) ask(t *testing.T, msg []byte) {
	t.Helper()
	if err := s.conn.SetWriteDeadline(time.Now().Add(streamWatchdog)); err != nil { //hop:realtime сторож
		t.Fatalf("дедлайн записи: %v", err)
	}
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msg)))
	copy(buf[2:], msg)
	if _, err := s.conn.Write(buf); err != nil {
		t.Fatalf("запрос не отправлен: %v", err)
	}
}

// answer читает один ответ по префиксу длины и возвращает тело.
func (s *dnsStream) answer(t *testing.T) []byte {
	t.Helper()
	if err := s.conn.SetReadDeadline(time.Now().Add(streamWatchdog)); err != nil { //hop:realtime сторож
		t.Fatalf("дедлайн чтения: %v", err)
	}
	var hdr [2]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		t.Fatalf("префикс длины не прочитан: %v", err)
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 {
		t.Fatal("нулевой префикс длины: ответ без тела")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(s.conn, body); err != nil {
		t.Fatalf("тело ответа короче префикса (%d): %v", n, err)
	}
	return body
}

// msg — сообщение-пустышка: netstack в DNS не заглядывает, ему это байты с
// префиксом длины. Разные длины и разное содержимое — чтобы ответы были
// различимы и чтобы врущий префикс ломал разбор следующего сообщения.
func msg(mark byte, n int) []byte {
	return bytes.Repeat([]byte{mark}, n)
}

// D5. Два запроса в одном соединении: оба обслужены, префикс длины на каждом
// ответе корректен (RFC 1035 §4.2.2).
func TestD5TwoQueriesInOneStream(t *testing.T) {
	s := newDNSStream(t, &fakenet.Resolver{})

	first, second := msg(0xA1, 12), msg(0xB2, 40)
	for _, q := range [][]byte{first, second} {
		s.ask(t, q)
		got := s.answer(t)
		if !bytes.Equal(got, q) {
			t.Fatalf("ответ % x, ожидался % x", got, q)
		}
	}
}

// D6. Второй запрос отвечается раньше первого: ответы допускается вернуть не по
// порядку, соединение медленным именем не блокируется (RFC 7766 §6.2.1.1).
//
// «Дольше» здесь — это порядок, а не длительность: первый запрос держится в
// Gate, пока не пришёл ответ на второй. Сна на фейковых часах не бывает, и
// проверять пришлось бы настоящую задержку, то есть настоящее время.
func TestD6SlowQueryDoesNotBlockTheStream(t *testing.T) {
	const slow, fast byte = 0xC1, 0xD2

	release := make(chan struct{})
	var held, freed atomic.Bool
	res := &fakenet.Resolver{Gate: func(q []byte) {
		if len(q) > 0 && q[0] == slow && held.CompareAndSwap(false, true) {
			<-release
		}
	}}
	s := newDNSStream(t, res)
	// Красный тест обязан падать, а не висеть: реализация, отвечающая строго по
	// порядку, до быстрого ответа не доходит вовсе, и снятие стенда ждало бы
	// удержанную горутину вечно.
	free := func() {
		if freed.CompareAndSwap(false, true) {
			close(release)
		}
	}
	t.Cleanup(free)

	slowQuery, fastQuery := msg(slow, 20), msg(fast, 24)
	s.ask(t, slowQuery)
	s.ask(t, fastQuery)

	if got := s.answer(t); !bytes.Equal(got, fastQuery) {
		t.Fatalf("первым пришёл % x, ожидался быстрый ответ % x", got, fastQuery)
	}
	free()
	if got := s.answer(t); !bytes.Equal(got, slowQuery) {
		t.Fatalf("вторым пришёл % x, ожидался медленный ответ % x", got, slowQuery)
	}
}

// D6. Ответы, отпущенные одновременно, не перемешиваются в потоке байт.
//
// Тот же конвейер, но с тридцатью двумя запросами, отпущенными разом: без
// замка на записи два ответа сложились бы в один кадр, и клиент, разбирающий
// поток по префиксу длины, не восстановился бы никогда. Смысл теста виден под
// `go test -race`; без него он ловит только грубое перемешивание.
func TestD6ParallelAnswersKeepFraming(t *testing.T) {
	const n = 32

	start := make(chan struct{})
	var started atomic.Bool
	res := &fakenet.Resolver{Gate: func([]byte) { <-start }}
	s := newDNSStream(t, res)
	release := func() {
		if started.CompareAndSwap(false, true) {
			close(start)
		}
	}
	t.Cleanup(release)

	want := make(map[byte]int, n)
	for i := 0; i < n; i++ {
		mark := byte(i + 1)
		want[mark] = 8 + i
		s.ask(t, msg(mark, want[mark]))
	}
	release()

	for i := 0; i < n; i++ {
		got := s.answer(t)
		mark := got[0]
		size, ok := want[mark]
		if !ok {
			t.Fatalf("ответ %d: метка %#x повторилась или не запрашивалась", i, mark)
		}
		delete(want, mark)
		if len(got) != size {
			t.Fatalf("ответ с меткой %#x длиной %d, ожидалась %d: кадры перемешаны", mark, len(got), size)
		}
		if bytes.Count(got, []byte{mark}) != len(got) {
			t.Fatalf("в кадре с меткой %#x чужие байты: % x", mark, got)
		}
	}
	if len(want) != 0 {
		t.Fatalf("ответов не пришло: %d", len(want))
	}
}

// D7. Соединение без запросов 10 с модельного времени закрыто нами, горутина
// освобождена (RFC 7766).
func TestD7IdleStreamIsClosed(t *testing.T) {
	s := newDNSStream(t, &fakenet.Resolver{})

	s.clk.Advance(dnsStreamIdle)

	if err := s.conn.SetReadDeadline(time.Now().Add(streamWatchdog)); err != nil { //hop:realtime сторож
		t.Fatalf("дедлайн чтения: %v", err)
	}
	var b [1]byte
	switch _, err := s.conn.Read(b[:]); {
	case err == nil:
		t.Fatalf("простаивающее соединение отдало байт % x вместо закрытия", b[:])
	case errors.Is(err, os.ErrDeadlineExceeded):
		t.Fatal("соединение не закрыто через 10 с модельного времени")
	}

	// Горутины освобождены простоем, а не закрытием стека: Close здесь не
	// зовётся, ждём только счётчик.
	freed := make(chan struct{})
	go func() {
		s.st.wg.Wait()
		close(freed)
	}()
	select {
	case <-freed:
	case <-time.After(streamWatchdog): //hop:realtime сторож
		t.Fatal("горутины соединения не освобождены")
	}
}

// D7. Простой считается с последнего запроса, а не с начала соединения: срок
// перезаводится на каждом.
//
// Три раунда по девять модельных секунд, а не один: одного хватило бы и
// реализации, которая ставит срок единожды при открытии, — общее время здесь
// уходит за десять секунд, и такая реализация рвёт соединение на втором сдвиге.
func TestD7IdleIsCountedFromTheLastQuery(t *testing.T) {
	s := newDNSStream(t, &fakenet.Resolver{})

	query := msg(0xE3, 16)
	for round := 1; round <= 3; round++ {
		s.ask(t, query)
		if got := s.answer(t); !bytes.Equal(got, query) {
			t.Fatalf("раунд %d: ответ % x, ожидался % x", round, got, query)
		}
		// Ответ уже у клиента — значит новый срок заведён (см. serveDNSStream),
		// и сдвиг часов не пролетает мимо незаведённого таймера.
		s.clk.Advance(dnsStreamIdle - time.Second)
	}
}

// Резолвер, объявивший StreamResolver, узнаёт, что клиент пришёл потоком: без
// этого ответ длиннее буфера EDNS0 уехал бы клиенту с флагом TC там, где TCP
// позволяет отдать полный RRset (§5.7, У4).
func TestStreamResolverSeesTheStreamTransport(t *testing.T) {
	res := &fakenet.StreamResolver{}
	s := newDNSStream(t, res)

	query := msg(0xF4, 18)
	s.ask(t, query)
	if got := s.answer(t); !bytes.Equal(got, query) {
		t.Fatalf("ответ % x, ожидался % x", got, query)
	}
	if n := res.Streamed(); n != 1 {
		t.Fatalf("QueryStream позван %d раз, ожидался ровно один", n)
	}
	if asks := res.Asks(); len(asks) != 1 || asks[0].Client != client || asks[0].Server != router53 {
		t.Fatalf("резолвер увидел %+v, ожидался запрос от %v на %v", asks, client, router53)
	}
}

// Резолвер без QueryStream обслуживается прежним Query: интерфейс Resolver
// заморожен с этапа 3, и потоку он обязан хватать.
func TestPlainResolverStillServesTheStream(t *testing.T) {
	res := &fakenet.Resolver{}
	s := newDNSStream(t, res)

	query := msg(0x5A, 22)
	s.ask(t, query)
	if got := s.answer(t); !bytes.Equal(got, query) {
		t.Fatalf("ответ % x, ожидался % x", got, query)
	}
}
