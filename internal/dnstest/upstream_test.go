package dnstest

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
)

// quietWait — сторожевой интервал для «событие не произошло». Настоящее
// время, но не модель продукта: это защита от зависшего теста, тот же приём,
// которым internal/packettest бережёт WaitEmitted (clock.System{}.After
// вместо time.After — realtimelint его не видит, потому что смотрит только на
// селекторы вида time.X).
const quietWait = 50 * time.Millisecond

func TestUpstreamDelayWaitsForFakeClock(t *testing.T) {
	fake := clock.NewFake(time.Unix(0, 0))
	clk := NewClock(fake)
	up := New(clk)
	dst := netip.MustParseAddrPort("1.1.1.1:53")
	up.Program(dst, Behavior{Delay: 150 * time.Millisecond, Answer: []byte("ответ")})

	conn, err := up.DialUDP(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.WriteTo([]byte("запрос"), nil)

	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 512)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		got <- append([]byte(nil), buf[:n]...)
	}()

	clk.WaitAfterCalls(1)
	select {
	case <-got:
		t.Fatal("ответ пришёл раньше Advance — задержка не на инъектированных часах")
	default:
	}

	fake.Advance(150 * time.Millisecond)

	select {
	case b := <-got:
		if string(b) != "ответ" {
			t.Fatalf("ответ = %q, хочу %q", b, "ответ")
		}
	case <-clock.System{}.After(time.Second):
		t.Fatal("ответ не пришёл после Advance")
	}
}

func TestUpstreamSilentNeverAnswers(t *testing.T) {
	fake := clock.NewFake(time.Unix(0, 0))
	clk := NewClock(fake)
	up := New(clk)
	dst := netip.MustParseAddrPort("1.1.1.1:53")
	up.Program(dst, Behavior{Silent: true})

	conn, err := up.DialUDP(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.WriteTo([]byte("запрос"), nil)

	// Запрос обязан долететь и быть учтён — иначе молчание можно спутать с
	// тем, что запрос вообще не дошёл до апстрима.
	up.WaitQueries(1)

	buf := make([]byte, 512)
	done := make(chan struct{})
	go func() {
		conn.ReadFrom(buf)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("молчащий апстрим всё-таки ответил")
	case <-clock.System{}.After(quietWait):
	}
}

func TestUpstreamCallsCountSeparatelyByDialer(t *testing.T) {
	fake := clock.NewFake(time.Unix(0, 0))
	clk := NewClock(fake)
	up := New(clk)
	dst := netip.MustParseAddrPort("1.1.1.1:53")
	up.Program(dst, Behavior{Answer: []byte("ответ")})

	udpConn, err := up.DialUDP(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	udpConn.WriteTo([]byte("q1"), nil)

	tcpConn, err := up.Dial(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpConn.Close()
	writeFramed(t, tcpConn, []byte("q2"))
	readFramed(t, tcpConn)

	directConn, err := up.DialDirect(context.Background(), "udp", dst)
	if err != nil {
		t.Fatal(err)
	}
	defer directConn.Close()
	directConn.Write([]byte("q3"))

	up.WaitQueries(3)
	calls := up.Calls()
	if calls.DialUDP != 1 || calls.Dial != 1 || calls.DialDirect != 1 {
		t.Fatalf("Calls() = %+v, хочу по одному вызову на каждый диалер", calls)
	}
}

func TestUpstreamDialDirectRejectsUnknownNetwork(t *testing.T) {
	fake := clock.NewFake(time.Unix(0, 0))
	clk := NewClock(fake)
	up := New(clk)
	dst := netip.MustParseAddrPort("1.1.1.1:53")

	if _, err := up.DialDirect(context.Background(), "unix", dst); err == nil {
		t.Fatal("DialDirect с неизвестной сетью обязан вернуть ошибку")
	}
}

// TestUpstreamTCPReadLoopNotBlockedByPendingAnswer — D6: соединение не
// блокируется, пока ответ на предыдущий запрос ждёт своей форы. Оба запроса
// обязаны дойти до стенда, даже если ни на один ещё не ответили.
func TestUpstreamTCPReadLoopNotBlockedByPendingAnswer(t *testing.T) {
	fake := clock.NewFake(time.Unix(0, 0))
	clk := NewClock(fake)
	up := New(clk)
	dst := netip.MustParseAddrPort("1.1.1.1:53")
	up.Program(dst, Behavior{Delay: time.Second, Answer: []byte("answer")})

	conn, err := up.Dial(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	writeFramed(t, conn, []byte("q1"))
	writeFramed(t, conn, []byte("q2"))

	up.WaitQueries(2)
	clk.WaitAfterCalls(2)
	fake.Advance(time.Second)

	readFramed(t, conn)
	readFramed(t, conn)
}

// TestUpstreamTCPDelayedAnswerGoroutineReleasedOnClose — М2 ревью волны 1
// (.superpowers/sdd/handoff-md-wondrous-boole/wave1-review.md): answerUDP
// прерывает ожидание Delay по c.done, а answerTCP раньше — нет, и висел до
// конца прогона бинаря, если клиент закрывал соединение раньше, чем часы
// докручивали задержку. D40/D44 требуют, чтобы горутины не копились именно
// в этом сценарии.
func TestUpstreamTCPDelayedAnswerGoroutineReleasedOnClose(t *testing.T) {
	fake := clock.NewFake(time.Unix(0, 0))
	clk := NewClock(fake)
	up := New(clk)
	dst := netip.MustParseAddrPort("1.1.1.1:53")
	// Час — заведомо дольше времени жизни теста: если бы починки не было,
	// горутина answerTCP провисела бы до конца прогона бинаря, а не только
	// до конца этого теста.
	up.Program(dst, Behavior{Delay: time.Hour, Answer: []byte("answer")})

	before := runtime.NumGoroutine()

	conn, err := up.Dial(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	writeFramed(t, conn, []byte("q1"))

	up.WaitQueries(1)
	clk.WaitAfterCalls(1) // answerTCP гарантированно уже внутри select на Delay

	conn.Close() // клиент уходит, не дожидаясь ответа — часы так и не докрутят Delay

	if !WaitObserved(time.Second, func() bool {
		runtime.GC()
		return runtime.NumGoroutine() <= before
	}) {
		t.Fatalf("горутина answerTCP не отпущена после закрытия соединения: было %d, сейчас %d", before, runtime.NumGoroutine())
	}
}

// TestUpstreamTCPBadLengthPrefixDoesNotDeliverFullMessage — D37: неверный
// префикс длины обязан оставить клиента без полного сообщения, а не
// заставить его ждать байты, которых не будет.
func TestUpstreamTCPBadLengthPrefixDoesNotDeliverFullMessage(t *testing.T) {
	fake := clock.NewFake(time.Unix(0, 0))
	clk := NewClock(fake)
	up := New(clk)
	dst := netip.MustParseAddrPort("1.1.1.1:53")
	up.Program(dst, Behavior{BadLengthPrefix: true})

	conn, err := up.Dial(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	writeFramed(t, conn, []byte("q"))
	up.WaitQueries(1)

	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n < 100 {
		t.Fatalf("длина в префиксе = %d, хочу заведомо больше присланного тела", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err == nil {
		t.Fatal("io.ReadFull дочитал n байт вопреки обещанному префиксу — сервер не оборвал поток")
	}
}

func writeFramed(t *testing.T, conn net.Conn, msg []byte) {
	t.Helper()
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	if _, err := conn.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
}

func readFramed(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint16(hdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	return buf
}
