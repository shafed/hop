package faultinject_test

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/faultinject"
)

// §8.1 требует, чтобы каждый режим давал своё наблюдаемое, а rst и blackhole
// были разными тестами: rst маскирует отсутствие таймаута, blackhole — нет.

func TestPassForwardsBothWays(t *testing.T) {
	up := echoServer(t)
	s := start(t, up, faultinject.Config{}, clock.System{})

	c := dial(t, s.Addr())
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("запись: %v", err)
	}
	if got := readN(t, c, 4); got != "ping" {
		t.Fatalf("прошло %q, ожидалось %q", got, "ping")
	}
}

func TestRSTGivesConnectionReset(t *testing.T) {
	s := start(t, echoServer(t), faultinject.Config{}, clock.System{})
	s.SetMode(faultinject.RST)

	// RST может прилететь и на connect, и на первом чтении — зависит от того,
	// успел ли клиент отправить SYN раньше, чем стенд снял соединение. Оба
	// исхода — один и тот же отказ.
	err := errors.New("соединение не рвалось")
	if c, derr := net.Dial("tcp", s.Addr().String()); derr != nil {
		err = derr
	} else {
		defer c.Close()
		c.Write([]byte("ping"))
		if _, rerr := c.Read(make([]byte, 16)); rerr != nil {
			err = rerr
		} else {
			t.Fatal("чтение прошло, ожидался разрыв")
		}
	}
	// ECONNRESET, а не EOF: корректное закрытие клиент принял бы за штатный
	// конец ответа, и «сервер снят» стало бы неотличимо от «сервер попрощался».
	// Проверка через io.EOF, потому что Windows отдаёт WSAECONNRESET, который
	// с syscall.ECONNRESET не сравнивается.
	if errors.Is(err, io.EOF) {
		t.Fatalf("получен EOF, ожидался ECONNRESET: %v", err)
	}
}

func TestBlackholeIsSilentAndStaysOpen(t *testing.T) {
	s := start(t, echoServer(t), faultinject.Config{}, clock.System{})
	s.SetMode(faultinject.Blackhole)

	c := dial(t, s.Addr())
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("запись: %v", err)
	}

	buf := make([]byte, 16)
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond)) //hop:realtime
	n, err := c.Read(buf)
	if n != 0 {
		t.Fatalf("пришло %d байт, ожидалось 0", n)
	}
	// Соединение обязано висеть: закрытие дало бы вызывающему ошибку, и
	// отсутствие собственного таймаута осталось бы незамеченным.
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("соединение закрылось (%v), ожидалось молчание", err)
	}
}

func TestSlowTakesDelayFromInjectedClock(t *testing.T) {
	clk := &recordingClock{Fake: clock.NewFake(time.Unix(0, 0))} //hop:realtime
	s := start(t, echoServer(t), faultinject.Config{Slow: 900 * time.Millisecond}, clk)
	s.SetMode(faultinject.Slow)

	c := dial(t, s.Addr())
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("запись: %v", err)
	}
	if got := readN(t, c, 4); got != "ping" {
		t.Fatalf("прошло %q", got)
	}

	// Обе стороны прошли через задержку, и величина взята из часов, а не из
	// настоящего времени: иначе тест деградации латентности стоил бы секунд.
	asked := clk.asked()
	if len(asked) < 2 {
		t.Fatalf("часы спрошены %d раз, ожидалось не меньше двух: %v", len(asked), asked)
	}
	for _, d := range asked {
		if d != 900*time.Millisecond {
			t.Fatalf("запрошена задержка %v, настроена 900ms", d)
		}
	}
}

func TestCutAfterHandshakeClosesAfterNBytes(t *testing.T) {
	s := start(t, echoServer(t), faultinject.Config{CutAfter: 4}, clock.System{})
	s.SetMode(faultinject.CutAfterHandshake)

	c := dial(t, s.Addr())
	if _, err := c.Write([]byte("0123456789")); err != nil {
		t.Fatalf("запись: %v", err)
	}

	// Первые CutAfter байт доходят — рукопожатие успевает пройти; всё, что
	// после, обрывается. Это и есть DPI-подобное поведение из §8.1.
	if got := readN(t, c, 4); got != "0123" {
		t.Fatalf("до разрыва пришло %q, ожидалось %q", got, "0123")
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second)) //hop:realtime
	if _, err := c.Read(make([]byte, 16)); err == nil {
		t.Fatal("чтение после разрыва прошло, ожидалось закрытие")
	}
}

func TestCloseTearsDownLiveConnections(t *testing.T) {
	s := start(t, echoServer(t), faultinject.Config{}, clock.System{})
	s.SetMode(faultinject.Blackhole)

	c := dial(t, s.Addr())
	s.Close()

	c.SetReadDeadline(time.Now().Add(2 * time.Second)) //hop:realtime
	if _, err := c.Read(make([]byte, 16)); err == nil {
		t.Fatal("соединение пережило Close стенда")
	}
}

// --- обвязка ---

func start(t *testing.T, upstream netip.AddrPort, cfg faultinject.Config, clk clock.Clock) *faultinject.Server {
	t.Helper()
	s, err := faultinject.New(upstream, cfg, clk)
	if err != nil {
		t.Fatalf("стенд: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// echoServer — «настоящий узел» за прослойкой: отдаёт обратно то, что получил.
func echoServer(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("эхо: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("адрес эха: %v", err)
	}
	return addr
}

func dial(t *testing.T, addr netip.AddrPort) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("соединение: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func readN(t *testing.T, c net.Conn, n int) string {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second)) //hop:realtime
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("чтение %d байт: %v", n, err)
	}
	return string(buf)
}

// recordingClock — часы, которые записывают запрошенный интервал и не ждут.
// Так проверяется, что задержка берётся у часов, а не у настоящего времени, и
// тест при этом не стоит настоящих 900 мс.
type recordingClock struct {
	*clock.Fake
	mu   sync.Mutex
	seen []time.Duration
}

func (c *recordingClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.seen = append(c.seen, d)
	c.mu.Unlock()
	ch := make(chan time.Time, 1)
	ch <- c.Now()
	return ch
}

func (c *recordingClock) asked() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.seen...)
}
