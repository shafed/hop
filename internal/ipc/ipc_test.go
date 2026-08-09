package ipc

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/tunnel"
)

// Тесты этого файла — L1: без прав, на всех трёх ОС. Проверяется склейка
// транспорта с машиной состояний, а не сама машина (она проверена в
// internal/tunnel) и не платформенный слой (он в internal/l3).

type fakeNet struct{ rejected, restored, downed atomic.Int32 }

func (n *fakeNet) Up(tunnel.Params) (tunnel.Device, error) { return fakeDev{}, nil }
func (n *fakeNet) Reject() error                           { n.rejected.Add(1); return nil }
func (n *fakeNet) Restore() error                          { n.restored.Add(1); return nil }
func (n *fakeNet) Down() error                             { n.downed.Add(1); return nil }

type fakeDev struct{}

func (fakeDev) Ref() string  { return "fake0" }
func (fakeDev) Close() error { return nil }

var pipeSeq atomic.Int32

// endpoint даёт адрес управляющей границы, годный для текущей ОС: unix-сокет в
// каталоге теста или named pipe с уникальным именем.
func endpoint(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`\\.\pipe\hop-test-%d-%d`, os.Getpid(), pipeSeq.Add(1))
	}
	return filepath.Join(t.TempDir(), "hop.sock")
}

func serve(t *testing.T) (string, *tunnel.Machine, *fakeNet) {
	t.Helper()
	net := &fakeNet{}
	// Дедлайн заведомо больше теста: здесь проверяется ребро, а не таймер.
	m := tunnel.New(clock.System{}, net, tunnel.Config{OrphanDeadline: time.Hour})

	path := endpoint(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	go NewServer(m, nil).Serve(l)
	return path, m, net
}

func params() tunnel.Params {
	return tunnel.Params{Name: "fake0", MTU: 1400, Addr: "10.255.0.1/24", Table: 8420}
}

// Обрыв соединения-владельца **и есть** ребро в orphaned (§6.2): никакого
// таймера, никакого heartbeat. Здесь это проверяется закрытием сокета, что для
// сервиса неотличимо от `kill -9` агента — ядро в обоих случаях закрывает
// дескриптор.
func TestOwnerDisconnectIsTheEdge(t *testing.T) {
	path, m, net := serve(t)

	cl, err := Connect(path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	res, err := cl.Start(params())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Token == "" {
		t.Fatal("StartTunnel не вернул attach-token")
	}
	if res.Device != "fake0" {
		t.Fatalf("device = %q", res.Device)
	}
	if m.State().Phase != tunnel.Up {
		t.Fatalf("phase = %s", m.State().Phase)
	}

	cl.Close()

	waitPhase(t, m, tunnel.Orphaned)
	if got := net.rejected.Load(); got != 1 {
		t.Fatalf("Reject вызван %d раз, ожидался 1", got)
	}
}

// Обрыв постороннего соединения ребра не вызывает: туннелем владеет ровно одно
// соединение, а `hop status` подключается и отключается сколько угодно.
func TestBystanderDisconnectIsNotTheEdge(t *testing.T) {
	path, m, net := serve(t)

	owner, err := Connect(path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer owner.Close()
	if _, err := owner.Start(params()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	for i := 0; i < 3; i++ {
		bystander, err := Connect(path)
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
		if _, err := bystander.Status(); err != nil {
			t.Fatalf("Status: %v", err)
		}
		bystander.Close()
	}

	// Дать серверу время обработать обрывы, если бы он их обрабатывал неверно.
	<-clock.System{}.After(200 * time.Millisecond)
	if got := m.State().Phase; got != tunnel.Up {
		t.Fatalf("phase = %s: обрыв постороннего соединения сдвинул машину", got)
	}
	if got := net.rejected.Load(); got != 0 {
		t.Fatalf("Reject вызван %d раз на посторонних обрывах", got)
	}
}

// Полный круг §3.1: Start → обрыв → Attach по токену. Тот же дескриптор, тот
// же токен.
func TestReattachOverIPC(t *testing.T) {
	path, m, net := serve(t)

	first, err := Connect(path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	res, err := first.Start(params())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	first.Close()
	waitPhase(t, m, tunnel.Orphaned)

	second, err := Connect(path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer second.Close()

	// Сначала мусорный токен: он обязан быть отвергнут и ничего не сдвинуть.
	if _, err := second.Attach(tunnel.Token("подделка")); err == nil {
		t.Fatal("Attach с чужим токеном прошёл")
	}
	if got := m.State().Phase; got != tunnel.Orphaned {
		t.Fatalf("после отказа phase = %s", got)
	}

	got, err := second.Attach(res.Token)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if got.Device != res.Device {
		t.Fatalf("device = %q, ожидался %q", got.Device, res.Device)
	}
	if m.State().Phase != tunnel.Up {
		t.Fatalf("phase = %s", m.State().Phase)
	}
	if n := net.restored.Load(); n != 1 {
		t.Fatalf("Restore вызван %d раз, ожидался 1", n)
	}
}

// Detach — то же ребро, но с известной причиной, и она видна в Status.
func TestDetachReasonReachesStatus(t *testing.T) {
	path, m, _ := serve(t)

	cl, err := Connect(path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer cl.Close()
	if _, err := cl.Start(params()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := cl.Detach(tunnel.ReasonRestart); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	st, err := cl.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Phase != tunnel.Orphaned || st.DetachReason != tunnel.ReasonRestart {
		t.Fatalf("state = %+v", st)
	}
	_ = m
}

// §6.14: ответ сервиса несёт токен по проводу, но в лог он не попадает ни
// через один глагол fmt — за это отвечает тип, а не дисциплина вызывающего.
func TestTokenIsNotFormattable(t *testing.T) {
	path, _, _ := serve(t)

	cl, err := Connect(path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer cl.Close()
	res, err := cl.Start(params())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	for _, s := range []string{
		fmt.Sprintf("%v", res),
		fmt.Sprintf("%+v", Response{Token: res.Token}),
		fmt.Sprintf("%#v", Request{Op: OpAttach, Token: res.Token}),
	} {
		if strings.Contains(s, string(res.Token)) {
			t.Fatalf("токен утёк в форматированный вывод: %s", s)
		}
	}
}

func waitPhase(t *testing.T, m *tunnel.Machine, want tunnel.Phase) {
	t.Helper()
	deadline := clock.System{}.After(5 * time.Second)
	tick := clock.System{}.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if m.State().Phase == want {
			return
		}
		select {
		case <-tick.C():
		case <-deadline:
			t.Fatalf("phase = %s, ожидалось %s", m.State().Phase, want)
		}
	}
}
