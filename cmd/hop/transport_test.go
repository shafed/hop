package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/tunnel"
)

// fakeControl — сервис за интерфейсом. Настоящий hopd потребовал бы root, и
// проверки шва уехали бы из L1 в L3.
type fakeControl struct {
	mu        sync.Mutex
	fd        int
	beats     int
	beatErr   error
	stopped   int
	detached  int
	startErr  error
	closed    int
	attachErr error
}

func (f *fakeControl) Start(tunnel.Params) (ipc.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return ipc.Result{}, f.startErr
	}
	return ipc.Result{Device: "hop0", FD: f.fd, Token: tunnel.Token("t")}, nil
}

func (f *fakeControl) Attach(tunnel.Token) (ipc.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.attachErr == nil {
		f.attachErr = errors.New("реаттача нет")
	}
	return ipc.Result{}, f.attachErr
}

func (f *fakeControl) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped++
	return nil
}

func (f *fakeControl) Heartbeat() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beats++
	return f.beatErr
}

func (f *fakeControl) Detach(tunnel.Reason) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detached++
	return nil
}

func (f *fakeControl) Status() (tunnel.State, error) {
	return tunnel.State{Phase: tunnel.Up}, nil
}

func (f *fakeControl) setBeatErr(err error) {
	f.mu.Lock()
	f.beatErr = err
	f.mu.Unlock()
}

func (f *fakeControl) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopped, f.detached
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestW39AcquireGivesDeviceOverTheFD — устройство поверх приехавшего
// дескриптора действительно читает и пишет.
//
// Дескриптор берётся от os.Pipe, а не от /dev/net/tun: агент по построению не
// может открыть TUN (§6.8) и получает готовый дескриптор — какой именно, ему
// всё равно. Проверяется ровно это свойство: устройство работает поверх того,
// что дали, и ничего не открывает само.
func TestW39AcquireGivesDeviceOverTheFD(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("труба: %v", err)
	}
	defer r.Close()
	defer w.Close()

	fc := &fakeControl{fd: int(r.Fd())}
	tr := newTransport(fc, filepath.Join(t.TempDir(), "token"), time.Hour, quietLog()) //hop:realtime
	defer tr.close()

	dev, err := tr.Acquire(tunnel.Params{Name: "hop0", MTU: 1400})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if dev.MTU() != 1400 {
		t.Errorf("MTU %d, ожидался 1400", dev.MTU())
	}

	want := []byte{0x45, 0x00, 0x00, 0x14}
	go func() { w.Write(want) }()

	bufs := [][]byte{make([]byte, 1400)}
	n, err := dev.ReadPackets(bufs)
	if err != nil {
		t.Fatalf("ReadPackets: %v", err)
	}
	if n != 1 {
		t.Fatalf("прочитано %d пакетов, ожидался 1", n)
	}
	if string(bufs[0]) != string(want) {
		t.Errorf("прочитано % x, ожидалось % x", bufs[0], want)
	}
}

// TestW40LostClosesOnceOnHeartbeatFailure — сорвавшийся heartbeat закрывает
// Lost, и ровно один раз (Р41).
//
// «Ровно один раз» — не педантизм: close закрытого канала паникует, а
// heartbeat крутится в цикле и сорвётся столько раз, сколько его позовут.
func TestW40LostClosesOnceOnHeartbeatFailure(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("труба: %v", err)
	}
	defer r.Close()
	defer w.Close()

	fc := &fakeControl{fd: int(r.Fd())}
	tr := newTransport(fc, filepath.Join(t.TempDir(), "token"), 10*time.Millisecond, quietLog()) //hop:realtime
	defer tr.close()

	if _, err := tr.Acquire(tunnel.Params{Name: "hop0", MTU: 1400}); err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	select {
	case <-tr.Lost():
		t.Fatal("Lost закрыт при живом сервисе: агент снял бы туннель на ровном месте")
	case <-time.After(50 * time.Millisecond): //hop:realtime
	}

	fc.setBeatErr(errors.New("сервис умер"))

	select {
	case <-tr.Lost():
	case <-time.After(2 * time.Second): //hop:realtime
		t.Fatal("сорвавшийся heartbeat не закрыл Lost — смерть сервиса осталась незамеченной (Р34)")
	}
}

// TestAcquireStopsTunnelWhenDeviceFails — туннель поднят, устройства нет:
// оставить так значило бы маршруты в никуда, то есть чёрную дыру вместо
// отказа (§5.6). Ровно тот дефект, которым этап С и был вызван.
func TestAcquireStopsTunnelWhenDeviceFails(t *testing.T) {
	fc := &fakeControl{fd: -1}                                                         // сервис дескриптора не прислал
	tr := newTransport(fc, filepath.Join(t.TempDir(), "token"), time.Hour, quietLog()) //hop:realtime
	defer tr.close()

	if _, err := tr.Acquire(tunnel.Params{Name: "hop0", MTU: 1400}); err == nil {
		t.Fatal("Acquire без дескриптора прошёл молча")
	}
	stopped, _ := fc.counts()
	if stopped != 1 {
		t.Errorf("туннель снят %d раз, ожидался 1: иначе маршруты остались бы вести в никуда", stopped)
	}
}

// TestW45AcquireStopsTunnelWhenTokenSaveFails — та же чёрная дыра, но на шаг
// раньше: интерфейс создан и маршруты разложены, а токен записать не вышло.
//
// Откат по отказу устройства стоит ниже по коду и до этого места не доходит,
// поэтому без своего отката здесь агент выходил бы, оставляя hopd с поднятым
// туннелем без датаплейна: трафик уходит в интерфейс, из которого его никто не
// читает (§5.6).
func TestW45AcquireStopsTunnelWhenTokenSaveFails(t *testing.T) {
	fc := &fakeControl{fd: -1}
	tr := newTransport(fc, unwritableTokenPath(t), time.Hour, quietLog()) //hop:realtime
	defer tr.close()

	if _, err := tr.Acquire(tunnel.Params{Name: "hop0", MTU: 1400}); err == nil {
		t.Fatal("Acquire прошёл молча, хотя токен записать не вышло")
	}
	stopped, _ := fc.counts()
	if stopped != 1 {
		t.Errorf("туннель снят %d раз, ожидался 1: hopd остался бы с интерфейсом и маршрутами, "+
			"но без агента и датаплейна", stopped)
	}
}

// unwritableTokenPath — путь, по которому saveToken честно не запишет: каталог
// подменён файлом, и MkdirAll упрётся в него так же, как упёрся бы в
// недоступный на запись /run/user/<uid>/hop. Подменять saveToken ради проверки
// не пришлось — отказывает настоящая файловая система.
func unwritableTokenPath(t *testing.T) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "hop")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatalf("подготовка непригодного каталога: %v", err)
	}
	return filepath.Join(blocker, "attach-token")
}

func (f *fakeControl) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

func (f *fakeControl) closes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// TestW71ControlWaitsForTheServiceAndKeepsTheOneConnection — агент не выходит,
// пока сервиса нет, и берёт его, как только он появился.
//
// До этого прохода `hop agent` соединялся с сервисом первой строкой runAgent:
// без hopd — «фоновая половина hop недоступна», код 2, за 11 мс, ни одной
// попытки. Автозапуск §6.13 (`systemctl --global enable hop-agent.service`)
// превращает это в цикл перезапусков на каждом логине, обогнавшем hopd.
//
// Проверяются три утверждения, и третье — не педантизм. (1) Пока dial
// отказывает, ожидание не кончается и агента не роняет. (2) Как только dial
// проходит, соединение установлено и им можно пользоваться. (3) Дальше dial
// БОЛЬШЕ НЕ ЗОВЁТСЯ: обрыв управляющего соединения — это ребро §6.2, сервис по
// нему решает, что агент ушёл, и переподключение поверх осиротевшего туннеля
// означало бы второй сеанс, ничего не знающий о первом (ipc.Client тоже
// говорит об этом прямо). Без (3) «ждёт сервис» неотличимо от «дозванивается
// заново на каждый вызов».
func TestW71ControlWaitsForTheServiceAndKeepsTheOneConnection(t *testing.T) {
	fc := &fakeControl{fd: -1}
	var mu sync.Mutex
	dials, alive := 0, false
	svc := newLazyControl(func() (controlConn, error) {
		mu.Lock()
		defer mu.Unlock()
		dials++
		if !alive {
			return nil, errors.New("сокет /run/hop.sock: connect: no such file or directory")
		}
		return fc, nil
	}, quietLog())

	// (1) Сервиса нет: обращение отказывает, но ожидание не сдаётся.
	if _, err := svc.Status(); err == nil {
		t.Fatal("Status прошёл при отсутствующем сервисе")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.wait(ctx, time.Millisecond) }() //hop:realtime
	select {
	case err := <-done:
		t.Fatalf("ожидание кончилось, хотя сервиса нет: %v — агент вышел бы кодом 2", err)
	case <-time.After(50 * time.Millisecond): //hop:realtime
	}

	// (2) Сервис появился — тот же процесс его берёт, без перезапуска.
	mu.Lock()
	alive = true
	mu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("сервис появился, а ожидание отказало: %v", err)
		}
	case <-time.After(5 * time.Second): //hop:realtime
		cancel()
		t.Fatal("сервис появился, а ожидание не кончилось")
	}
	cancel()

	mu.Lock()
	afterWait := dials
	mu.Unlock()

	// (3) Соединение одно: следующие вызовы идут по нему, а не дозваниваются.
	for i := 0; i < 3; i++ {
		if _, err := svc.Status(); err != nil {
			t.Fatalf("Status по установленному соединению: %v", err)
		}
	}
	mu.Lock()
	total := dials
	mu.Unlock()
	if total != afterWait {
		t.Errorf("dial позван ещё %d раз после того, как соединение установлено: "+
			"обрыв соединения — ребро §6.2, и второй сеанс поверх осиротевшего туннеля "+
			"о первом ничего не знает", total-afterWait)
	}

	// Закрытие — обязанность того, кто соединение открыл: до этого прохода его
	// закрывал `defer cl.Close()` в runAgent, и вместе с ранним dial ушёл бы и он.
	if err := svc.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := fc.closes(); got != 1 {
		t.Errorf("соединение закрыто %d раз, ожидался 1", got)
	}
}

// TestW71WaitEndsOnSignalNotOnItsOwnDeadline — ожидание сервиса обрывается
// только сигналом.
//
// Своего дедлайна у него нет намеренно: hop-agent.service тоже не держит о нём
// мнения, а агент, сдавшийся по таймеру, вернул бы ровно тот отказ, ради
// которого проход и был начат. Но обрываться он ОБЯЗАН: run() ловит SIGTERM до
// этой ветки, и агент, не слышащий сигнала, висел бы на `systemctl stop` до
// таймаута юнита.
func TestW71WaitEndsOnSignalNotOnItsOwnDeadline(t *testing.T) {
	svc := newLazyControl(func() (controlConn, error) {
		return nil, errors.New("сервиса нет и не будет")
	}, quietLog())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.wait(ctx, time.Millisecond) }() //hop:realtime

	select {
	case err := <-done:
		t.Fatalf("ожидание кончилось само: %v", err)
	case <-time.After(100 * time.Millisecond): //hop:realtime
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("ожидание вернуло %v, ожидалась отмена ctx", err)
		}
	case <-time.After(5 * time.Second): //hop:realtime
		t.Fatal("ожидание не услышало отмены — `systemctl stop` висел бы до таймаута юнита")
	}
}
