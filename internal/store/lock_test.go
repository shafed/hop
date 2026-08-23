// Замок стора — docs/verification-store.md §5.4, S28 и решение Р14.
//
// Проверка идёт двумя процессами, а не двумя горутинами: замок
// рекомендательный и берётся на дескриптор, поэтому внутрипроцессную гонку он
// не ловит вовсе — её ловит txMu, а S28 не про неё. Второй процесс — это тот
// же бинарь тестов, перезапущенный с HOP_TEST_STORE_* в окружении.
package store

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"sync"
	"testing"
	"time" //hop:realtime — шаг прокрутки фейковых часов во втором процессе

	"github.com/shafed/hop/internal/clock"
)

const (
	envHelperDir  = "HOP_TEST_STORE_DIR"
	envHelperMode = "HOP_TEST_STORE_MODE"

	// modeRefuse — замок держат: второй писатель обязан подождать и отказать.
	modeRefuse = "refuse"
	// modeAppend — замок свободен: второй писатель обязан дописать свой узел.
	modeAppend = "append"
)

// TestS28SecondWriterWaitsThenFails — S28.
func TestS28SecondWriterWaitsThenFails(t *testing.T) {
	s, dir := newStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))
	if err := s.Flush(); err != nil {
		t.Fatalf("первая запись не прошла: %v", err)
	}

	// Замок держится ровно столько, сколько идёт второй процесс. Держать его
	// изнутри транзакции, а не «поспать пять секунд», можно как раз потому,
	// что слой записи инъектируем.
	locked := make(chan struct{})
	release := make(chan struct{})
	held := make(chan error, 1)
	go func() {
		held <- s.transact(func() error {
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked

	// Отпустить замок обязано и падение проверки: иначе упавший тест повиснет
	// на закрытии стора, и красный результат превратится в таймаут.
	var once sync.Once
	unhold := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unhold)

	runHelper(t, dir, modeRefuse)

	unhold()
	if err := <-held; err != nil {
		t.Fatalf("транзакция, державшая замок, отказала: %v", err)
	}

	// Замок отпущен — второй процесс дописывает свой узел.
	runHelper(t, dir, modeAppend)

	// Записи не потеряны: отказавший писатель не затёр чужое, а дождавшийся
	// дописал к чужому, а не поверх него.
	if err := s.Close(); err != nil {
		t.Fatalf("закрытие не прошло: %v", err)
	}
	s2 := openStore(t, dir)
	got := nodeIDs(s2.Nodes("g"))
	slices.Sort(got)
	if !slices.Equal(got, []string{"n1", "n2"}) {
		t.Errorf("в сторе %v, а обязаны быть оба узла: n1 от первого писателя, n2 от второго", got)
	}
}

// runHelper запускает второй процесс — тот же бинарь тестов — и требует, чтобы
// его собственные проверки прошли.
func runHelper(t *testing.T, dir, mode string) {
	t.Helper()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("не найти собственный бинарь: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestS28Helper$", "-test.v")
	cmd.Env = append(os.Environ(), envHelperDir+"="+dir, envHelperMode+"="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("второй процесс в режиме %q отработал не так, как обязан: %v\n%s", mode, err, out)
	}
}

// TestS28Helper — второй процесс. Без HOP_TEST_STORE_DIR пропускается: обычный
// прогон пакета его не запускает.
func TestS28Helper(t *testing.T) {
	dir := os.Getenv(envHelperDir)
	if dir == "" {
		t.Skip("вспомогательный процесс S28: запускается из TestS28SecondWriterWaitsThenFails")
	}

	// Ожидание замка идёт по часам, поэтому фейковые часы, которые крутит
	// отдельная горутина, превращают пять секунд ожидания в миллисекунды
	// реального времени — и при этом проверяют именно те пять секунд.
	clk := clock.NewFake(testEpoch)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			time.Sleep(time.Millisecond) //hop:realtime — шаг прокрутки модельного времени
			clk.Advance(200 * time.Millisecond)
		}
	}()
	defer func() {
		close(stop)
		wg.Wait()
	}()

	s, err := Open(dir, clk)
	if err != nil {
		t.Fatalf("второй процесс не открыл стор: %v", err)
	}
	addNode(t, s, node("n2", "g", "b.example"))

	start := clk.Now()
	err = s.Flush()

	switch mode := os.Getenv(envHelperMode); mode {
	case modeRefuse:
		if err == nil {
			t.Fatal("второй писатель прошёл сквозь замок: одновременные правки теряют одну из них")
		}
		if !errors.Is(err, ErrLocked) {
			t.Fatalf("ошибка не про занятый стор, чинить нечего: %v", err)
		}
		if waited := clk.Now().Sub(start); waited < lockTimeout {
			t.Fatalf("ждал %s, а обязан ждать до %s", waited, lockTimeout)
		}
	case modeAppend:
		if err != nil {
			t.Fatalf("замок свободен, а запись не прошла: %v", err)
		}
	default:
		t.Fatalf("неизвестный режим %q", mode)
	}

	// В режиме refuse закрытие снова упрётся в замок — это ожидаемо, и его
	// ошибка ничего не добавляет к уже проверенному.
	_ = s.Close()
}
