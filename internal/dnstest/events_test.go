package dnstest

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/health"
)

// TestWaitObservedWaitsForTheRealChangeNotTheSend — регрессионный тест на В4
// (.superpowers/sdd/handoff-md-wondrous-boole/wave1-review.md): доказывает,
// что WaitObserved действительно ждёт следа реакции наблюдаемой стороны, а не
// одного факта отправки в канал, которого раньше (ошибочно) хватало по
// doc-комментарию NewSwitchEvents.
func TestWaitObservedWaitsForTheRealChangeNotTheSend(t *testing.T) {
	events := NewSwitchEvents()
	var generation atomic.Int64
	proceed := make(chan struct{}) // тест сам решает, когда наблюдателю можно отреагировать

	go func() {
		<-events
		<-proceed
		generation.Add(1)
	}()

	events <- health.SwitchEvent{}
	if got := generation.Load(); got != 0 {
		t.Fatalf("generation = %d сразу после Send, реакция не должна была успеть", got)
	}

	waited := make(chan bool, 1)
	go func() {
		waited <- WaitObserved(time.Second, func() bool { return generation.Load() == 1 })
	}()

	// Пока proceed не закрыт, наблюдаемое значение не меняется, и WaitObserved
	// обязан всё ещё ждать — вернуться раньше значило бы, что он поверил
	// самому факту Send, а не следу реакции (это и есть В4).
	select {
	case <-waited:
		t.Fatal("WaitObserved вернулся раньше, чем наблюдаемое значение стало истинным")
	case <-clock.System{}.After(10 * waitObservedPoll):
	}

	close(proceed)

	select {
	case ok := <-waited:
		if !ok {
			t.Fatal("WaitObserved не дождался реакции наблюдателя")
		}
	case <-clock.System{}.After(time.Second):
		t.Fatal("WaitObserved не вернулся после того, как условие стало истинным")
	}
}

// TestWaitObservedTimesOutInstead проверяет отказ по таймауту: помощник не
// имеет права виснуть навсегда, если наблюдаемое значение не наступает.
func TestWaitObservedTimesOutInstead(t *testing.T) {
	done := make(chan bool, 1)
	go func() {
		done <- WaitObserved(10*waitObservedPoll, func() bool { return false })
	}()

	select {
	case ok := <-done:
		if ok {
			t.Fatal("WaitObserved вернул true на условии, которое никогда не станет истинным")
		}
	case <-clock.System{}.After(time.Second):
		t.Fatal("WaitObserved не отказал по собственному таймауту — завис")
	}
}

// TestWaitObservedReturnsAsSoonAsTrue проверяет, что помощник не ждёт полный
// таймаут, если условие уже истинно к первому вызову.
func TestWaitObservedReturnsAsSoonAsTrue(t *testing.T) {
	if !WaitObserved(time.Second, func() bool { return true }) {
		t.Fatal("WaitObserved = false на изначально истинном условии")
	}
}
