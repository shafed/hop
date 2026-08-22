package dnstest

import (
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
)

// TestClockWaitAfterCallsBlocksUntilAfterIsCalled проверяет саму гонку,
// которую Clock обязан закрывать: WaitAfterCalls не имеет права вернуться,
// пока проверяемая горутина не дошла до After — иначе Advance в тесте
// резолвера будет иногда происходить раньше регистрации ожидания.
func TestClockWaitAfterCallsBlocksUntilAfterIsCalled(t *testing.T) {
	fake := clock.NewFake(time.Unix(0, 0))
	clk := NewClock(fake)

	done := make(chan struct{})
	go func() {
		<-clk.After(time.Second)
		close(done)
	}()

	clk.WaitAfterCalls(1)
	// В этой точке горутина гарантированно уже внутри After — можно двигать
	// часы, не рискуя, что Advance проскочит раньше регистрации ожидания.
	fake.Advance(time.Second)

	select {
	case <-done:
	case <-clock.System{}.After(time.Second): // сторожевой таймаут теста, не модель продукта
		t.Fatal("канал After не сработал после Advance")
	}
}

func TestClockAfterCallsCounts(t *testing.T) {
	fake := clock.NewFake(time.Unix(0, 0))
	clk := NewClock(fake)

	if got := clk.AfterCalls(); got != 0 {
		t.Fatalf("AfterCalls() = %d, хочу 0", got)
	}
	clk.After(time.Second)
	clk.After(time.Second)
	if got := clk.AfterCalls(); got != 2 {
		t.Fatalf("AfterCalls() = %d, хочу 2", got)
	}
}

// TestClockPassesThroughNow проверяет, что обёртка не заслоняет остальную
// часть clock.Clock — Now должен идти напрямую к обёрнутым часам.
func TestClockPassesThroughNow(t *testing.T) {
	start := time.Unix(1000, 0)
	fake := clock.NewFake(start)
	clk := NewClock(fake)

	if got := clk.Now(); !got.Equal(start) {
		t.Fatalf("Now() = %v, хочу %v", got, start)
	}
	fake.Advance(5 * time.Second)
	if got := clk.Now(); !got.Equal(start.Add(5 * time.Second)) {
		t.Fatalf("Now() после Advance = %v, хочу %v", got, start.Add(5*time.Second))
	}
}
