package clock

import (
	"testing"
	"time" //hop:realtime
)

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestAdvanceFiresAfter(t *testing.T) {
	f := NewFake(epoch)
	ch := f.After(10 * time.Second)

	f.Advance(9 * time.Second)
	select {
	case <-ch:
		t.Fatal("сработало раньше срока")
	default:
	}

	f.Advance(time.Second)
	select {
	case at := <-ch:
		if !at.Equal(epoch.Add(10 * time.Second)) {
			t.Errorf("время срабатывания %v, ожидалось %v", at, epoch.Add(10*time.Second))
		}
	default:
		t.Fatal("не сработало в срок")
	}
}

func TestTickerRepeats(t *testing.T) {
	f := NewFake(epoch)
	tk := f.NewTicker(time.Second)
	defer tk.Stop()

	// Один Advance через несколько периодов даёт один доставленный тик:
	// у канала буфер 1, как у time.Ticker.
	f.Advance(3 * time.Second)
	if len(tk.C()) != 1 {
		t.Fatalf("тиков в канале %d, ожидался 1", len(tk.C()))
	}
	<-tk.C()

	f.Advance(time.Second)
	select {
	case <-tk.C():
	default:
		t.Fatal("тикер не сработал после дренажа")
	}
}

func TestStoppedTickerSilent(t *testing.T) {
	f := NewFake(epoch)
	tk := f.NewTicker(time.Second)
	tk.Stop()
	f.Advance(10 * time.Second)
	if len(tk.C()) != 0 {
		t.Fatal("остановленный тикер сработал")
	}
}

func TestNowMovesExactly(t *testing.T) {
	f := NewFake(epoch)
	f.After(time.Second) // ожидающий не должен сбить итоговое Now
	f.Advance(2500 * time.Millisecond)
	if got := f.Now(); !got.Equal(epoch.Add(2500 * time.Millisecond)) {
		t.Errorf("Now = %v, ожидалось %v", got, epoch.Add(2500*time.Millisecond))
	}
}
