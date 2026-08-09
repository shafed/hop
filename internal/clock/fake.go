package clock

import (
	"sort"
	"sync"
	"time" //hop:realtime
)

// Fake — часы с ручной прокруткой. Advance двигает время и срабатывает всё,
// чей срок наступил, в порядке сроков.
type Fake struct {
	mu      sync.Mutex
	now     time.Time
	waiters []*waiter
}

type waiter struct {
	at     time.Time
	ch     chan time.Time
	period time.Duration // 0 для After, >0 для тикера
	dead   bool
}

// NewFake создаёт часы, стоящие на t.
func NewFake(t time.Time) *Fake { return &Fake{now: t} }

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *Fake) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := &waiter{at: f.now.Add(d), ch: make(chan time.Time, 1)}
	f.waiters = append(f.waiters, w)
	return w.ch
}

func (f *Fake) NewTicker(d time.Duration) Ticker {
	if d <= 0 {
		panic("clock: неположительный интервал тикера")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	w := &waiter{at: f.now.Add(d), ch: make(chan time.Time, 1), period: d}
	f.waiters = append(f.waiters, w)
	return &fakeTicker{f: f, w: w}
}

// Advance двигает время на d и доставляет всё, что за это время наступило.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	target := f.now.Add(d)
	for {
		next := f.earliestLocked(target)
		if next == nil {
			break
		}
		f.now = next.at
		select {
		case next.ch <- next.at:
		default: // получатель ещё не забрал прошлый тик — как у time.Ticker
		}
		if next.period > 0 {
			next.at = next.at.Add(next.period)
		} else {
			next.dead = true
		}
	}
	f.now = target
	f.gcLocked()
}

func (f *Fake) earliestLocked(limit time.Time) *waiter {
	var best *waiter
	for _, w := range f.waiters {
		if w.dead || w.at.After(limit) {
			continue
		}
		if best == nil || w.at.Before(best.at) {
			best = w
		}
	}
	return best
}

func (f *Fake) gcLocked() {
	alive := f.waiters[:0]
	for _, w := range f.waiters {
		if !w.dead {
			alive = append(alive, w)
		}
	}
	f.waiters = alive
	sort.Slice(f.waiters, func(i, j int) bool { return f.waiters[i].at.Before(f.waiters[j].at) })
}

type fakeTicker struct {
	f *Fake
	w *waiter
}

func (t *fakeTicker) C() <-chan time.Time { return t.w.ch }

func (t *fakeTicker) Stop() {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	t.w.dead = true
}
