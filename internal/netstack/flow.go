package netstack

import (
	"sync"
	"time"

	"github.com/shafed/hop/internal/clock"
)

// flowTable — вердикты, принятые по первому пакету.
//
// Таблица нужна не ради скорости, а ради контракта §3.4: вердикт принимается
// **на первом пакете потока** и дальше не пересматривается. Без неё вердикт
// пересчитывался бы на каждом пакете, и смерть последнего узла посреди уже
// установленного соединения превращала бы его пакеты в RST в обход gvisor,
// который в этот момент этим соединением владеет. Новые потоки при этом
// отвергаются немедленно — ровно этого fail-close и хочет (§5.6).
type flowTable struct {
	clk  clock.Clock
	idle time.Duration

	mu    sync.Mutex
	m     map[flow]*flowEntry
	swept time.Time
}

type flowEntry struct {
	v    Verdict
	seen time.Time
}

func newFlowTable(clk clock.Clock, idle time.Duration) *flowTable {
	return &flowTable{clk: clk, idle: idle, m: make(map[flow]*flowEntry), swept: clk.Now()}
}

// verdict возвращает вердикт потока, принимая его при первой встрече.
func (t *flowTable) verdict(f flow, healthy func() bool) Verdict {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.clk.Now()
	t.sweepLocked(now)

	if e, ok := t.m[f]; ok {
		e.seen = now
		return e.v
	}
	v := classify(f, healthy())
	t.m[f] = &flowEntry{v: v, seen: now}
	return v
}

// peek — вердикт уже принятого потока. Возвращает 0, если потока нет: значит,
// пакет пришёл в стек мимо насоса, и доверять ему нечего.
func (t *flowTable) peek(f flow) Verdict {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.m[f]; ok {
		return e.v
	}
	return 0
}

// reset забывает вердикты. Зовётся только вместе с разрывом потоков (§5.5):
// потоков, которым эти вердикты принадлежали, больше нет, а пакет, пришедший
// следом, обязан получить вердикт по текущей живости.
func (t *flowTable) reset() {
	t.mu.Lock()
	clear(t.m)
	t.mu.Unlock()
}

func (t *flowTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// sweepLocked чистит просроченное. Реже, чем раз в половину простоя, смысла
// нет; чаще — лишняя работа на каждом пакете.
func (t *flowTable) sweepLocked(now time.Time) {
	if now.Sub(t.swept) < t.idle/2 {
		return
	}
	t.swept = now
	for f, e := range t.m {
		if now.Sub(e.seen) >= t.idle {
			delete(t.m, f)
		}
	}
}
