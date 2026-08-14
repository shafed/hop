package health

import "sync"

// eventQueue — неограниченная очередь событий с насосом в канал.
//
// Требование §2 верификации: события не теряются. Буферизованный канал их
// теряет ровно в интересном случае — когда переключений много, потому что сеть
// разваливается, а подписчик (CLI, а позже трей и GUI, §3.3) читает медленно.
// Отбрасывать переключение — значит соврать в hop events --follow.
type eventQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []SwitchEvent
	closed bool
	out    chan SwitchEvent
	quit   chan struct{}
}

func newEventQueue() *eventQueue {
	q := &eventQueue{out: make(chan SwitchEvent), quit: make(chan struct{})}
	q.cond = sync.NewCond(&q.mu)
	go q.pump()
	return q
}

func (q *eventQueue) push(ev SwitchEvent) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.items = append(q.items, ev)
	q.cond.Signal()
}

func (q *eventQueue) pump() {
	for {
		q.mu.Lock()
		for len(q.items) == 0 && !q.closed {
			q.cond.Wait()
		}
		if len(q.items) == 0 && q.closed {
			q.mu.Unlock()
			close(q.out)
			return
		}
		ev := q.items[0]
		q.items = q.items[1:]
		q.mu.Unlock()

		// После close непрочитанное отбрасывается: иначе насос остаётся
		// висеть на отправке в канал, который уже никто не читает.
		select {
		case q.out <- ev:
		case <-q.quit:
			close(q.out)
			return
		}
	}
}

func (q *eventQueue) close() {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	q.cond.Signal()
	q.mu.Unlock()
	close(q.quit)
}
