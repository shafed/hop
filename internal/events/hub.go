package events

import (
	"sync"

	"github.com/shafed/hop/internal/policy"
)

// subBuffer — глубина канала подписчика. События редкие; буфер нужен только
// затем, чтобы клиент, занятый отрисовкой, не терял переключение.
const subBuffer = 64

// Hub — рассылка событий всем подписчикам (§3.3).
//
// Два свойства, ради которых он существует и которые обязаны выполняться
// одновременно:
//
//  1. событие получает **каждый** подписчик, а не первый попавшийся;
//  2. медленный подписчик не тормозит остальных и не растит память: буфер
//     ограничен, и переполнивший его клиент отваливается целиком, а не копит
//     очередь до конца жизни агента.
//
// Второе — причина, по которой отправка не блокирующая: заклинивший трей не
// имеет права остановить автопереключение.
type Hub struct {
	mu     sync.Mutex
	subs   []*Sub
	closed bool
}

// Sub — один подписчик. Канал закрывается, когда подписку сняли, хаб закрыли
// или подписчик отстал.
type Sub struct {
	hub  *Hub
	ch   chan Event
	done bool // канал уже закрыт; под hub.mu
}

func NewHub() *Hub { return &Hub{} }

// Subscribe заводит подписчика. После Close отдаёт уже закрытый канал, чтобы
// читатель разошёлся сам, а не ждал вечно.
func (h *Hub) Subscribe() *Sub {
	h.mu.Lock()
	defer h.mu.Unlock()

	s := &Sub{hub: h, ch: make(chan Event, subBuffer)}
	if h.closed {
		s.done = true
		close(s.ch)
		return s
	}
	h.subs = append(h.subs, s)
	return s
}

// C — канал событий подписчика.
func (s *Sub) C() <-chan Event { return s.ch }

// Close снимает подписку. Идемпотентен: хаб мог отцепить подписчика раньше.
func (s *Sub) Close() {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	s.hub.dropLocked(s)
}

// Publish рассылает событие.
//
// Политика event_broadcast: при выключении рассылка вырождается в одного
// получателя — первого подписавшегося. Второй клиент (трей рядом с CLI) о
// переключении не узнаёт вовсе, и это краснит TestTwoClientsBothGetEvent.
func (h *Hub) Publish(ev Event) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Копия списка: отставший подписчик отцепляется прямо в цикле.
	for _, s := range append([]*Sub(nil), h.subs...) {
		select {
		case s.ch <- ev:
		default:
			// Буфер полон: подписчик не читает. Держать событие для него значило
			// бы либо остановить агента, либо растить очередь без предела.
			h.dropLocked(s)
		}
		if !policy.EventBroadcast.On() {
			return
		}
	}
}

// Close закрывает хаб и все подписки.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.closed = true
	for _, s := range append([]*Sub(nil), h.subs...) {
		h.dropLocked(s)
	}
}

func (h *Hub) dropLocked(s *Sub) {
	for i, x := range h.subs {
		if x == s {
			h.subs = append(h.subs[:i], h.subs[i+1:]...)
			break
		}
	}
	if !s.done {
		s.done = true
		close(s.ch)
	}
}
