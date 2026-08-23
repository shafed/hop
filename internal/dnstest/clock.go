package dnstest

import (
	"sync"
	"time"

	"github.com/shafed/hop/internal/clock"
)

// Clock оборачивает clock.Clock и считает обращения к After.
//
// Зачем: и поддельный апстрим (задержка ответа, Behavior.Delay), и будущий
// резолвер (фора апстриму, таймаут попытки, удержание в waiting) регистрируют
// ожидание на одних и тех же часах. Тест обязан двигать часы (Advance)
// только после того, как проверяемая горутина реально встала в ожидание —
// иначе Advance иногда происходит раньше, чем горутина дошла до After, срок
// не наступает ни для кого, и тест либо виснет, либо иногда проходит, а
// иногда нет (самый частый способ получить флаки-тест на clock.Fake).
// Синхронный признак «встал в ожидание» — само обращение к After, и
// WaitAfterCalls блокируется до него, а не опрашивает часы в цикле.
//
// Цена: счётчик один на все обращения к After сразу у всех потребителей
// этого экземпляра часов, без различения, кто именно ждёт. Для L1-стенда
// этого достаточно — сценарии регистра ждут ровно одного нового ожидания за
// раз (§5, D41–D43, D12–D14); если когда-нибудь понадобится различать
// несколько параллельных ожидающих, считать нужно будет по метке, а не по
// общему числу.
type Clock struct {
	clock.Clock

	mu    sync.Mutex
	cond  *sync.Cond
	calls uint64
}

// NewClock оборачивает часы c. Резолвер и Upstream должны получить один и
// тот же *Clock через Config.Clock и через dnstest.New — иначе задержка
// апстрима и таймауты резолвера считают обращения к After по отдельности, и
// WaitAfterCalls в тесте ждёт не то количество.
func NewClock(c clock.Clock) *Clock {
	cl := &Clock{Clock: c}
	cl.cond = sync.NewCond(&cl.mu)
	return cl
}

// After — как у обёрнутых часов, плюс отметка «кто-то встал в ожидание».
func (c *Clock) After(d time.Duration) <-chan time.Time {
	ch := c.Clock.After(d)
	c.mu.Lock()
	c.calls++
	c.cond.Broadcast()
	c.mu.Unlock()
	return ch
}

// AfterCalls — сколько раз всего вызывали After.
func (c *Clock) AfterCalls() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// WaitAfterCalls блокируется, пока общее число обращений к After не достигнет
// n. Тест зовёт его перед Advance: так гонка «часы сдвинулись раньше, чем
// горутина встала в ожидание» невозможна в принципе — Advance физически не
// может выполниться раньше события, которого он дожидается.
func (c *Clock) WaitAfterCalls(n uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.calls < n {
		c.cond.Wait()
	}
}
