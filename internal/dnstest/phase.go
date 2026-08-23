package dnstest

import (
	"sync"

	"github.com/shafed/hop/internal/phase"
)

// Phase — управляемый источник фазы трафика для Config.Phase
// (docs/verification-dns.md §2, требование 3: резолвер получает функцию, а
// не булев Healthy — waiting, failing и bypass это три разных ответа
// резолвера, и одним битом их не свести). До этапа С, где связка даёт
// резолверу настоящую фазу, ставить её неоткуда, кроме как вручную — Set
// это и делает.
type Phase struct {
	mu sync.Mutex
	p  phase.Traffic
}

// NewPhase создаёт источник в фазе initial.
func NewPhase(initial phase.Traffic) *Phase {
	return &Phase{p: initial}
}

// Set меняет текущую фазу.
func (p *Phase) Set(v phase.Traffic) {
	p.mu.Lock()
	p.p = v
	p.mu.Unlock()
}

// Get — текущая фаза. Метод, а не поле: подпись совпадает с ожидаемым
// Config.Phase (func() phase.Traffic), и p.Get годится в конфиг напрямую, без
// обёртки в замыкание на каждый тест.
func (p *Phase) Get() phase.Traffic {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.p
}
