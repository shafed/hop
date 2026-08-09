package tunnel

import (
	"context"
	"time"

	"github.com/shafed/hop/internal/clock"
)

// Run будит машину по времени: истёкший orphan_deadline и заклинивший живой
// агент — единственные переходы, у которых нет внешнего события.
//
// Шаг тикера — доля heartbeat, чтобы задержка обнаружения не добавлялась к
// самим порогам. На точность дедлайна это не влияет: решение принимает
// Machine.expireLocked по часам, а не по числу тиков.
func Run(ctx context.Context, clk clock.Clock, m *Machine, step time.Duration) {
	if step <= 0 {
		step = 200 * time.Millisecond
	}
	t := clk.NewTicker(step)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			m.Poll()
		}
	}
}
