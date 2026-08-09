// Package health — политика живости узлов. В этапе 0 здесь только интерфейс
// пробера: §3.4 требует, чтобы пробер и часы были интерфейсами, а не прямыми
// вызовами, иначе T1–T8 придётся гонять на настоящей сети и настоящем времени.
package health

import (
	"context"
	"time" //xrayvpn:realtime
)

// Result — исход одной пробы.
type Result struct {
	RTT time.Duration
	Err error // nil — успех; иначе fail/timeout
}

// Prober проверяет узел. Реализация v1 ходит через тот же outbound, что и
// трафик (§6.7); фейковая реализация тестов не ходит никуда.
type Prober interface {
	Probe(ctx context.Context, nodeID string) Result
}
