// Package clock — единственное место в продукте, где разрешено обращаться к
// настоящему времени (§8.1: «Интервалы, окна и гистерезис тестируются
// инъектируемыми часами»). Правило поддерживается линтом cmd/realtimelint.
package clock

import "time" //hop:realtime

// Ticker — тикер за интерфейсом, чтобы фейковые часы могли его подменить.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// Clock — часы, которые получает всякий, кому нужно время.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
	NewTicker(d time.Duration) Ticker
}

// System — настоящие часы.
type System struct{}

func (System) Now() time.Time { return time.Now() } //hop:realtime

func (System) After(d time.Duration) <-chan time.Time { return time.After(d) } //hop:realtime

func (System) NewTicker(d time.Duration) Ticker {
	return systemTicker{time.NewTicker(d)} //hop:realtime
}

type systemTicker struct{ t *time.Ticker }

func (s systemTicker) C() <-chan time.Time { return s.t.C }
func (s systemTicker) Stop()               { s.t.Stop() }
