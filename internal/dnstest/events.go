package dnstest

import "github.com/shafed/hop/internal/health"

// NewSwitchEvents создаёт канал событий переключения для Config.Events.
//
// Небуферизованный — как настоящий internal/health.Manager.Events(): Send в
// такой канал вернётся только тогда, когда резолвер действительно прочитал
// событие, и тесту (D19, D20, D55) не нужно гадать, добралось ли оно, —
// достаточно, что отправка вообще завершилась.
func NewSwitchEvents() chan health.SwitchEvent {
	return make(chan health.SwitchEvent)
}
