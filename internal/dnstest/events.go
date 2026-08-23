package dnstest

import (
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/health"
)

// NewSwitchEvents создаёт канал событий переключения для Config.Events.
//
// Небуферизованный — как настоящий internal/health.Manager.Events(). Но это
// даёт меньше, чем кажется: завершившаяся отправка в такой канал доказывает
// только то, что резолвер начал читать из канала (Send разблокировался в
// момент <-Events), а не то, что он закончил на событие реагировать —
// например, сбросил кэш. Между этими двумя моментами резолвер ещё работает в
// своей горутине, ничем с отправителем не связанной. Тест, который сразу
// после Send читает Snapshot(), гонится с этой горутиной: проходит на
// быстрой машине, падает под -race и в CI.
//
// Признак «событие обработано» обязан быть на стороне наблюдателя — тот же
// приём, что несёт Clock.WaitAfterCalls для ожидания на часах: не гадать по
// самому факту отправки, а дождаться следа, который оставляет реакция.
// Обычно это счётчик поколения резолвера после сброса кэша. Дождаться такого
// следа без гонки и без риска зависнуть навсегда — WaitObserved.
func NewSwitchEvents() chan health.SwitchEvent {
	return make(chan health.SwitchEvent)
}

// waitObservedPoll — интервал опроса в WaitObserved. Настоящее время, не
// clock.Clock из Config: это сторожевой шаг сторожевого таймаута, а не
// модель поведения продукта, — тот же приём, которым internal/packettest
// бережёт WaitEmitted через clock.System.
const waitObservedPoll = time.Millisecond

// WaitObserved вызывает observe в цикле, пока тот не вернёт true, и
// возвращает true. Если это не случится за timeout — возвращает false вместо
// того, чтобы виснуть навсегда.
//
// Зачем: у произвольного observe (внешнего состояния резолвера — например,
// счётчика поколения) нет своего канала уведомлений, который стенд мог бы
// разбудить, в отличие от Clock.WaitAfterCalls и Upstream.WaitQueries,
// которые будят сами себя, потому что сами меняют наблюдаемое ими состояние.
// Опрос — единственный способ дождаться значения, которым стенд не владеет.
//
// Типичное использование при обработке события переключения (D19, D20,
// D55) — там, где раньше был бы гонка на одной законченной отправке в канал:
//
//	events <- health.SwitchEvent{}
//	if !dnstest.WaitObserved(time.Second, func() bool {
//	        return r.Snapshot().Generation == wantGeneration
//	}) {
//	        t.Fatal("резолвер не обработал событие переключения")
//	}
//
// timeout меряется настоящими часами (clock.System), не Config.Clock:
// это сторожевой таймаут теста на случай бага, а не часть модели, которую
// продвигает Advance, — иначе дождаться таймаута можно было бы, только
// докрутив часы вручную, а WaitObserved как раз избавляет тест от этого
// ручного управления.
func WaitObserved(timeout time.Duration, observe func() bool) bool {
	deadline := clock.System{}.After(timeout)
	for {
		if observe() {
			return true
		}
		select {
		case <-deadline:
			// Последний шанс: observe мог стать true ровно на грани
			// дедлайна, между последней проверкой и его срабатыванием.
			return observe()
		case <-clock.System{}.After(waitObservedPoll):
		}
	}
}
