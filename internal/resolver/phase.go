package resolver

import (
	"context"

	"github.com/shafed/hop/internal/dnsmsg"
)

// ЗАГЛУШКА ЭТАПА. Файл принадлежит задаче З7: фазы трафика, удержание в
// waiting, fail-close и сброс кэша по подписке (Р15, Р16, Р25, D9–D13,
// D16–D20). Сейчас гейт пропускает всё через узел, чтобы задачи З4–З6 имели
// компилируемую спину.

// gate — что делать с запросом в текущей фазе трафика.
//
// Возвращает маршрут наверх либо ошибку, означающую отказ клиенту: спина
// превращает её в SERVFAIL, и в кэш при этом не заглядывает (Р15).
func (r *Resolver) gate(_ context.Context, _ dnsmsg.Msg) (route, error) {
	return routeNode, nil
}

// watchSwitches — подписка §5.7: кэш сбрасывает сам резолвер.
func (r *Resolver) watchSwitches() {
	defer r.wg.Done()
	for {
		select {
		case <-r.done:
			return
		case _, ok := <-r.cfg.Events:
			if !ok {
				return
			}
			r.flush()
		}
	}
}

// flush выкидывает кэш целиком и двигает Generation. Наблюдаемость счётчиком,
// а не последствием: без неё D19 зелен и в реализации, где кэша нет вовсе.
func (r *Resolver) flush() {
	r.cache.reset()
	r.cnt.generation.Add(1)
}
