package resolver

import (
	"context"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dnsmsg"
)

// ЗАГЛУШКА ЭТАПА. Файл принадлежит задаче З5: TTL и его границы,
// отрицательный кэш, ключ и регистр имени, потолок и LRU, склейка в полёте
// (Р17, Р18, Р23, Р24, D21–D32, D38, D39). Сейчас кэша нет: каждый вопрос
// идёт наверх.

// cache — общий на процесс кэш ответов.
type cache struct{ clk clock.Clock }

func newCache(clk clock.Clock) *cache { return &cache{clk: clk} }

// size — записей всего и из них отрицательных.
func (c *cache) size() (entries, negative int) { return 0, 0 }

// reset выкидывает всё. Зовётся только из flush (Р25, §5.7в).
func (c *cache) reset() {}

// flightGroup — склейка одинаковых вопросов в полёте (Р24).
type flightGroup struct{}

func newFlightGroup() *flightGroup { return &flightGroup{} }

// lookup — попадание в кэш либо поход наверх. Промах кэша и есть поход
// наверх, поэтому шаг один: иначе между проверкой и запросом появляется окно,
// в котором склейка не работает.
func (r *Resolver) lookup(ctx context.Context, q dnsmsg.Msg, rt route) (dnsmsg.Msg, error) {
	r.cnt.misses.Add(1)
	return r.ask(ctx, q, rt)
}
