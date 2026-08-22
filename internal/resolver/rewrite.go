package resolver

import "github.com/shafed/hop/internal/dnsmsg"

// ЗАГЛУШКА ЭТАПА. Файл принадлежит задаче З6: AAAA и ECS — единственные
// искажения, которые разрешает У6 (Р19, Р26, D45–D50). Сейчас ничего не
// синтезирует и ничего не вырезает.

// synthesize — ответ, который резолвер сочиняет сам, не спрашивая апстрим.
// nil означает «вопрос идёт наверх обычным путём».
func (r *Resolver) synthesize(_ dnsmsg.Msg) []byte { return nil }

// upstreamQuery — байты нашего запроса наверх: свой идентификатор, вырезанный
// ECS, объявленный буфер EDNS0 UpstreamEDNS.
func (r *Resolver) upstreamQuery(q dnsmsg.Msg, id uint16) ([]byte, error) {
	return dnsmsg.WithID(q.Raw, id)
}
