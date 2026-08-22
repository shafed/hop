package resolver

import (
	"context"
	"errors"

	"github.com/shafed/hop/internal/dnsmsg"
)

// ЗАГЛУШКА ЭТАПА. Файл принадлежит задаче З4: два апстрима с форой, таймаут
// попытки и общий бюджет, повтор по TCP на флаг TC, усечение к клиенту
// (D1, D14, D15, D33–D37, D40–D44). Сейчас наверх не ходит вовсе.

var errNoUpstream = errors.New("resolver: апстримы ещё не реализованы (З4)")

// ask спрашивает апстримы и возвращает ответ, годный для кэша и для клиента.
func (r *Resolver) ask(_ context.Context, _ dnsmsg.Msg, _ route) (dnsmsg.Msg, error) {
	return dnsmsg.Msg{}, errNoUpstream
}

// fit — ответ клиенту: его идентификатор и потолок его буфера.
//
// Клиент по TCP получает сообщение целиком; клиент по UDP — не больше
// объявленного им буфера EDNS0, а не влезло — заголовок с вопросом и поднятым
// TC, а не обрезанные байты RRset (D34).
func (r *Resolver) fit(q dnsmsg.Msg, answer dnsmsg.Msg, tr Transport) ([]byte, error) {
	limit := StreamMax
	if tr == TransportUDP {
		limit = ClientUDPDefault
		if n, err := q.BufferSize(); err == nil && n > limit {
			limit = n
		}
	}
	fitted, truncated, err := dnsmsg.Fit(dnsmsg.Reply(answer, q.Header.ID), limit)
	if err != nil {
		return nil, err
	}
	if truncated {
		r.cnt.truncToClient.Add(1)
	}
	return fitted, nil
}

// fitRaw — то же для ответа, который резолвер собрал сам (отказ, синтез AAAA).
// Разбор собственной сборки стоит одного прохода по заголовку и вопросу и
// держит один путь усечения на все ответы, а не два.
func (r *Resolver) fitRaw(q dnsmsg.Msg, raw []byte, tr Transport) ([]byte, error) {
	m, err := dnsmsg.Parse(raw)
	if err != nil {
		return nil, err
	}
	return r.fit(q, m, tr)
}
