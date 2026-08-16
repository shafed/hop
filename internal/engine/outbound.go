package engine

import (
	"context"
	"errors"
	"net"
)

// Outbound — исходящее через **активный** узел.
//
// Движок работает с явным id узла: health выбирает, engine исполняет, и это
// разделение — часть §3.4. Но у резолвера (§5.7) выбора нет: он ходит туда же,
// куда трафик, и знать про health ему нечего. Outbound и есть этот стык —
// замыкание «какой узел сейчас активен» с двумя методами и без единого нового
// понятия.
//
// Смена узла меняет путь без единого вызова сюда: id спрашивается на каждом
// соединении, а не запоминается.
type Outbound struct {
	eng    *Engine
	active func() string
}

// NewOutbound связывает движок с выбором узла.
func NewOutbound(eng *Engine, active func() string) *Outbound {
	return &Outbound{eng: eng, active: active}
}

var errNoActive = errors.New("engine: активного узла нет")

// DialTCP открывает соединение к addr через активный узел.
func (o *Outbound) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	id := o.node()
	if id == "" {
		return nil, errNoActive
	}
	return o.eng.DialTCP(ctx, id, addr)
}

// DialUDP открывает UDP-сокет через активный узел.
func (o *Outbound) DialUDP(ctx context.Context) (net.PacketConn, error) {
	id := o.node()
	if id == "" {
		return nil, errNoActive
	}
	return o.eng.DialUDP(ctx, id)
}

func (o *Outbound) node() string {
	if o.active == nil {
		return ""
	}
	return o.active()
}
