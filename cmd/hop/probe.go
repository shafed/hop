package main

import (
	"context"
	"fmt"
	"net"

	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/store"
)

// probeNodes проверяет каждый узел из стора и собирает вывод команды.
//
// Зачем отдельный режим, когда пробы и так идут внутри агента: агент требует
// поднятого туннеля, то есть root и работающего hopd, и его отказ не отвечает
// на вопрос, чей он. Здесь поднимается только движок — ни TUN, ни маршрутов, ни
// прав, — и «узел не отвечает» отделяется от «туннель не доносит». Без этого
// разделения любая поломка выглядит одинаково: тишина.
//
// Путь пробы тот же, что в продукте (§6.7): дозвон через outbound проверяемого
// узла, те же три URL, та же сводка §5.4. Отличается только владелец движка.
//
// Печатает не она, а emit (§5.9): здесь собирается значение, а как его подать —
// человеку таблицей или машине в JSON — решает одна точка на весь бинарь.
func probeNodes(ctx context.Context, st *store.Store, physical engine.InterfaceFunc) (probeOut, error) {
	var nodes []store.Node
	for _, g := range st.Groups() {
		for _, n := range st.Nodes(g.ID) {
			if n.Supported {
				nodes = append(nodes, n)
			}
		}
	}
	// Пустой стор — ошибка конфигурации (код 1), а не fail-close (код 3):
	// «живых узлов нет» и «узлов нет вовсе» требуют от человека разного.
	if len(nodes) == 0 {
		return probeOut{}, fmt.Errorf("в сторе нет ни одного поддержанного узла")
	}

	en := make([]engine.Node, 0, len(nodes))
	for _, n := range nodes {
		en = append(en, n.ToEngine())
	}
	// OnFailure не задаётся: живости здесь нет, а вердикт §6.15 и так вернётся
	// вызывающему вместе с ошибкой.
	e, err := engine.NewWithConfig(engine.Config{Nodes: en, Physical: physical})
	if err != nil {
		return probeOut{}, fmt.Errorf("движок не собрался: %w", err)
	}
	defer e.Close()

	p := newProber(func(ctx context.Context, nodeID, _, addr string) (net.Conn, error) {
		return e.DialTCP(engine.WithProbe(ctx), nodeID, addr)
	})

	v := probeOut{Nodes: make([]probeNodeOut, 0, len(nodes))}
	for _, n := range nodes {
		c, cancel := context.WithTimeout(ctx, health.DefaultProbeTimeout)
		res := p.Probe(c, n.ID)
		cancel()

		out := probeNodeOut{ID: n.ID, Name: n.Name, Server: n.Server, Port: n.Port}
		if res.Err != nil {
			out.Error = res.Err.Error()
		} else {
			out.Alive = true
			out.RTTMs = res.RTT.Milliseconds()
			v.Alive++
		}
		v.Nodes = append(v.Nodes, out)
	}
	return v, nil
}
