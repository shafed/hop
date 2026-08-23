package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/store"
)

// probeNodes проверяет каждый узел из стора и печатает результат.
//
// Зачем отдельный режим, когда пробы и так идут внутри агента: агент требует
// поднятого туннеля, то есть root и работающего hopd, и его отказ не отвечает
// на вопрос, чей он. Здесь поднимается только движок — ни TUN, ни маршрутов, ни
// прав, — и «узел не отвечает» отделяется от «туннель не доносит». Без этого
// разделения любая поломка выглядит одинаково: тишина.
//
// Путь пробы тот же, что в продукте (§6.7): дозвон через outbound проверяемого
// узла, те же три URL, та же сводка §5.4. Отличается только владелец движка.
func probeNodes(ctx context.Context, st *store.Store, out io.Writer, physical engine.InterfaceFunc) error {
	var nodes []store.Node
	for _, g := range st.Groups() {
		for _, n := range st.Nodes(g.ID) {
			if n.Supported {
				nodes = append(nodes, n)
			}
		}
	}
	if len(nodes) == 0 {
		return fmt.Errorf("в сторе нет ни одного поддержанного узла")
	}

	en := make([]engine.Node, 0, len(nodes))
	for _, n := range nodes {
		en = append(en, n.ToEngine())
	}
	// OnFailure не задаётся: живости здесь нет, а вердикт §6.15 и так вернётся
	// вызывающему вместе с ошибкой.
	e, err := engine.NewWithConfig(engine.Config{Nodes: en, Physical: physical})
	if err != nil {
		return fmt.Errorf("движок не собрался: %w", err)
	}
	defer e.Close()

	p := newProber(func(ctx context.Context, nodeID, _, addr string) (net.Conn, error) {
		return e.DialTCP(engine.WithProbe(ctx), nodeID, addr)
	})

	for _, n := range nodes {
		c, cancel := context.WithTimeout(ctx, health.DefaultProbeTimeout)
		res := p.Probe(c, n.ID)
		cancel()

		name := n.Name
		if name == "" {
			name = n.ID[:min(8, len(n.ID))]
		}
		if res.Err != nil {
			fmt.Fprintf(out, "✗ %-20s %s:%d — %v\n", name, n.Server, n.Port, res.Err)
			continue
		}
		fmt.Fprintf(out, "✓ %-20s %s:%d — %s\n", name, n.Server, n.Port,
			res.RTT.Round(time.Millisecond)) //hop:realtime
	}
	return nil
}
