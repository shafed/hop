package main

import (
	"context"
	"log/slog"
	"strings"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/agent"
	"github.com/shafed/hop/internal/health"
)

// watch — единственное окно наружу до этапа 9.
//
// Связка держит фазу трафика, активный узел и кольцо событий (§2), но показать
// их некому: `hop status` с подкомандами и рассылкой событий — этап 9, а
// `-status` этапа 2 отвечает про фазу **сервиса**, то есть про то, есть ли
// интерфейс, а не про то, идёт ли трафик через узел. Без этого живой прогон
// неотличим от чёрной дыры на глаз — ровно тем и был вызван этот этап.
//
// Поэтому здесь не «логирование для красоты», а наблюдаемость: переключения на
// INFO, полный срез живости на DEBUG.
func watch(ctx context.Context, a *agent.Agent, log *slog.Logger, every time.Duration) {
	history, events := a.Events(16)
	defer a.Unsubscribe(events)

	for _, ev := range history {
		logSwitch(log, ev)
	}

	t := time.NewTicker(every) //hop:realtime
	defer t.Stop()

	var last, lastDNS string
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			logSwitch(log, ev)
		case <-t.C:
			snap := a.Snapshot()
			// Фаза печатается на INFO только когда сменилась: иначе тикер
			// забил бы лог одной и той же строкой, и настоящая смена в нём
			// потерялась бы.
			if cur := string(snap.Traffic) + "/" + snap.Active; cur != last {
				last = cur
				log.Info("фаза трафика", "фаза", snap.Traffic, "узел", orNone(snap.Active))
			}
			log.Debug("живость", "фаза", snap.Traffic, "узел", orNone(snap.Active),
				"узлы", nodesLine(snap.Nodes))

			// DNS печатается отдельно от фазы трафика, потому что отвечает на
			// другой вопрос. Приложение, получившее SERVFAIL, видит «сайт не
			// найден» — неотличимо от сломавшегося интернета, и цена этой
			// неразличимости названа прямо в Р15 регистра. Здесь она и
			// платится: пока `hop` работает на переднем плане, это
			// единственное окно наружу (`hop status` спрашивает сервис, а
			// резолвер живёт в агенте).
			if ds, ok := a.DNSStats(); ok {
				// На INFO — только край: начали или перестали отказывать.
				// Тикер иначе забил бы лог одной строкой, и настоящая смена в
				// нём потерялась бы, ровно как у фазы выше.
				if cur := dnsEdge(snap.Traffic); cur != lastDNS {
					lastDNS = cur
					log.Info("DNS", "состояние", cur, "отказов", ds.ServFail)
				}
				log.Debug("DNS", "записей", ds.Entries, "из них отрицательных", ds.Negative,
					"попаданий", ds.Hits, "промахов", ds.Misses,
					"наверх", ds.Upstream, "мимо туннеля", ds.UpstreamDirect,
					"в полёте", ds.InFlight, "удержано", ds.Held,
					"склеено", ds.Coalesced, "повторов по TCP", ds.TCPRetry,
					"усечено клиенту", ds.TruncToClient, "отказов", ds.ServFail,
					"поколение кэша", ds.Generation)
			}
		}
	}
}

func logSwitch(log *slog.Logger, ev health.SwitchEvent) {
	log.Info("переключение узла",
		"с", orNone(ev.From), "на", ev.To, "причина", ev.Reason,
		"порвано соединений", ev.Interrupted)
}

// nodesLine — срез живости одной строкой. Ключей и адресов здесь нет (§6.14):
// узел опознаётся по id, а лог уезжает в вывод пользователю.
func nodesLine(ns []health.NodeHealth) string {
	var b strings.Builder
	for i, n := range ns {
		if i > 0 {
			b.WriteString(" | ")
		}
		b.WriteString(n.NodeID[:min(8, len(n.NodeID))])
		b.WriteString("=")
		// State — uint8 со своим String(); string(State) дал бы байт, а не слово.
		b.WriteString(n.State.String())
		if n.RTT > 0 {
			b.WriteString(" ")
			b.WriteString(n.RTT.Round(time.Millisecond).String()) //hop:realtime
		}
		if n.LastError != "" {
			b.WriteString(" (")
			b.WriteString(n.LastError)
			b.WriteString(")")
		}
	}
	if b.Len() == 0 {
		return "нет узлов"
	}
	return b.String()
}

// dnsEdge — то, что резолвер сейчас делает с клиентскими запросами. Это
// функция фазы трафика, а не отдельное состояние: fail-close и удержание
// задаются ею целиком (Р15, Р16, Р25).
func dnsEdge(p agent.TrafficPhase) string {
	switch p {
	case agent.PhaseFailing:
		return "отказывает: живых узлов нет"
	case agent.PhaseWaiting:
		return "придерживает запросы: узлы ещё не проверены"
	case agent.PhaseBypass:
		return "резолвит мимо туннеля"
	default:
		return "резолвит через узел"
	}
}

func orNone(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
