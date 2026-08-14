package cli

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/shafed/hop/internal/events"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/tunnel"
)

// table — колонки выравниваются по числу рун, а не байт: имена узлов приходят
// из подписки и почти всегда не латиница.
func table(w io.Writer) *tabwriter.Writer { return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0) }

// renderStatus — §С5 плюс требование §2 показывать orphaned с причиной.
func renderStatus(w io.Writer, st events.Status) {
	fmt.Fprintf(w, "фаза: %s\n", st.Phase)
	if st.Device != "" {
		fmt.Fprintf(w, "устройство: %s\n", st.Device)
	}
	if st.ActiveNode != "" {
		name := st.ActiveNode
		if st.ActiveName != "" {
			name += " (" + st.ActiveName + ")"
		}
		fmt.Fprintf(w, "активный узел: %s\n", name)
		fmt.Fprintf(w, "латентность: %s\n", rtt(st.RTTms))
	}
	// Фазы down и orphaned означают, что агента нет: про автопереключение в них
	// сказать нечего, и «выключено» было бы неправдой.
	if st.Phase != tunnel.Down && st.Phase != tunnel.Orphaned {
		fmt.Fprintf(w, "автопереключение: %s\n", onOff(st.Auto))
	}
	if st.LastSwitch != nil {
		fmt.Fprintf(w, "последнее переключение: %s\n", switchLine(*st.LastSwitch))
	}

	switch st.Phase {
	case tunnel.Orphaned:
		fmt.Fprintf(w, "предупреждение: агента нет, туннель отвечает отказом; осталось %d с, причина: %s\n",
			st.OrphanLeftMS/1000, st.DetachReason)
	case tunnel.Failing:
		fmt.Fprintln(w, "предупреждение: живых узлов нет, трафик заблокирован; hop bypass --on выпустит его напрямую")
	case tunnel.Bypass:
		fmt.Fprintln(w, "предупреждение: обход включён, трафик идёт мимо узлов и не защищён")
	}
}

// renderNodes — §С5: список с состоянием и латентностью. live=false означает
// «данные из стора, агент не запущен»: путать неизвестность с untested нельзя.
func renderNodes(w io.Writer, list []events.NodeInfo, live bool) {
	if len(list) == 0 {
		fmt.Fprintln(w, "узлов нет: hop sub add <url> либо hop node add <ссылка>")
		return
	}
	if !live {
		fmt.Fprintln(w, "агент не запущен: показан состав из стора, живость неизвестна")
	}

	t := table(w)
	fmt.Fprintln(t, "\tID\tУЗЕЛ\tСОСТОЯНИЕ\tRTT\tГРУППА")
	for _, n := range list {
		mark := " "
		if n.Active {
			mark = "*"
		}
		name := n.Name
		if !n.Supported {
			name += " (не поддержан)"
		}
		fmt.Fprintf(t, "%s\t%s\t%s\t%s\t%s\t%s\n", mark, n.ID, name, n.State, rtt(n.RTTms), n.Group)
	}
	t.Flush()
}

// renderGroups — `hop sub list`. Группа manual тоже здесь: пользователь видит
// один список источников, а не два (§5.8).
func renderGroups(w io.Writer, st *store.Store) {
	groups := st.Groups()
	if len(groups) == 0 {
		fmt.Fprintln(w, "подписок нет: hop sub add <url>")
		return
	}

	t := table(w)
	fmt.Fprintln(t, "ID\tИМЯ\tУЗЛОВ\tОБНОВЛЕНА\tИСТОЧНИК")
	for _, g := range groups {
		updated := "—"
		if !g.LastUpdatedAt.IsZero() {
			updated = g.LastUpdatedAt.Format("2006-01-02 15:04")
		}
		src := g.SourceURL
		if src == "" {
			src = "—"
		}
		fmt.Fprintf(t, "%s\t%s\t%d\t%s\t%s\n", g.ID, g.Name, len(st.Nodes(g.ID)), updated, src)
	}
	t.Flush()
}

// switchLine — «Событие переключения» §2 одной строкой. Причина здесь не
// украшение: от неё зависит, рвались ли соединения (§5.5).
func switchLine(sw events.Switch) string {
	from := sw.FromNode
	if from == "" {
		from = "—"
	}
	s := fmt.Sprintf("%s → %s, причина %s", from, sw.ToNode, sw.Reason)
	if sw.InterruptedConnections > 0 {
		s += fmt.Sprintf(", порвано соединений: %d", sw.InterruptedConnections)
	}
	return s
}

func eventLine(ev events.Event) string {
	ts := ev.At.Format("15:04:05")
	if ev.Switch != nil {
		return fmt.Sprintf("%s %s: %s", ts, ev.Phase, switchLine(*ev.Switch))
	}
	return fmt.Sprintf("%s фаза: %s", ts, ev.Phase)
}

func nodeLine(n events.NodeInfo) string {
	s := fmt.Sprintf("узел %s (%s): %s, %s", n.ID, n.Name, n.State, rtt(n.RTTms))
	if n.LastError != "" {
		s += ", " + n.LastError
	}
	return s
}

func rtt(ms int64) string {
	if ms <= 0 {
		return "—"
	}
	return fmt.Sprintf("%d мс", ms)
}

func onOff(v bool) string {
	if v {
		return "включено"
	}
	return "выключено"
}
