package store

// Формирование вывода `hop nodes --json` и `hop status --json` (§1/С2, §1/С4).
//
// Команд ещё нет — они этап 9. Здесь лежит то, из чего они будут собраны, и это
// не забегание вперёд: S33 требует проверить, что ключей нет в выводе, а
// проверять это на несуществующей команде негде (шаг 7 регистра,
// docs/verification-store.md §8). Разбор флагов и печать остаются этапу 9.

import "github.com/shafed/hop/internal/health"

// NodeView — узел, каким его видит вывод команд.
//
// Отдельный тип с тегами, а не Node: список полей вывода обязан быть явным
// перечислением того, что показывать **можно**. Отрицание («Node, только без
// params») продержалось бы до первого протокола, у которого секрет лежит в
// новом поле, — и выдало бы его само собой (Р12, §6.14).
type NodeView struct {
	ID      string `json:"id"`
	GroupID string `json:"group_id"`
	Name    string `json:"name,omitempty"`
	// Server и Port показывать надо: без адреса пользователь не отличит свои
	// узлы друг от друга, а §6.14 запрещает ключи, а не узнаваемость.
	Server    string `json:"server"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Transport string `json:"transport,omitempty"`
	Security  string `json:"security,omitempty"`
	Supported bool   `json:"supported"`
	// UnsupReason — по нему группируется сводка импорта (§6.11, §1/С2).
	UnsupReason string `json:"unsup_reason,omitempty"`

	// Живость: то, что стор про узел знает после рестарта, — срез, а не окно
	// (§2). Окна в выводе нет и быть не может: стор его не хранит.
	State       string `json:"state"`
	RTTMs       int64  `json:"rtt_ms,omitempty"`
	LastProbeAt string `json:"last_probe_at,omitempty"`
}

// GroupView — группа для вывода. Ключей у группы нет, но source_url подписки —
// это URL, по которому её тело отдаётся любому, кто его знает, то есть ровно
// такой же секрет, как ключ узла. В выводе остаётся только имя.
type GroupView struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	Nodes         int    `json:"nodes"`
	LastUpdatedAt string `json:"last_updated_at,omitempty"`
	AutoUpdate    bool   `json:"auto_update"`
}

// StatusView — часть вывода `hop status --json`, за которую отвечает стор:
// какой узел активен и что про него известно. Фазы туннеля и трафика (§5.2)
// живут в tunnel и health, и приклеит их этап 9 — стор про них не знает (§3.4).
type StatusView struct {
	Active *NodeView   `json:"active,omitempty"`
	Groups []GroupView `json:"groups"`
	Nodes  int         `json:"nodes"`
}

// GroupNodesView — группа вместе со своим составом: ровно то, что показывает
// `hop nodes` (§1/С2).
//
// Тип живёт здесь, а не в том, кто печатает, потому что печатающих стало двое:
// `cmd/hop` читает стор напрямую, пока связки нет, а связка отдаёт то же самое
// через сокет §3.3 при живом агенте. Два экземпляра этой структуры разошлись
// бы молча — тот же довод, по которому перечень полей узла живёт в NodeView, а
// не в команде.
type GroupNodesView struct {
	// Group и Nodes рядом, а не встраиванием: у GroupView есть своё поле
	// nodes — счётчик, — и встраивание молча заслонило бы его списком.
	Group GroupView  `json:"group"`
	Nodes []NodeView `json:"nodes"`
}

// LiveHealth — источник живости свежее диска.
//
// Стор хранит СРЕЗ живости (§2): на диск он попадает не чаще раза в
// healthDebounce, и §2 называет его «тем, чему можно верить после паузы», а не
// «прямо сейчас». Пока агент жив, «прямо сейчас» знает health.Manager, и
// показывать вместо него срез получасовой свежести значит показывать
// устаревшее там, где актуальное есть.
//
// nil означает «свежее нечему быть»: стор отвечает сам, как и до сокета §3.3.
type LiveHealth func(nodeID string) (health.NodeHealth, bool)

// FullView — все группы со своим составом (§1/С2), с живостью из live, если
// она есть.
//
// Одна функция на обоих вызывающих. Второй экземпляр сборки — в `cmd/hop`
// рядом с печатью — разъехался бы с этим по одному полю за раз, и заметить
// это можно было бы только сравнив два куска кода глазами.
func (s *Store) FullView(live LiveHealth) []GroupNodesView {
	groups := s.Groups()
	out := make([]GroupNodesView, 0, len(groups))
	for _, g := range groups {
		nodes := s.Nodes(g.ID)
		out = append(out, GroupNodesView{
			Group: groupView(g, len(nodes)),
			Nodes: s.nodeViews(nodes, live),
		})
	}
	return out
}

// NodesView — вывод `hop nodes --json` для группы. Порядок — node_order (Р8).
func (s *Store) NodesView(groupID string) []NodeView {
	return s.nodeViews(s.Nodes(groupID), nil)
}

func (s *Store) nodeViews(nodes []Node, live LiveHealth) []NodeView {
	out := make([]NodeView, 0, len(nodes))
	for _, n := range nodes {
		h, ok := health.NodeHealth{}, false
		if live != nil {
			h, ok = live(n.ID)
		}
		if !ok {
			h, _ = s.Health(n.ID)
		}
		out = append(out, nodeView(n, h))
	}
	return out
}

// StatusView собирает вывод `hop status --json`. Пустой activeID означает «узел
// не выбран» — законное состояние до первого выбора (§5.5).
func (s *Store) StatusView(activeID string) StatusView {
	groups := s.Groups()
	v := StatusView{Groups: make([]GroupView, 0, len(groups))}
	for _, g := range groups {
		nodes := s.Nodes(g.ID)
		v.Nodes += len(nodes)
		v.Groups = append(v.Groups, groupView(g, len(nodes)))
	}
	if n, ok := s.Node(activeID); ok {
		h, _ := s.Health(activeID)
		active := nodeView(n, h)
		v.Active = &active
	}
	return v
}

// groupView и nodeView — единственные места, где решается, какие поля узла и
// группы показывать МОЖНО (Р12, §6.14). Их сторожит S33, и обходить их сборкой
// GroupView руками нельзя ни одному вызывающему.
func groupView(g Group, nodes int) GroupView {
	return GroupView{
		ID:            g.ID,
		Name:          g.Name,
		Nodes:         nodes,
		LastUpdatedAt: formatTime(g.LastUpdatedAt),
		AutoUpdate:    g.AutoUpdate,
	}
}

func nodeView(n Node, h health.NodeHealth) NodeView {
	return NodeView{
		ID:          n.ID,
		GroupID:     n.GroupID,
		Name:        n.Name,
		Server:      n.Server,
		Port:        n.Port,
		Protocol:    n.Protocol,
		Transport:   n.Transport,
		Security:    n.Security,
		Supported:   n.Supported,
		UnsupReason: n.UnsupReason.String(),
		State:       h.State.String(),
		RTTMs:       h.RTT.Milliseconds(),
		LastProbeAt: formatTime(h.LastProbeAt),
	}
}
