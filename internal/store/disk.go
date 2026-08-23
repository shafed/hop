package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"time" //hop:realtime — только форматирование и разбор меток, часов здесь нет

	"github.com/shafed/hop/internal/health"
)

// diskVersion — версия раскладки файлов. Пишется, чтобы будущая миграция
// (например, смена правила §6.16, требующая явной миграции стора) могла
// отличить старый файл от нового, а не угадывать по составу полей.
const diskVersion = 1

// Три файла, а не один (§2): живость обновляется каждые секунды, и общий файл
// переписывал бы вместе с ней секреты — лишний износ и лишнее окно, в котором
// обрыв уносит всё сразу.
const (
	groupsFile = "groups.json"
	nodesFile  = "nodes.json"
	healthFile = "health.json"
	lockFile   = ".lock"
)

type diskGroups struct {
	Version int         `json:"version"`
	Groups  []diskGroup `json:"groups"`
}

type diskGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// SourceURL пуст у manual (§2).
	SourceURL string `json:"source_url,omitempty"`
	// LastUpdatedAt — RFC3339 либо пусто. Строкой, а не time.Time: нулевое
	// время в JSON выглядит как «0001-01-01» и читается как настоящая дата.
	LastUpdatedAt string   `json:"last_updated_at,omitempty"`
	QuotaInfo     string   `json:"quota_info,omitempty"`
	NodeOrder     []string `json:"node_order"`
	AutoUpdate    bool     `json:"auto_update"`
	// AutoUpdateInterval — строка time.Duration: «6h0m0s» в файле, который
	// человек будет читать глазами, полезнее, чем 21600.
	AutoUpdateInterval string `json:"auto_update_interval,omitempty"`
}

type diskNodes struct {
	Version int        `json:"version"`
	Nodes   []diskNode `json:"nodes"`
}

type diskNode struct {
	ID        string `json:"id"`
	GroupID   string `json:"group_id"`
	MergeKey  string `json:"merge_key"`
	Name      string `json:"name,omitempty"`
	Protocol  string `json:"protocol"`
	Server    string `json:"server"`
	Port      int    `json:"port"`
	Transport string `json:"transport,omitempty"`
	Security  string `json:"security,omitempty"`
	// Params — здесь лежат ключи доступа, из-за них весь файл 0600 (Р12).
	Params    map[string]string `json:"params,omitempty"`
	Supported bool              `json:"supported"`
	// UnsupReason — строкой из §6.11, а не числом: файл читают глазами, а
	// перенумерование причин не должно молча переназначать их смысл.
	UnsupReason string `json:"unsup_reason,omitempty"`
	RawLink     string `json:"raw_link,omitempty"`
}

type diskHealth struct {
	Version int              `json:"version"`
	Nodes   []diskNodeHealth `json:"nodes"`
}

// diskNodeHealth — срез живости, а не вся NodeHealth (§2): окно,
// traffic_failures и last_error описывают «прямо сейчас» и после паузы врут.
//
// Три последних поля в продукте не появляются никогда: обрезает живость
// healthSlice (health.go), и с включённой политикой health_slice они приходят
// сюда пустыми. Место для них есть ровно затем, чтобы выключенная политика
// действительно писала на диск всю NodeHealth, а не делала вид (S36, S37).
type diskNodeHealth struct {
	NodeID      string `json:"node_id"`
	State       string `json:"state"`
	RTTMs       int64  `json:"rtt_ms,omitempty"`
	LastProbeAt string `json:"last_probe_at,omitempty"`

	Window          []string `json:"window,omitempty"`
	TrafficFailures int      `json:"traffic_failures,omitempty"`
	LastError       string   `json:"last_error,omitempty"`
}

// encodeGroups сериализует группы в порядке, в котором они лежат в сторе.
func encodeGroups(order []string, groups map[string]Group) ([]byte, error) {
	d := diskGroups{Version: diskVersion, Groups: make([]diskGroup, 0, len(order))}
	for _, id := range order {
		g, ok := groups[id]
		if !ok {
			continue
		}
		d.Groups = append(d.Groups, diskGroup{
			ID:                 g.ID,
			Name:               g.Name,
			SourceURL:          g.SourceURL,
			LastUpdatedAt:      formatTime(g.LastUpdatedAt),
			QuotaInfo:          g.QuotaInfo,
			NodeOrder:          g.NodeOrder,
			AutoUpdate:         g.AutoUpdate,
			AutoUpdateInterval: formatDuration(g.AutoUpdateInterval),
		})
	}
	return marshal(d)
}

func decodeGroups(raw []byte) ([]string, map[string]Group, error) {
	var d diskGroups
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, nil, err
	}
	order := make([]string, 0, len(d.Groups))
	groups := make(map[string]Group, len(d.Groups))
	for _, g := range d.Groups {
		if g.ID == "" {
			return nil, nil, fmt.Errorf("группа без id")
		}
		if _, dup := groups[g.ID]; dup {
			return nil, nil, fmt.Errorf("две группы с id %q", g.ID)
		}
		updated, err := parseTime(g.LastUpdatedAt)
		if err != nil {
			return nil, nil, fmt.Errorf("группа %q: last_updated_at: %w", g.ID, err)
		}
		interval, err := parseDuration(g.AutoUpdateInterval)
		if err != nil {
			return nil, nil, fmt.Errorf("группа %q: auto_update_interval: %w", g.ID, err)
		}
		order = append(order, g.ID)
		groups[g.ID] = Group{
			ID:                 g.ID,
			Name:               g.Name,
			SourceURL:          g.SourceURL,
			LastUpdatedAt:      updated,
			QuotaInfo:          g.QuotaInfo,
			NodeOrder:          g.NodeOrder,
			AutoUpdate:         g.AutoUpdate,
			AutoUpdateInterval: interval,
		}
	}
	return order, groups, nil
}

// encodeNodes пишет узлы в порядке групп и node_order, а хвостом — те, кого в
// порядке нет. Порядок в файле не значим для чтения, но постоянный вывод
// делает наблюдаемым, что запись изменила состав, а не только форматирование.
func encodeNodes(order []string, groups map[string]Group, nodes map[string]Node) ([]byte, error) {
	d := diskNodes{Version: diskVersion, Nodes: make([]diskNode, 0, len(nodes))}
	written := make(map[string]bool, len(nodes))
	appendNode := func(id string) {
		n, ok := nodes[id]
		if !ok || written[id] {
			return
		}
		written[id] = true
		d.Nodes = append(d.Nodes, diskNode{
			ID:          n.ID,
			GroupID:     n.GroupID,
			MergeKey:    n.MergeKey,
			Name:        n.Name,
			Protocol:    n.Protocol,
			Server:      n.Server,
			Port:        n.Port,
			Transport:   n.Transport,
			Security:    n.Security,
			Params:      n.Params,
			Supported:   n.Supported,
			UnsupReason: n.UnsupReason.String(),
			RawLink:     n.RawLink,
		})
	}
	for _, gid := range order {
		for _, id := range groups[gid].NodeOrder {
			appendNode(id)
		}
	}
	rest := make([]string, 0, len(nodes)-len(written))
	for id := range nodes {
		if !written[id] {
			rest = append(rest, id)
		}
	}
	sort.Strings(rest)
	for _, id := range rest {
		appendNode(id)
	}
	return marshal(d)
}

func decodeNodes(raw []byte) (map[string]Node, error) {
	var d diskNodes
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	nodes := make(map[string]Node, len(d.Nodes))
	for _, n := range d.Nodes {
		if n.ID == "" {
			return nil, fmt.Errorf("узел без id")
		}
		if _, dup := nodes[n.ID]; dup {
			return nil, fmt.Errorf("два узла с id %q", n.ID)
		}
		reason, err := unsupReasonFromString(n.UnsupReason)
		if err != nil {
			return nil, fmt.Errorf("узел %q: %w", n.ID, err)
		}
		nodes[n.ID] = Node{
			ID:          n.ID,
			GroupID:     n.GroupID,
			MergeKey:    n.MergeKey,
			Name:        n.Name,
			Protocol:    n.Protocol,
			Server:      n.Server,
			Port:        n.Port,
			Transport:   n.Transport,
			Security:    n.Security,
			Params:      n.Params,
			Supported:   n.Supported,
			UnsupReason: reason,
			RawLink:     n.RawLink,
		}
	}
	return nodes, nil
}

func encodeHealth(hs map[string]health.NodeHealth) ([]byte, error) {
	ids := make([]string, 0, len(hs))
	for id := range hs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	d := diskHealth{Version: diskVersion, Nodes: make([]diskNodeHealth, 0, len(ids))}
	for _, id := range ids {
		h := hs[id]
		d.Nodes = append(d.Nodes, diskNodeHealth{
			NodeID:      h.NodeID,
			State:       h.State.String(),
			RTTMs:       h.RTT.Milliseconds(),
			LastProbeAt: formatTime(h.LastProbeAt),
			// Не «если политика включена», а «что принесли»: обрезает один
			// healthSlice, и второе место, где спрашивают тот же флаг, однажды
			// разошлось бы с первым.
			Window:          encodeWindow(h.Window),
			TrafficFailures: h.TrafficFailures,
			LastError:       h.LastError,
		})
	}
	return marshal(d)
}

func decodeHealth(raw []byte) (map[string]health.NodeHealth, error) {
	var d diskHealth
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	hs := make(map[string]health.NodeHealth, len(d.Nodes))
	for _, n := range d.Nodes {
		if n.NodeID == "" {
			return nil, fmt.Errorf("живость без node_id")
		}
		state, err := healthStateFromString(n.State)
		if err != nil {
			return nil, fmt.Errorf("живость узла %q: %w", n.NodeID, err)
		}
		probed, err := parseTime(n.LastProbeAt)
		if err != nil {
			return nil, fmt.Errorf("живость узла %q: last_probe_at: %w", n.NodeID, err)
		}
		// Окна в файле нет: его не пишет healthSlice (§2) — пустое окно
		// означает «не проверен», и стартовый бюджет §5.6 отсчитывается заново.
		// Разбор всё же есть: файл, написанный сборкой с выключенной политикой
		// health_slice, обязан читаться ею же целиком, иначе выключение
		// политики ломало бы запись и чтение по-разному и S36 краснела бы не по
		// той причине.
		window, err := decodeWindow(n.Window)
		if err != nil {
			return nil, fmt.Errorf("живость узла %q: %w", n.NodeID, err)
		}
		hs[n.NodeID] = health.NodeHealth{
			NodeID:          n.NodeID,
			State:           state,
			RTT:             time.Duration(n.RTTMs) * time.Millisecond,
			LastProbeAt:     probed,
			Window:          window,
			TrafficFailures: n.TrafficFailures,
			LastError:       n.LastError,
		}
	}
	return hs, nil
}

// marshal — единая форма файлов стора: с отступами и с переводом строки в
// конце, чтобы их можно было читать и сравнивать обычными средствами.
func marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}

func formatDuration(d time.Duration) string {
	if d == 0 {
		return ""
	}
	return d.String()
}

func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}

// unsupReasonFromString — обратная сторона UnsupReason.String(). Живёт здесь,
// а не в types.go, потому что нужна только чтению с диска.
func unsupReasonFromString(s string) (UnsupReason, error) {
	switch s {
	case "":
		return UnsupNone, nil
	case "protocol":
		return UnsupProtocol, nil
	case "transport":
		return UnsupTransport, nil
	case "security":
		return UnsupSecurity, nil
	case "parse":
		return UnsupParse, nil
	}
	return UnsupNone, fmt.Errorf("неизвестная причина unsup_reason %q", s)
}

// encodeWindow и decodeWindow — окно исходов словами, а не числами: файл читают
// глазами, и перенумерование Outcome не должно молча переназначать смысл
// записанного. В продукте окно на диск не идёт вовсе (§2); эти две функции
// существуют ради выключенной политики health_slice.
func encodeWindow(w []health.Outcome) []string {
	if len(w) == 0 {
		return nil
	}
	out := make([]string, 0, len(w))
	for _, o := range w {
		out = append(out, outcomeString(o))
	}
	return out
}

func decodeWindow(w []string) ([]health.Outcome, error) {
	if len(w) == 0 {
		return nil, nil
	}
	out := make([]health.Outcome, 0, len(w))
	for _, s := range w {
		o, err := outcomeFromString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

func outcomeString(o health.Outcome) string {
	switch o {
	case health.Fail:
		return "fail"
	case health.Timeout:
		return "timeout"
	default:
		return "ok"
	}
}

func outcomeFromString(s string) (health.Outcome, error) {
	switch s {
	case "ok":
		return health.OK, nil
	case "fail":
		return health.Fail, nil
	case "timeout":
		return health.Timeout, nil
	}
	return health.OK, fmt.Errorf("неизвестный исход пробы %q", s)
}

// healthStateFromString — разбор состояния живости. Своя функция, а не метод в
// health: обратный разбор нужен только тому, кто читает файл.
func healthStateFromString(s string) (health.State, error) {
	switch s {
	case "", "untested":
		return health.Untested, nil
	case "alive":
		return health.Alive, nil
	case "dead":
		return health.Dead, nil
	}
	return health.Untested, fmt.Errorf("неизвестное состояние %q", s)
}
