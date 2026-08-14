// Package events — граница «клиенты ↔ агент» (§3.3).
//
// Отдельный сокет в каталоге пользователя, на котором агент отвечает CLI и
// рассылает события. С первого дня он рассчитан на **несколько одновременных
// клиентов**: в v1 это один CLI, но рядом с ним встанут GUI и трей, и событие
// обязано дойти до каждого, а не до того, кто успел первым.
//
// Клиенты никогда не говорят с привилегированным сервисом: всё, что они видят,
// собрал агент (§3.3). Поэтому Status здесь один и склеен из двух источников —
// сервис знает `orphaned` и устройство, агент знает узел и переключение (C9).
//
// Транспорт — построчный JSON поверх stream-сокета: запрос, потом один ответ,
// а для подписки — поток ответов до закрытия соединения. Никакого
// мультиплексирования нет намеренно: одно соединение — одна команда, и клиенту
// не нужно сопоставлять ответы с запросами.
package events

import (
	"os"
	"path/filepath"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/tunnel"
)

// DefaultPath — сокет агента по умолчанию: каталог пользователя, а не /run
// (§3.3). Рядом с ним лежит attach-token, и каталог создаётся с правами 0700.
var DefaultPath = defaultPath()

func defaultPath() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "hop", "agent.sock")
}

// Status — TunnelState §2 целиком, каким его видит пользователь: часть полей
// пришла от сервиса (§3.1), часть от супервизора (§3.4).
type Status struct {
	Phase tunnel.Phase `json:"phase"`
	// Device — как агент получает пакеты (§2). Пусто, если сервис недоступен.
	Device string `json:"device,omitempty"`
	// OrphanLeftMS и DetachReason заполнены только в orphaned: §2 требует, чтобы
	// status показывал это состояние с причиной — снаружи оно выглядит как
	// «интернета нет».
	OrphanLeftMS int64         `json:"orphan_left_ms,omitempty"`
	DetachReason tunnel.Reason `json:"detach_reason,omitempty"`

	ActiveNode string `json:"active_node,omitempty"`
	ActiveName string `json:"active_name,omitempty"`
	RTTms      int64  `json:"rtt_ms,omitempty"`
	// Auto — включено ли автопереключение (§С3).
	Auto bool `json:"auto"`
	// LastSwitch — причина последнего переключения (§С5). nil, пока их не было.
	LastSwitch *Switch `json:"last_switch,omitempty"`
}

// Switch — «Событие переключения» §2 в машинном виде. Имена полей взяты из
// спеки: они и есть контракт для тех, кто читает --json.
type Switch struct {
	At                     time.Time     `json:"at"`
	FromNode               string        `json:"from_node,omitempty"`
	ToNode                 string        `json:"to_node,omitempty"`
	Reason                 health.Reason `json:"reason"`
	InterruptedConnections int           `json:"interrupted_connections"`
}

// NodeInfo — строка `hop nodes`: узел (§2) вместе с его живостью (NodeHealth).
type NodeInfo struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Group string `json:"group,omitempty"`
	// State — untested тоже состояние: отсутствие истории надо показывать, а не
	// прятать (§2).
	State health.State `json:"state"`
	RTTms int64        `json:"rtt_ms,omitempty"`
	// Supported — умеет ли наша сборка Xray этот узел (§6.11). Неподдержанный
	// узел виден в списке, но в выборе не участвует.
	Supported bool   `json:"supported"`
	Active    bool   `json:"active,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

// Event — то, что уезжает подписчикам (§3.3): смена узла и/или фазы туннеля.
type Event struct {
	At    time.Time    `json:"at"`
	Phase tunnel.Phase `json:"phase"`
	// Switch заполнен, когда сменился активный узел; nil — сменилась только
	// фаза (например, включён обход §5.6).
	Switch *Switch `json:"switch,omitempty"`
}

// Cmd — команда клиента. Соответствие командам CLI прямое (§5.9).
type Cmd string

const (
	CmdStatus Cmd = "status"
	CmdNodes  Cmd = "nodes"
	CmdPin    Cmd = "pin"
	CmdAuto   Cmd = "auto"
	CmdBypass Cmd = "bypass"
	CmdPing   Cmd = "ping"
	CmdEvents Cmd = "events"
)

// Request — запрос клиента. Узлов и ключей в нём нет: клиент называет id, а
// всё остальное про узел агент знает сам (§6.14).
type Request struct {
	Cmd  Cmd    `json:"cmd"`
	Node string `json:"node,omitempty"`
	On   bool   `json:"on,omitempty"`
}

// Response — ответ агента. Для подписки таких ответов приходит много, по
// одному на событие.
type Response struct {
	Error  string     `json:"error,omitempty"`
	Status *Status    `json:"status,omitempty"`
	Nodes  []NodeInfo `json:"nodes,omitempty"`
	Node   *NodeInfo  `json:"node,omitempty"`
	Event  *Event     `json:"event,omitempty"`
}

// FromSwitch переводит событие переключения из health в машинный вид.
func FromSwitch(sw health.Switch) Switch {
	return Switch{
		At:                     sw.At,
		FromNode:               sw.From,
		ToNode:                 sw.To,
		Reason:                 sw.Reason,
		InterruptedConnections: sw.InterruptedConnections,
	}
}
