// Package health — живость узлов, выбор активного и переключение (§5.4, §5.5,
// §6.3–§6.7). Регистр проверок — docs/verification-autoswitch.md.
//
// Пакет не знает ни про Xray, ни про подписки (§3.4): наружу он смотрит через
// Prober, Clock и колбэк разрыва соединений. Всё время берётся из часов, вся
// живость — из окна результатов.
package health

import (
	"time" //hop:realtime
)

// State — состояние узла из §2 (NodeHealth.state).
type State uint8

const (
	// Untested — результатов ещё нет либо есть только неудачи, которых не
	// хватило на смерть. Узел не выбирается: успешной пробы не было ни разу.
	Untested State = iota
	// Alive — в окне есть успех и меньше k неудач.
	Alive
	// Dead — в окне не меньше k неудач либо счётчик ошибок трафика дошёл до k.
	Dead
)

func (s State) String() string {
	switch s {
	case Alive:
		return "alive"
	case Dead:
		return "dead"
	default:
		return "untested"
	}
}

// Outcome — исход одной пробы, кольцо которых образует окно §2.
type Outcome uint8

const (
	OK Outcome = iota
	Fail
	Timeout
)

func (o Outcome) bad() bool { return o != OK }

// FailureKind — замкнутое перечисление ошибок трафика, убивающих узел (§6.15).
// Именно перечисление, а не строка: иначе классификация расползётся по коду и
// однажды тихо начнёт считать смертью упавший сайт (A7, A8).
type FailureKind uint8

const (
	// DialTimeout — не установилось соединение с узлом.
	DialTimeout FailureKind = iota + 1
	// HandshakeFailed — разрыв во время рукопожатия с узлом.
	HandshakeFailed
	// TLSError — ошибка TLS или REALITY от узла.
	TLSError
	// ProxyRefused — узел принял соединение, но отказался проксировать.
	ProxyRefused
)

func (k FailureKind) String() string {
	switch k {
	case DialTimeout:
		return "dial-timeout"
	case HandshakeFailed:
		return "handshake-failed"
	case TLSError:
		return "tls-error"
	case ProxyRefused:
		return "proxy-refused"
	default:
		return "unknown"
	}
}

// valid отсекает всё, чего нет в §6.15. Отказ целевого хоста — 502, NXDOMAIN,
// refused от сайта — сюда не попадает и узел не убивает (A7).
func (k FailureKind) valid() bool {
	return k >= DialTimeout && k <= ProxyRefused
}

// Reason — причина переключения (§2, §5.5). От неё зависит, рвать ли активные
// соединения.
type Reason uint8

const (
	// ReasonDead — активный узел умер либо его не было вовсе. Соединения
	// рвутся: они уже мертвы, и разрыв даёт приложению переподключиться за
	// секунды вместо минут TCP-таймаута (§5.5).
	ReasonDead Reason = iota + 1
	// ReasonFaster — нашёлся узел быстрее более чем на tolerance. Рвать
	// нечего и незачем.
	ReasonFaster
	// ReasonManual — hop up --node (§1/С3).
	ReasonManual
)

func (r Reason) String() string {
	switch r {
	case ReasonDead:
		return "dead"
	case ReasonFaster:
		return "faster"
	case ReasonManual:
		return "manual"
	default:
		return "unknown"
	}
}

// SwitchEvent — событие переключения (§2).
type SwitchEvent struct {
	At          time.Time
	From        string // пусто только у самого первого выбора (A20)
	To          string
	Reason      Reason
	Interrupted int
}

// Node — то, что health знает об узле. Всё остальное живёт в store (§3.4).
type Node struct {
	ID string
	// Supported — умеет ли это наша сборка Xray (§6.11). Неподдерживаемый
	// узел не пробуется ни разу и не может быть выбран (A13).
	Supported bool
}

// NodeHealth — снимок живости одного узла (§2).
type NodeHealth struct {
	NodeID          string
	State           State
	RTT             time.Duration
	Window          []Outcome
	TrafficFailures int
	LastProbeAt     time.Time
	LastError       string
}

// Snapshot — весь наблюдаемый снаружи вердикт модуля одним куском
// (docs/verification-autoswitch.md §2).
type Snapshot struct {
	Active string
	Auto   bool
	Round  uint64
	Nodes  []NodeHealth
}

// Node возвращает живость узла по id.
func (s Snapshot) Node(id string) (NodeHealth, bool) {
	for _, n := range s.Nodes {
		if n.NodeID == id {
			return n, true
		}
	}
	return NodeHealth{}, false
}

// nodeState — внутреннее состояние узла.
type nodeState struct {
	node    Node
	order   int
	window  []Outcome // последние n результатов, старые слева
	traffic int
	rtt     time.Duration
	last    time.Time
	lastErr string

	nextProbe time.Time
	inFlight  bool
	probed    bool // была хотя бы одна проба — для стартового бюджета (Р5)
}

// record кладёт исход в окно длины size, вытесняя самый старый.
func (n *nodeState) record(o Outcome, size int) {
	n.window = append(n.window, o)
	if len(n.window) > size {
		n.window = n.window[len(n.window)-size:]
	}
	n.probed = true
}

// fails считает неудачи в окне.
func (n *nodeState) fails() int {
	c := 0
	for _, o := range n.window {
		if o.bad() {
			c++
		}
	}
	return c
}

// state вычисляет состояние по правилу Р1 — единственному и симметричному:
// узел мёртв ровно тогда, когда в окне не меньше k неудач. Отдельного порога
// воскрешения нет, поэтому возврат стоит ровно k успехов подряд.
//
// Узел без единого успеха остаётся Untested, а не Alive: выбирать узел, ни
// разу не ответивший, нельзя (A11, A12).
func (n *nodeState) state(k int) State {
	if n.fails() >= k || n.traffic >= k {
		return Dead
	}
	for _, o := range n.window {
		if o == OK {
			return Alive
		}
	}
	return Untested
}

func (n *nodeState) health(k int) NodeHealth {
	w := make([]Outcome, len(n.window))
	copy(w, n.window)
	return NodeHealth{
		NodeID:          n.node.ID,
		State:           n.state(k),
		RTT:             n.rtt,
		Window:          w,
		TrafficFailures: n.traffic,
		LastProbeAt:     n.last,
		LastError:       n.lastErr,
	}
}
