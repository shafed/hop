package health

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/policy"
)

// State — §2, NodeHealth.state.
type State string

const (
	// Untested — узел ещё ни разу не проверялся. Не то же самое, что alive:
	// непроверенный узел не должен выигрывать выбор у проверенного.
	Untested State = "untested"
	Alive    State = "alive"
	Dead     State = "dead"
)

// Outcome — исход одной пробы в окне §6.3. Timeout отделён от Fail, потому что
// это разные наблюдаемые: blackhole даёт таймаут там, где rst даёт отказ, и
// §8.1 требует различать их.
type Outcome uint8

const (
	OK Outcome = iota + 1
	Fail
	Timeout
)

// NodeHealth — §2. Живёт отдельно от node.Node, потому что обновляется на
// порядки чаще.
type NodeHealth struct {
	NodeID string
	State  State
	// RTT — последняя успешная латентность. По ней работает гистерезис §6.4.
	RTT time.Duration
	// Window — кольцо последних N исходов проб (§6.3).
	Window []Outcome
	// TrafficFailures — ошибки реального трафика в текущем окне (§5.4). Только
	// те, что §6.15 признал смертью: отказ сайта сюда не попадает.
	TrafficFailures int
	LastProbeAt     time.Time
	LastError       string
}

func (h NodeHealth) clone() NodeHealth {
	c := h
	c.Window = append([]Outcome(nil), h.Window...)
	return c
}

// MonitorConfig — политика смерти §6.3.
type MonitorConfig struct {
	// K, N — мёртв при K неудачах из N последних проб.
	K, N int
}

// DefaultMonitorConfig — стартовые значения §6.3: 2 из 3. Одна ошибка не
// убивает: в sing-box одна неудачная проба стирает историю узла, и на
// нестабильной сети выбор начинает метаться.
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{K: 2, N: 3}
}

// Monitor — окно проб и вывод состояния из него (§6.3).
//
// Он же приёмник исходов реального трафика: Reporter реализован здесь, а зовёт
// его ровно одна функция классификации в internal/engine (§6.15, D10).
type Monitor struct {
	cfg MonitorConfig
	clk clock.Clock

	mu    sync.RWMutex
	nodes map[string]*NodeHealth

	// onDeath — кого разбудить, когда узел признан мёртвым. Без этого смерть,
	// увиденную трафиком (§6.15), заметил бы только следующий тик расписания:
	// до 30 секунд на активном ярусе, при бюджете T9/T11 в 5 секунд.
	onDeath func(nodeID string)
}

var _ Reporter = (*Monitor)(nil)

// NewMonitor создаёт монитор с пустой историей: все узлы untested.
func NewMonitor(cfg MonitorConfig, clk clock.Clock) *Monitor {
	// Бессмысленное окно (нулевое или порог больше окна) сделало бы узел
	// бессмертным, а это молчаливый отказ от §6.3 — лучше стартовые значения.
	if cfg.N <= 0 || cfg.K <= 0 || cfg.K > cfg.N {
		cfg = DefaultMonitorConfig()
	}
	return &Monitor{cfg: cfg, clk: clk, nodes: make(map[string]*NodeHealth)}
}

// SetOnDeath ставит обработчик смерти узла. Зовётся один раз при сборке, до
// того как монитору начнут поступать исходы: гонку с живыми пробами этот
// сеттер не переживёт и переживать не должен.
func (m *Monitor) SetOnDeath(f func(nodeID string)) { m.onDeath = f }

// Observe кладёт исход пробы в окно и пересчитывает состояние узла.
//
// Политика k_of_n: при выключении окно схлопывается в одну последнюю пробу
// (K=1), и первая же неудача убивает узел — это краснит T2.
func (m *Monitor) Observe(nodeID string, r Result) {
	m.mu.Lock()
	h := m.entryLocked(nodeID)
	h.LastProbeAt = m.clk.Now()
	var died bool
	if r.Err != nil {
		h.LastError = r.Err.Error()
		died = m.pushLocked(h, outcomeOf(r.Err))
	} else {
		h.RTT = r.RTT
		h.LastError = ""
		died = m.pushLocked(h, OK)
	}
	m.mu.Unlock()

	m.notify(nodeID, died)
}

// notify зовёт обработчик вне замка: он ведёт в выбор и расписание, а те
// спрашивают монитор о здоровье — под замком это заклинило бы агента.
func (m *Monitor) notify(nodeID string, died bool) {
	if died && m.onDeath != nil {
		m.onDeath(nodeID)
	}
}

// ReportFailure — исход реального трафика (§6.15). Приходит только то, что
// признано смертью узла; отказы целевого хоста сюда не доходят вовсе.
func (m *Monitor) ReportFailure(nodeID string, kind FailureKind) {
	m.mu.Lock()
	h := m.entryLocked(nodeID)
	h.TrafficFailures++
	h.LastError = kind.String()
	// Ошибка трафика идёт в то же окно, что и проба: §5.4 считает оба
	// источника одним свидетельством о живости. Второе окно означало бы два
	// разных ответа на вопрос «жив ли узел» и спор между ними.
	o := Fail
	if kind == DialTimeout {
		o = Timeout
	}
	died := m.pushLocked(h, o)
	m.mu.Unlock()

	m.notify(nodeID, died)
}

// ReportSuccess — успешное соединение через узел. Обнуляет счётчик ошибок
// трафика и обновляет rtt.
func (m *Monitor) ReportSuccess(nodeID string, rtt time.Duration) {
	m.mu.Lock()
	h := m.entryLocked(nodeID)
	h.TrafficFailures = 0
	h.RTT = rtt
	h.LastError = ""
	m.pushLocked(h, OK)
	m.mu.Unlock()
}

// Get — снимок здоровья узла. Для незнакомого узла возвращает untested, а не
// «нет данных»: отсутствие истории — это тоже состояние (§2).
func (m *Monitor) Get(nodeID string) NodeHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()

	h, ok := m.nodes[nodeID]
	if !ok {
		return NodeHealth{NodeID: nodeID, State: Untested}
	}
	return h.clone()
}

// Snapshot — здоровье всех известных узлов, для `hop nodes` (§С5).
func (m *Monitor) Snapshot() []NodeHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]NodeHealth, 0, len(m.nodes))
	for _, h := range m.nodes {
		out = append(out, h.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// HasAlive — есть ли хоть один живой узел. Это то, что netstack спрашивает
// перед вердиктом (§3.4, Config.Healthy) и что показывает `no healthy nodes`
// в T4.
func (m *Monitor) HasAlive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, h := range m.nodes {
		if h.State == Alive {
			return true
		}
	}
	return false
}

func (m *Monitor) entryLocked(nodeID string) *NodeHealth {
	h, ok := m.nodes[nodeID]
	if !ok {
		h = &NodeHealth{NodeID: nodeID, State: Untested}
		m.nodes[nodeID] = h
	}
	return h
}

// limits — окно и порог смерти §6.3.
//
// Развилка политики k_of_n: выключенная политика оставляет от окна одну
// последнюю пробу — путь sing-box с DeleteURLTestHistory, где единственная
// неудача стирает историю узла и на нестабильной сети выбор мечется.
func (m *Monitor) limits() (k, n int) {
	if policy.KOfN.On() {
		return m.cfg.K, m.cfg.N
	}
	return 1, 1
}

// pushLocked двигает окно и выводит из него состояние. Возвращает true, если
// узел именно этим исходом стал мёртвым: повторная смерть уже мёртвого узла —
// не событие, и будить на неё выбор незачем.
func (m *Monitor) pushLocked(h *NodeHealth, o Outcome) bool {
	was := h.State
	k, n := m.limits()

	h.Window = append(h.Window, o)
	if len(h.Window) > n {
		h.Window = append(h.Window[:0], h.Window[len(h.Window)-n:]...)
	}

	fails, ok := 0, false
	for _, w := range h.Window {
		if w == OK {
			ok = true
			continue
		}
		fails++
	}
	switch {
	case fails >= k:
		h.State = Dead
	case ok:
		h.State = Alive
	default:
		// Проб было мало и все неудачные: до порога §6.3 не дотянули, но
		// живым такой узел называть нечего — латентности у него нет.
		h.State = Untested
	}
	return h.State == Dead && was != Dead
}

// outcomeOf различает зависание и отказ. Разница нужна §8.1: blackhole ловит
// отсутствие таймаута там, где rst его маскирует.
func outcomeOf(err error) Outcome {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return Timeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return Timeout
	}
	return Fail
}
