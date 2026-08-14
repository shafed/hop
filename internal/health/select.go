package health

import (
	"fmt"
	"sync"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/policy"
)

// Reason — §2, last_switch.reason. Не украшение: от него зависит, рвать ли
// активные соединения (§5.5).
type Reason string

const (
	// ReasonDead — активный узел признан мёртвым. Его соединения уже мертвы, и
	// разрыв даёт приложению переподключиться за секунды вместо минут
	// TCP-таймаута.
	ReasonDead Reason = "dead"
	// ReasonFaster — нашёлся узел быстрее. Рвать нечего и незачем: обрыв
	// загрузки или звонка ради 30 мс раздражает сильнее, чем сами 30 мс.
	ReasonFaster Reason = "faster"
	// ReasonManual — `hop up --node` или `hop node use`.
	ReasonManual Reason = "manual"
)

// Switch — «Событие переключения» §2.
type Switch struct {
	At                     time.Time
	From                   string
	To                     string
	Reason                 Reason
	InterruptedConnections int
}

// Interrupts — рвать ли активные соединения по этому переключению (§5.5).
//
// Решение живёт здесь, а не у потребителя события, потому что оно целиком
// выводится из reason, и второе место означало бы второй ответ на тот же
// вопрос. В sing-box reason нет вовсе (`performUpdateCheck` знает только «выбор
// изменился»), поэтому разрыв там пришлось делать глобальным флагом.
//
// Политика switch_reason: при выключении метод перестаёт различать причины и
// рвёт всегда — это краснит T10 (соединение через медленный узел не доживает до
// конца).
func (sw Switch) Interrupts() bool {
	if !policy.SwitchReason.On() {
		return true
	}
	return sw.Reason == ReasonDead
}

// SelectorConfig — гистерезис §6.4.
type SelectorConfig struct {
	// Tolerance — насколько кандидат должен быть быстрее активного, чтобы
	// переключение состоялось.
	Tolerance time.Duration
}

// DefaultSelectorConfig — стартовое значение §6.4: 50 мс, как в sing-box. Без
// него два узла с 90 и 95 мс перекидывают пользователя туда-сюда на каждом
// цикле.
func DefaultSelectorConfig() SelectorConfig {
	return SelectorConfig{Tolerance: 50 * time.Millisecond}
}

// subBuffer — глубина канала подписчика. Событие переключения редкое, а
// подписчик может быть занят: буфер отвязывает выбор узла от скорости CLI.
const subBuffer = 64

// Selector — выбор активного узла и рассылка события переключения.
//
// Своих горутин не заводит: пересчёт делает Reconsider, которого зовёт тот, кто
// узнал новость — расписание после прогона проб или движок после ошибки
// трафика. Так весь §6.4 проверяется на фейковых часах без гонок.
type Selector struct {
	mon *Monitor
	cfg SelectorConfig
	clk clock.Clock

	mu         sync.Mutex
	candidates []string
	active     string
	pinned     bool
	closed     bool
	subs       []chan Switch
}

// NewSelector создаёт селектор поверх монитора. Активного узла нет, пока не
// позван Reconsider или Pin.
func NewSelector(m *Monitor, cfg SelectorConfig, clk clock.Clock) *Selector {
	return &Selector{mon: m, cfg: cfg, clk: clk}
}

// SetCandidates задаёт множество, из которого выбираем: поддержанные узлы
// (§6.11) всех групп. Исчезнувший из подписки узел обязан исчезнуть и отсюда,
// иначе выбор упрётся в узел, которого нет (T19).
func (s *Selector) SetCandidates(ids []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidates = append([]string(nil), ids...)
}

// Active — текущий выбор, пусто при «no healthy nodes» (T4).
func (s *Selector) Active() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Pin фиксирует узел вручную и выключает автовыбор до Auto(true) (§С3).
// Порождает событие с reason=manual.
func (s *Selector) Pin(nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.knownLocked(nodeID) {
		return fmt.Errorf("health: узел %q не в списке кандидатов", nodeID)
	}
	s.pinned = true
	if s.active == nodeID {
		return nil
	}
	s.switchLocked(nodeID, ReasonManual)
	return nil
}

// Auto включает и выключает автопереключение.
func (s *Selector) Auto(on bool) {
	s.mu.Lock()
	s.pinned = !on
	s.mu.Unlock()

	if on {
		// `hop auto on` обязан пересчитать сразу: фиксация могла держать
		// пользователя на узле, который давно мёртв.
		s.Reconsider()
	}
}

// Reconsider пересчитывает выбор по текущему здоровью и, если выбор сменился,
// рассылает событие.
//
// Политика tolerance: при выключении гистерезис становится нулевым, и любые
// колебания rtt дают переключение — это краснит T3.
func (s *Selector) Reconsider() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pinned || s.closed {
		return
	}

	best, bestRTT := s.bestLocked()
	cur := s.active
	if cur == best {
		return
	}
	if best == "" {
		// Живых узлов не осталось: выбор пуст, дальше работает fail-close
		// §5.6. Причина «dead» — активный узел именно умер (T4).
		s.switchLocked("", ReasonDead)
		return
	}

	curH := s.mon.Get(cur)
	if cur == "" || !s.knownLocked(cur) || curH.State != Alive {
		// Держаться не за что: активного нет вовсе, он выпал из подписки
		// (T19) или мёртв (T1). Перечисление причин §2 замкнуто, третьей нет,
		// и «dead» честнее «faster»: выигрыша по rtt здесь не измеряли.
		s.switchLocked(best, ReasonDead)
		return
	}

	tol := s.cfg.Tolerance
	if !policy.Tolerance.On() {
		tol = 0
	}
	if curH.RTT-bestRTT > tol {
		s.switchLocked(best, ReasonFaster)
	}
}

// Subscribe отдаёт канал событий переключения. Подписчиков может быть
// несколько: §3.3 требует рассылки всем, а не одному, — в v1 это CLI, дальше к
// нему добавятся GUI и трей.
func (s *Selector) Subscribe() <-chan Switch {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan Switch, subBuffer)
	if s.closed {
		close(ch)
		return ch
	}
	s.subs = append(s.subs, ch)
	return ch
}

// Close закрывает каналы подписчиков.
func (s *Selector) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}
	s.closed = true
	for _, ch := range s.subs {
		close(ch)
	}
	s.subs = nil
}

// bestLocked — живой узел с минимальным rtt (§6.4). Порядок кандидатов решает
// ничью, чтобы одинаковые latencies не перекидывали выбор сами по себе.
func (s *Selector) bestLocked() (string, time.Duration) {
	var best string
	var bestRTT time.Duration
	for _, id := range s.candidates {
		h := s.mon.Get(id)
		if h.State != Alive {
			continue
		}
		if best == "" || h.RTT < bestRTT {
			best, bestRTT = id, h.RTT
		}
	}
	return best, bestRTT
}

func (s *Selector) knownLocked(id string) bool {
	for _, c := range s.candidates {
		if c == id {
			return true
		}
	}
	return false
}

func (s *Selector) switchLocked(to string, r Reason) {
	sw := Switch{At: s.clk.Now(), From: s.active, To: to, Reason: r}
	s.active = to
	for _, ch := range s.subs {
		select {
		case ch <- sw:
		default:
			// Подписчик не читает свой канал. Блокировать на нём выбор узла
			// нельзя: тогда зависший CLI останавливает автопереключение.
		}
	}
}
