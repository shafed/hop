// Package tunnel — машина состояний сервиса `up → orphaned → (up | down)`
// из §6.2.
//
// Пакет намеренно ничего не знает про ОС, сокеты и права: он получает Net
// (привилегированные операции) и Clock (§8.1) и больше ни от чего не зависит.
// Поэтому весь §6.2 проверяется как L1 — без прав, на всех трёх ОС.
//
// Машина синхронна: своих горутин у неё нет. Дедлайн проверяется в Poll и в
// начале каждой операции, поэтому событие, пришедшее после истечения дедлайна,
// видит уже убранный туннель независимо от того, успел ли кто-то вызвать Poll.
// В продукте Poll зовёт Runner (runner.go), в тестах — сам тест после прокрутки
// фейковых часов.
package tunnel

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/policy"
)

// Phase — §2, TunnelState.phase.
type Phase string

const (
	Down     Phase = "down"
	Starting Phase = "starting"
	Up       Phase = "up"
	Orphaned Phase = "orphaned"
	Failing  Phase = "failing"
	Bypass   Phase = "bypass"
)

// Reason — почему агента не стало.
type Reason string

const (
	// ReasonClosed — ребро по закрытию соединения: EOF/EPIPE на управляющем
	// сокете, ERROR_BROKEN_PIPE на трубе. Приходит и при kill -9.
	ReasonClosed Reason = "closed"
	// ReasonHeartbeat — heartbeat_miss пропусков подряд: агент жив, но
	// заклинил, сокет не закрылся, ребро само не сработало.
	ReasonHeartbeat Reason = "heartbeat"
	// ReasonRestart — Detach(reason=restart): плановый перезапуск агента.
	ReasonRestart Reason = "restart"
)

// Device — то, что сервис отдаёт агенту: дескриптор TUN (Linux, macOS) или
// конец трубы (Windows). Ref устойчив: реаттач обязан вернуть тот же (T24).
type Device interface {
	Ref() string
	Close() error
}

// Params — параметры интерфейса и маршрутов. Ни одного узла и ни одного
// ключа (§3.1).
type Params struct {
	Name     string // имя интерфейса
	MTU      int
	Addr     string // адрес туннеля с маской, "10.255.0.1/24"
	Table    int    // номер таблицы маршрутизации туннеля
	AgentUID int    // для ip rule с UID-диапазоном (§6.8)
}

// Net — привилегированные операции, которыми командует машина. Реализация —
// платформенный слой; в L1-тесте — фейк.
//
// Reject и Restore обязаны трогать только политику для пакетов: интерфейс,
// адреса и индекс в состоянии orphaned не меняются (§6.2), иначе теряется
// смысл T24.
type Net interface {
	Up(Params) (Device, error)
	// Reject переводит устройство в отказ: читателем становится сам сервис и
	// отвечает RST/ICMP на каждый пакет (§6.2). Подмена маршрутов ядра на
	// unreachable/-reject была первым решением и отвергнута замером: она
	// закрывает только новые соединения, у установленного сокета Write
	// продолжает возвращать успех.
	Reject() error
	// Restore возвращает устройство агенту: читатель сервиса уходит, маршруты
	// возвращаются в туннельную форму.
	Restore() error
	Down() error // полный teardown до снапшота
}

// Config — пороги §6.2.
type Config struct {
	OrphanDeadline time.Duration // 15 с
	Heartbeat      time.Duration // 1 с
	HeartbeatMiss  int           // 3
}

// DefaultConfig — стартовые значения §6.2.
func DefaultConfig() Config {
	return Config{OrphanDeadline: 15 * time.Second, Heartbeat: time.Second, HeartbeatMiss: 3}
}

// Handle — ответ на StartTunnel и Attach.
type Handle struct {
	Device Device
	Token  Token
}

// State — то, что уезжает в Status() (§3.1).
type State struct {
	Phase        Phase
	DetachReason Reason        // заполнен только в orphaned
	OrphanLeft   time.Duration // сколько осталось до teardown, только в orphaned
	Device       string        // Ref устройства, пусто в down
}

var (
	ErrWrongPhase = errors.New("tunnel: операция недопустима в текущем состоянии")
	ErrBadToken   = errors.New("tunnel: неверный attach-token")
	ErrWrongOwner = errors.New("tunnel: туннель принадлежит другому владельцу")
)

// Machine — сама машина состояний.
type Machine struct {
	clk clock.Clock
	net Net
	cfg Config

	mu        sync.Mutex
	phase     Phase
	params    Params
	device    Device
	token     Token
	owner     string // UID (Linux, macOS) или SID (Windows) владельца туннеля
	reason    Reason
	orphanAt  time.Time // момент ребра; дедлайн считается от него и ни от чего больше
	lastBeat  time.Time
	failedTry int // неудачные Attach — только для наблюдаемости, на дедлайн не влияют
}

// New создаёт машину в состоянии down.
func New(clk clock.Clock, net Net, cfg Config) *Machine {
	return &Machine{clk: clk, net: net, cfg: cfg, phase: Down}
}

// Start — StartTunnel(TunnelParams) (§3.1). owner — UID или SID вызывающего.
func (m *Machine) Start(p Params, owner string) (Handle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked()

	if m.phase != Down {
		return Handle{}, fmt.Errorf("%w: %s, ожидалось down", ErrWrongPhase, m.phase)
	}
	m.phase = Starting
	dev, err := m.net.Up(p)
	if err != nil {
		m.phase = Down
		return Handle{}, err
	}
	m.params = p
	m.device = dev
	m.token = NewToken()
	m.owner = owner
	m.phase = Up
	m.reason = ""
	m.lastBeat = m.clk.Now()
	m.failedTry = 0
	return Handle{Device: dev, Token: m.token}, nil
}

// AgentGone — ребро в orphaned. Стоит 0 мс и не зависит ни от какого таймера:
// его источник — закрытие соединения датаплейна либо heartbeat_miss.
func (m *Machine) AgentGone(r Reason) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked()
	m.enterOrphanedLocked(r)
}

func (m *Machine) enterOrphanedLocked(r Reason) {
	if m.phase != Up {
		return
	}
	m.phase = Orphaned
	m.reason = r
	m.orphanAt = m.clk.Now()
	m.failedTry = 0

	// §6.2: в orphaned меняется только политика для пакетов. Без этого шага
	// окно молчаливое — интерфейс жив, читателя нет, пакеты дропаются, что
	// прямо запрещено §5.6. Это и краснит T23-fast/T23b при orphan_reject=off.
	if policy.OrphanReject.On() {
		_ = m.net.Reject()
	}

	// orphan_deadline=off схлопывает окно в ноль: агенту некуда возвращаться,
	// и T24 краснеет — интерфейс исчезает до реаттача.
	if m.deadlineLocked() == 0 {
		m.teardownLocked()
	}
}

// Attach — реаттач по токену (§3.1). Проверяются и токен, и владелец.
//
// Неудачная попытка не двигает orphanAt: дедлайн считается от ребра. Иначе
// непривилегированный локальный процесс, предъявляющий мусорный токен в цикле,
// держит машину в состоянии отказа сколько угодно долго.
func (m *Machine) Attach(t Token, owner string) (Handle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked()

	if m.phase != Orphaned {
		return Handle{}, fmt.Errorf("%w: %s, ожидалось orphaned", ErrWrongPhase, m.phase)
	}
	if owner != m.owner {
		m.failedTry++
		return Handle{}, ErrWrongOwner
	}
	if !m.token.equal(t) {
		m.failedTry++
		return Handle{}, ErrBadToken
	}

	if err := m.net.Restore(); err != nil {
		return Handle{}, err
	}
	m.phase = Up
	m.reason = ""
	m.lastBeat = m.clk.Now()
	m.failedTry = 0
	// Токен тот же: он привязан к туннелю, а не к сеансу агента. Иначе агент,
	// упавший второй раз, реаттачиться уже не сможет.
	return Handle{Device: m.device, Token: m.token}, nil
}

// Detach — плановый уход агента (§3.1). Ребро то же, но причина известна и
// видна в Status.
func (m *Machine) Detach(r Reason) {
	if r == "" {
		r = ReasonRestart
	}
	m.AgentGone(r)
}

// Heartbeat отмечает, что агент жив.
func (m *Machine) Heartbeat() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked()
	if m.phase == Up {
		m.lastBeat = m.clk.Now()
	}
}

// Stop — StopTunnel: полный teardown из любого состояния.
func (m *Machine) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.phase == Down {
		return nil
	}
	return m.teardownLocked()
}

// Poll двигает машину по времени: истёкший orphan_deadline и заклинивший
// живой агент. В продукте зовёт Runner, в тестах — сам тест.
func (m *Machine) Poll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked()
}

// State — снимок для Status().
func (m *Machine) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked()

	s := State{Phase: m.phase, DetachReason: m.reason}
	if m.device != nil && m.phase != Down {
		s.Device = m.device.Ref()
	}
	if m.phase == Orphaned {
		s.OrphanLeft = m.orphanAt.Add(m.deadlineLocked()).Sub(m.clk.Now())
		if s.OrphanLeft < 0 {
			s.OrphanLeft = 0
		}
	}
	return s
}

// FailedAttempts — сколько Attach отвергнуто с момента ребра. Наблюдаемость:
// само число ни на что не влияет, и тест на это смотрит.
func (m *Machine) FailedAttempts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.failedTry
}

func (m *Machine) deadlineLocked() time.Duration {
	if !policy.OrphanDeadline.On() {
		return 0
	}
	return m.cfg.OrphanDeadline
}

// expireLocked — единственное место, где машина смотрит на часы сама.
func (m *Machine) expireLocked() {
	now := m.clk.Now()
	switch m.phase {
	case Up:
		if m.cfg.HeartbeatMiss > 0 && m.cfg.Heartbeat > 0 {
			miss := time.Duration(m.cfg.HeartbeatMiss) * m.cfg.Heartbeat
			if now.Sub(m.lastBeat) >= miss {
				m.enterOrphanedLocked(ReasonHeartbeat)
			}
		}
	case Orphaned:
		if !now.Before(m.orphanAt.Add(m.deadlineLocked())) {
			m.teardownLocked()
		}
	}
}

func (m *Machine) teardownLocked() error {
	err := m.net.Down()
	if m.device != nil {
		if cerr := m.device.Close(); err == nil {
			err = cerr
		}
	}
	m.phase = Down
	m.device = nil
	m.token = ""
	m.owner = ""
	m.reason = ""
	m.failedTry = 0
	return err
}
