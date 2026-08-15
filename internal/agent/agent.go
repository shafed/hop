// Пакет agent — связка (§3.4). Он владеет остальными модулями и соединяет их
// события; сам он не умеет ни разбирать пакеты, ни считать живость, ни ходить в
// сеть.
//
// Почему это пакет, а не главная функция. Связка — единственное место, где
// границы всех шести модулей встречаются друг с другом, и ошибка в ней лежит
// **между** модулями, каждый из которых по отдельности зелен. В `cmd/hop` такая
// логика проверялась бы только запуском бинаря; здесь она проверяется как всё
// остальное — на фейковых часах, без прав, на трёх ОС.
//
// Регистр проверок — `docs/verification-agent.md`, написан до этого файла.
package agent

import (
	"sync"
	"time"

	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/tunnel"
)

// TrafficPhase — §2, TunnelState.traffic_phase: фаза, которой владеет агент.
//
// Вторая половина разделения из §2. Сервисная фаза (`tunnel.Phase`) отвечает на
// вопрос «есть ли интерфейс», эта — на вопрос «что происходит с пакетом». Одно
// поле на оба не годилось: комбинация «туннель поднят, живых узлов нет»
// истинна целиком, а выражалась бы половиной.
type TrafficPhase string

const (
	// PhaseWaiting — стартовый бюджет §5.6: ни один узел ещё не проверен,
	// трафик ждёт. Это не Failing: там знание, здесь незнание, и пользователю
	// показывать их одинаково нельзя.
	PhaseWaiting TrafficPhase = "waiting"
	// PhaseProxied — есть живой узел, трафик идёт через него.
	PhaseProxied TrafficPhase = "proxied"
	// PhaseFailing — живых узлов нет, fail-close (§5.6).
	PhaseFailing TrafficPhase = "failing"
	// PhaseBypass — обход включён осознанно (§1/С6). Туннель при этом снят
	// (Р35 регистра связки), поэтому Tunnel в снимке будет Down.
	PhaseBypass TrafficPhase = "bypass"
)

// Snapshot — всё наблюдаемое состояние агента одним значением.
//
// Одним, а не набором геттеров: между двумя вызовами состояние меняется, и
// тест, собирающий снимок из трёх обращений, проверяет то, чего не было ни в
// один момент времени. Тот же довод, что у `health.Snapshot`.
type Snapshot struct {
	// Tunnel — фаза сервиса, как её отдал Status(). Пусто, если связи нет.
	Tunnel tunnel.Phase
	// Traffic — наша фаза.
	Traffic TrafficPhase
	// Active — id активного узла или пусто.
	Active string
	// Last — последнее переключение. Нулевое, если его не было.
	Last health.SwitchEvent
	// Auto — включено ли автопереключение (§1/С3).
	Auto bool
	// Pinned — зафиксированный узел или пусто. Фиксация буквальна: §1/С3.
	Pinned string
	// Rebuilds — сколько раз пересобирался инстанс Xray. Нужен WaitRebuild:
	// без счётчика У4 проверяется сном (§2 регистра).
	Rebuilds uint64
	// Detached — почему нет связи с сервисом. Пусто, когда связь есть (Р34).
	Detached string
	// Nodes — живость целиком, как её отдал health.
	Nodes []health.NodeHealth
}

// eventRing — кольцо последних событий переключения (§2).
//
// Кольцо, а не журнал на диске: флаппящая подписка писала бы непрерывно, а
// ценность истории переключений падает с возрастом быстрее, чем растёт файл.
// Размер — из §2.
const eventRingSize = 256

type eventRing struct {
	mu   sync.Mutex
	buf  []health.SwitchEvent
	next int
	n    int
	subs []chan health.SwitchEvent
}

func newEventRing() *eventRing {
	return &eventRing{buf: make([]health.SwitchEvent, eventRingSize)}
}

// push кладёт событие в кольцо и рассылает подписчикам.
//
// Рассылка неблокирующая: подписчик, который не читает, теряет события, но не
// останавливает переключение узлов. Обратный выбор поставил бы живость трафика
// в зависимость от расторопности CLI-клиента.
func (r *eventRing) push(ev health.SwitchEvent) {
	r.mu.Lock()
	r.buf[r.next] = ev
	r.next = (r.next + 1) % len(r.buf)
	if r.n < len(r.buf) {
		r.n++
	}
	subs := append([]chan health.SwitchEvent(nil), r.subs...)
	r.mu.Unlock()

	for _, c := range subs {
		select {
		case c <- ev:
		default:
		}
	}
}

// history отдаёт накопленное в хронологическом порядке.
func (r *eventRing) history() []health.SwitchEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]health.SwitchEvent, 0, r.n)
	start := 0
	if r.n == len(r.buf) {
		start = r.next
	}
	for i := 0; i < r.n; i++ {
		out = append(out, r.buf[(start+i)%len(r.buf)])
	}
	return out
}

// subscribe отдаёт накопленное и канал на будущее — одним вызовом и под одним
// замком.
//
// Двумя вызовами было бы окно, в котором событие уже не в истории и ещё не в
// канале. Клиент, подключившийся сразу после переключения, обязан его увидеть
// (§2), а такое окно ровно это и ломает.
func (r *eventRing) subscribe(buf int) ([]health.SwitchEvent, <-chan health.SwitchEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]health.SwitchEvent, 0, r.n)
	start := 0
	if r.n == len(r.buf) {
		start = r.next
	}
	for i := 0; i < r.n; i++ {
		out = append(out, r.buf[(start+i)%len(r.buf)])
	}

	c := make(chan health.SwitchEvent, buf)
	r.subs = append(r.subs, c)
	return out, c
}

func (r *eventRing) unsubscribe(c <-chan health.SwitchEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, s := range r.subs {
		if (<-chan health.SwitchEvent)(s) == c {
			r.subs = append(r.subs[:i], r.subs[i+1:]...)
			close(s)
			return
		}
	}
}

func (r *eventRing) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, s := range r.subs {
		close(s)
	}
	r.subs = nil
}

// reaction — что связка сделала в ответ на переключение. Порядок этих четырёх
// зафиксирован (Р33), а зафиксированный порядок надо чем-то наблюдать.
type reaction uint8

const (
	reactFlush reaction = iota + 1
	reactInterrupt
	reactEvent
	reactPersist
)

func (r reaction) String() string {
	switch r {
	case reactFlush:
		return "flush"
	case reactInterrupt:
		return "interrupt"
	case reactEvent:
		return "event"
	case reactPersist:
		return "persist"
	default:
		return "unknown"
	}
}

// reactionLog — журнал реакций. В продукте он ограничен последним
// переключением и стоит четыре записи; тесту этого хватает, а памяти не жаль.
type reactionLog struct {
	mu   sync.Mutex
	last []reaction
}

func (l *reactionLog) begin() {
	l.mu.Lock()
	l.last = l.last[:0]
	l.mu.Unlock()
}

func (l *reactionLog) mark(r reaction) {
	l.mu.Lock()
	l.last = append(l.last, r)
	l.mu.Unlock()
}

func (l *reactionLog) order() []reaction {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]reaction(nil), l.last...)
}

// Стартовые значения §4 регистра. Собраны здесь, а не рассыпаны по коду: у
// каждого из них есть источник, и разъехаться они должны заметно.
const (
	// drainTimeout — потолок дренажа старого инстанса Xray (§5.8, Р32).
	drainTimeout = 30 * time.Second
	// healthPersistEvery — период сохранения среза живости (Р36). Равен
	// дебаунсу стора намеренно: два периода разъехались бы при первой правке.
	healthPersistEvery = 30 * time.Second
	// reattachMin, reattachMax — backoff восстановления связи с сервисом (Р34).
	reattachMin = time.Second
	reattachMax = 15 * time.Second
)
