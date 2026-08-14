package health

import (
	"errors"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
)

// Все тесты §8.2 идут на фейковых часах и фейковом пробере: без сети, без TUN и
// без sleep. Иначе один тест окна «2 из 3» занимает минуты (§8.1).
var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const ms = time.Millisecond

// harness — монитор, селектор и подписка на события в одной коробке.
type harness struct {
	t      *testing.T
	clk    *clock.Fake
	mon    *Monitor
	sel    *Selector
	events <-chan Switch
}

func newHarness(t *testing.T, ids ...string) *harness {
	t.Helper()
	clk := clock.NewFake(epoch)
	mon := NewMonitor(DefaultMonitorConfig(), clk)
	sel := NewSelector(mon, DefaultSelectorConfig(), clk)
	sel.SetCandidates(ids)
	t.Cleanup(sel.Close)
	return &harness{t: t, clk: clk, mon: mon, sel: sel, events: sel.Subscribe()}
}

// ok — успешная проба узла.
func (h *harness) ok(id string, rtt time.Duration) {
	h.mon.Observe(id, Result{RTT: rtt})
}

// fail — неудачная проба узла.
func (h *harness) fail(id string) {
	h.mon.Observe(id, Result{Err: errors.New("проба не прошла")})
}

// switches — всё, что накопилось в подписке, и очистка.
func (h *harness) switches() []Switch {
	var out []Switch
	for {
		select {
		case sw := <-h.events:
			out = append(out, sw)
		default:
			return out
		}
	}
}

// lastSwitch — последнее событие; отсутствие события само по себе провал.
func (h *harness) lastSwitch() Switch {
	h.t.Helper()
	all := h.switches()
	if len(all) == 0 {
		h.t.Fatal("события переключения не было")
	}
	return all[len(all)-1]
}

// T1. Узел A даёт 2 неудачи из 3 — он помечен dead, активным стал B.
func TestT1DeadNodeSwitchesToBackup(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.ok("A", 50*ms)
	h.ok("B", 100*ms)
	h.sel.Reconsider()
	if h.sel.Active() != "A" {
		t.Fatalf("активным стал %q, ожидался быстрейший A", h.sel.Active())
	}
	h.switches()

	h.fail("A")
	h.sel.Reconsider()
	if got := h.mon.Get("A").State; got != Alive {
		t.Fatalf("одна неудача из трёх дала состояние %q", got)
	}

	h.fail("A")
	h.sel.Reconsider()
	if got := h.mon.Get("A").State; got != Dead {
		t.Fatalf("две неудачи из трёх дали состояние %q", got)
	}
	if h.sel.Active() != "B" {
		t.Fatalf("после смерти A активен %q, ожидался B", h.sel.Active())
	}
}

// T3. A держит 100 мс, B колеблется 80–120 мс, 20 циклов — переключений быть не
// должно: выигрыш ни разу не превысил tolerance (§6.4).
func TestT3NoFlappingWithinTolerance(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.ok("A", 100*ms)
	h.ok("B", 100*ms)
	h.sel.Reconsider()
	if h.sel.Active() != "A" {
		t.Fatalf("активным стал %q, ожидался A", h.sel.Active())
	}
	h.switches()

	for i := 0; i < 20; i++ {
		h.ok("A", 100*ms)
		h.ok("B", time.Duration(80+(i*13)%41)*ms)
		h.sel.Reconsider()
	}

	if got := h.switches(); len(got) != 0 {
		t.Fatalf("за 20 циклов джиттера 80–120 мс произошло %d переключений: %+v", len(got), got)
	}
	if h.sel.Active() != "A" {
		t.Fatalf("активен %q, ожидался неизменный A", h.sel.Active())
	}
}

// T4. Все узлы мертвы — живых нет, выбор пуст, дальше работает fail-close §5.6.
func TestT4AllDeadLeavesNoSelection(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.ok("A", 50*ms)
	h.ok("B", 100*ms)
	h.sel.Reconsider()
	h.switches()

	for i := 0; i < 2; i++ {
		h.fail("A")
		h.fail("B")
	}
	h.sel.Reconsider()

	if h.mon.HasAlive() {
		t.Fatal("HasAlive говорит «жив», хотя мертвы все: netstack не закроется")
	}
	if got := h.sel.Active(); got != "" {
		t.Fatalf("активным остался %q, ожидался пустой выбор", got)
	}
	if sw := h.lastSwitch(); sw.To != "" || sw.Reason != ReasonDead {
		t.Fatalf("событие %+v, ожидался переход в пустой выбор по причине dead", sw)
	}
}

// T7. Активный узел умер — событие несёт reason=dead, и по нему рвутся
// соединения (§5.5).
func TestT7DeadSwitchCarriesReasonDead(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.ok("A", 50*ms)
	h.ok("B", 100*ms)
	h.sel.Reconsider()
	h.switches()

	h.fail("A")
	h.fail("A")
	h.sel.Reconsider()

	sw := h.lastSwitch()
	if sw.From != "A" || sw.To != "B" || sw.Reason != ReasonDead {
		t.Fatalf("событие %+v, ожидалось A→B по причине dead", sw)
	}
	if sw.At != h.clk.Now() {
		t.Fatalf("время события %v, часы показывают %v", sw.At, h.clk.Now())
	}
	if !sw.Interrupts() {
		t.Fatal("смерть узла не рвёт соединения: приложение будет ждать TCP-таймаут")
	}
}

// T8. Нашёлся узел быстрее больше чем на tolerance — событие несёт
// reason=faster.
func TestT8FasterSwitchCarriesReasonFaster(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.ok("A", 100*ms)
	h.sel.Reconsider()
	h.switches()

	h.ok("B", 40*ms)
	h.sel.Reconsider()

	sw := h.lastSwitch()
	if sw.From != "A" || sw.To != "B" || sw.Reason != ReasonFaster {
		t.Fatalf("событие %+v, ожидалось A→B по причине faster", sw)
	}
}

// T10. Переключение на более быстрый узел не рвёт активные соединения (§5.5).
// Обрыв загрузки ради 60 мс раздражает сильнее, чем сами 60 мс.
func TestT10FasterSwitchKeepsConnections(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.ok("A", 100*ms)
	h.sel.Reconsider()
	h.switches()

	// Долгое соединение через A. Живёт, пока супервизор его не порвал.
	connAlive := true

	h.ok("B", 40*ms)
	h.sel.Reconsider()

	sw := h.lastSwitch()
	if sw.Reason != ReasonFaster {
		t.Fatalf("причина переключения %q, ожидалась faster", sw.Reason)
	}
	if sw.Interrupts() {
		connAlive = false // ровно это делает супервизор, получив такое событие
	}
	if !connAlive {
		t.Fatal("соединение через A порвано ради выигранных 60 мс")
	}
	if h.sel.Active() != "B" {
		t.Fatalf("новые соединения идут через %q, ожидался B", h.sel.Active())
	}
}

// Ручная фиксация узла выключает автовыбор до `hop auto on` (§С3).
func TestPinStopsAutoUntilAutoOn(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.ok("A", 100*ms)
	h.ok("B", 20*ms)
	h.sel.Reconsider()
	h.switches()

	if err := h.sel.Pin("A"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if sw := h.lastSwitch(); sw.To != "A" || sw.Reason != ReasonManual {
		t.Fatalf("событие %+v, ожидалось ручное переключение на A", sw)
	}

	h.sel.Reconsider()
	if h.sel.Active() != "A" {
		t.Fatalf("автовыбор увёл с зафиксированного узла на %q", h.sel.Active())
	}

	h.sel.Auto(true)
	if h.sel.Active() != "B" {
		t.Fatalf("после `auto on` активен %q, ожидался быстрейший B", h.sel.Active())
	}
	if err := h.sel.Pin("нет-такого"); err == nil {
		t.Fatal("Pin принял узел, которого нет среди кандидатов")
	}
}
