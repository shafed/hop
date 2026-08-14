package health

import (
	"context"
	"testing"

	"github.com/shafed/hop/internal/clock"
)

// T2. Одна неудача, потом успех — узел жив, активный узел не менялся ни разу.
// При k=1 первая же ошибка убила бы A и увела бы пользователя на B: ровно это
// делает sing-box своим DeleteURLTestHistory (§6.3).
func TestT2SingleFailureDoesNotKill(t *testing.T) {
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
	h.ok("A", 50*ms)
	h.sel.Reconsider()

	if got := h.mon.Get("A").State; got != Alive {
		t.Fatalf("после одной неудачи и успеха состояние A — %q", got)
	}
	if h.sel.Active() != "A" {
		t.Fatalf("активен %q, ожидался неизменный A", h.sel.Active())
	}
	if got := h.switches(); len(got) != 0 {
		t.Fatalf("одна неудача дала %d переключений: %+v", len(got), got)
	}
}

// Ошибки реального трафика §6.15 идут в то же окно, что и пробы: §5.4 считает
// оба источника одним свидетельством о живости. Узел, который не смог принять
// ни одного соединения, обязан умереть без единой пробы.
func TestTrafficFailuresShareProbeWindow(t *testing.T) {
	clk := clock.NewFake(epoch)
	mon := NewMonitor(DefaultMonitorConfig(), clk)

	mon.Observe("A", Result{RTT: 50 * ms})
	mon.ReportFailure("A", HandshakeFailed)
	if got := mon.Get("A").State; got != Alive {
		t.Fatalf("одна ошибка трафика дала состояние %q", got)
	}

	mon.ReportFailure("A", DialTimeout)
	h := mon.Get("A")
	if h.State != Dead {
		t.Fatalf("две ошибки трафика из трёх дали состояние %q", h.State)
	}
	if h.TrafficFailures != 2 {
		t.Fatalf("счётчик ошибок трафика %d, ожидалось 2", h.TrafficFailures)
	}
	if h.Window[len(h.Window)-1] != Timeout {
		t.Fatalf("dial-timeout попал в окно как %v, ожидался таймаут", h.Window[len(h.Window)-1])
	}
	if mon.HasAlive() {
		t.Fatal("HasAlive говорит «жив» про единственный мёртвый узел")
	}

	mon.ReportSuccess("A", 70*ms)
	mon.ReportSuccess("A", 70*ms)
	if got := mon.Get("A"); got.State != Alive || got.TrafficFailures != 0 {
		t.Fatalf("после успешного трафика узел %+v, ожидался живой с нулём ошибок", got)
	}
}

// Незнакомый узел — untested, а не «нет данных»: отсутствие истории тоже
// состояние (§2), и непроверенный узел не должен выигрывать выбор.
func TestUnknownNodeIsUntested(t *testing.T) {
	mon := NewMonitor(DefaultMonitorConfig(), clock.NewFake(epoch))
	if got := mon.Get("нет-такого"); got.State != Untested || got.NodeID != "нет-такого" {
		t.Fatalf("незнакомый узел выглядит как %+v", got)
	}

	// Снимок отдаёт копию: правка у вызывающего не должна доезжать до окна.
	mon.Observe("A", Result{RTT: 10 * ms})
	snap := mon.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("снимок содержит %d узлов, ожидался один", len(snap))
	}
	snap[0].Window[0] = Fail
	if mon.Get("A").Window[0] != OK {
		t.Fatal("Snapshot отдал окно по ссылке: чужая правка изменила историю")
	}
}

// Зависшая проба обязана лечь в окно таймаутом, а не отказом: blackhole ловит
// отсутствие таймаута там, где rst его маскирует (§8.1).
func TestHungProbeIsTimeout(t *testing.T) {
	mon := NewMonitor(DefaultMonitorConfig(), clock.NewFake(epoch))
	mon.Observe("A", Result{Err: context.DeadlineExceeded})
	h := mon.Get("A")
	if len(h.Window) != 1 || h.Window[0] != Timeout {
		t.Fatalf("окно после зависшей пробы: %v", h.Window)
	}
	if h.State != Untested {
		t.Fatalf("одна зависшая проба дала состояние %q, а порога смерти она не набрала", h.State)
	}
}
