// Регистр проверок автопереключения — docs/verification-autoswitch.md §5.
// T* — номера из SPEC.md §8.2, A* — новые. Всё здесь уровня L1: фейковый
// пробер, фейковые часы, ни сети, ни TUN, ни Xray.
package health

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time" //hop:realtime
)

const ms = time.Millisecond

// --- 5.1 Окно и смерть узла (У1) ---------------------------------------

// T1: узел A даёт 2 неудачи из 3 — он мёртв, активным стал B.
func TestT1TwoFailuresKillNodeAndSwitch(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	if f.active() != "A" {
		t.Fatalf("активен %q, ожидался A — он быстрее", f.active())
	}

	f.prober.setFailing("A", true)
	f.advanceRound(DefaultActiveInterval)
	if got := f.state("A"); got == Dead {
		t.Fatal("узел умер от одной неудачи — правило k из n не работает")
	}
	f.advanceRound(DefaultActiveInterval)

	if got := f.state("A"); got != Dead {
		t.Errorf("состояние A = %v, ожидалось dead после двух неудач", got)
	}
	if f.active() != "B" {
		t.Errorf("активен %q, ожидался B", f.active())
	}
}

// T2: одна неудача, затем успех — активный узел не менялся ни разу.
// Охраняет k_of_n: при k=1 первая же неудача переключит.
func TestT2SingleFailureKeepsNodeAlive(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()
	f.waitFor("A не стал активным", func() bool { return f.active() == "A" })
	// Стартовый обход выбирает первый ответивший узел (Р4), поэтому считаем
	// переключения от установившегося состояния, а не от нуля.
	base := len(f.switches())

	f.prober.setFailing("A", true)
	f.advanceRound(DefaultActiveInterval)
	f.prober.setFailing("A", false)
	f.advanceRound(DefaultActiveInterval)

	if got := f.state("A"); got != Alive {
		t.Errorf("состояние A = %v, ожидалось alive: одна неудача не убивает", got)
	}
	if f.active() != "A" {
		t.Errorf("активен %q, ожидался A", f.active())
	}
	if sw := f.switches(); len(sw) != base {
		t.Errorf("переключений после старта %d, ожидалось 0: %+v", len(sw)-base, sw[base:])
	}
}

// A1: окно скользящее, а не «подряд» — [fail, ok, fail] убивает.
func TestA1WindowIsSlidingNotConsecutive(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	for _, fail := range []bool{true, false, true} {
		f.prober.setFailing("A", fail)
		f.advanceRound(DefaultActiveInterval)
	}

	if got := f.state("A"); got != Dead {
		t.Errorf("состояние A = %v, ожидалось dead: в окне [fail, ok, fail] две неудачи", got)
	}
}

// A2: четвёртый результат вытесняет первую неудачу — узел жив.
func TestA2OldFailureLeavesTheWindow(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	for _, fail := range []bool{true, false, false} {
		f.prober.setFailing("A", fail)
		f.advanceRound(DefaultActiveInterval)
	}

	if got := f.state("A"); got != Alive {
		t.Errorf("состояние A = %v, ожидалось alive: окно [ok, ok, ...] без двух неудач", got)
	}
	h, _ := f.mgr.Snapshot().Node("A")
	if len(h.Window) != DefaultN {
		t.Errorf("длина окна %d, ожидалось %d", len(h.Window), DefaultN)
	}
}

// A3: воскрешение (Р1) — мёртвый узел возвращается ровно после k успехов.
// Охраняет k_of_n: при k=1 два успеха его не вернут.
func TestA3DeadNodeReturnsAfterTwoSuccesses(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	f.prober.setFailing("A", true)
	f.advanceRound(DefaultActiveInterval)
	f.advanceRound(DefaultActiveInterval)
	if f.state("A") != Dead {
		t.Fatalf("A не умер после двух неудач: %v", f.state("A"))
	}

	// Мёртвый узел ушёл в хвост расписания, поэтому шаг — хвостовой интервал.
	f.prober.setFailing("A", false)
	f.advanceRound(2 * DefaultTailInterval)
	if got := f.state("A"); got != Dead {
		t.Errorf("состояние A = %v, ожидалось dead: одного успеха мало", got)
	}
	f.advanceRound(2 * DefaultTailInterval)
	if got := f.state("A"); got != Alive {
		t.Errorf("состояние A = %v, ожидалось alive после двух успехов", got)
	}
}

// A4: мёртвый узел продолжает опрашиваться — иначе смерть необратима.
func TestA4DeadNodeKeepsBeingProbed(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	f.prober.setFailing("A", true)
	f.advanceRound(DefaultActiveInterval)
	f.advanceRound(DefaultActiveInterval)
	if f.state("A") != Dead {
		t.Fatalf("A не умер: %v", f.state("A"))
	}

	before := f.prober.callCount("A")
	f.advanceRound(2 * DefaultTailInterval)
	if after := f.prober.callCount("A"); after <= before {
		t.Errorf("проб мёртвого узла %d → %d: мёртвый узел перестал опрашиваться", before, after)
	}
}

// A5: ошибки трафика §6.15 убивают узел наравне с пробами (Р2).
// Охраняет traffic_kills.
func TestA5TrafficFailuresKillNode(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	f.mgr.ReportFailure("A", DialTimeout)
	if got := f.state("A"); got != Alive {
		t.Errorf("состояние A = %v после одной ошибки трафика, ожидалось alive", got)
	}
	f.mgr.ReportFailure("A", HandshakeFailed)

	if got := f.state("A"); got != Dead {
		t.Errorf("состояние A = %v, ожидалось dead после двух ошибок трафика", got)
	}
	if f.active() != "B" {
		t.Errorf("активен %q, ожидался B", f.active())
	}
}

// A6: успешная проба гасит счётчик трафика, но не стирает окно проб (Р2).
func TestA6SuccessfulProbeClearsTrafficCounter(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	f.mgr.ReportFailure("A", TLSError)
	h, _ := f.mgr.Snapshot().Node("A")
	if h.TrafficFailures != 1 {
		t.Fatalf("счётчик трафика %d, ожидался 1", h.TrafficFailures)
	}

	f.advanceRound(DefaultActiveInterval)

	h, _ = f.mgr.Snapshot().Node("A")
	if h.TrafficFailures != 0 {
		t.Errorf("счётчик трафика %d после успешной пробы, ожидался 0", h.TrafficFailures)
	}
	if h.State != Alive {
		t.Errorf("состояние A = %v, ожидалось alive", h.State)
	}
}

// A7: отказ целевого хоста узел не убивает (§6.15). Такой отказ просто не
// попадает в перечисление, поэтому ReportFailure его игнорирует.
func TestA7TargetHostErrorsDoNotKillNode(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	for i := 0; i < 5; i++ {
		f.mgr.ReportFailure("A", FailureKind(0))  // «сайт вернул 502»
		f.mgr.ReportFailure("A", FailureKind(99)) // «NXDOMAIN»
	}

	h, _ := f.mgr.Snapshot().Node("A")
	if h.TrafficFailures != 0 {
		t.Errorf("счётчик трафика %d, ожидался 0: отказ целевого хоста узел не убивает", h.TrafficFailures)
	}
	if h.State != Alive {
		t.Errorf("состояние A = %v, ожидалось alive", h.State)
	}
	if f.active() != "A" {
		t.Errorf("активен %q, ожидался A", f.active())
	}
}

// A8: FailureKind — замкнутое перечисление, а не строка (§6.15).
func TestA8FailureKindIsClosedEnum(t *testing.T) {
	valid := []FailureKind{DialTimeout, HandshakeFailed, TLSError, ProxyRefused}
	for _, k := range valid {
		if !k.valid() {
			t.Errorf("%v обязан быть в перечислении", k)
		}
		if k.String() == "unknown" {
			t.Errorf("%d без имени", k)
		}
	}
	for _, k := range []FailureKind{0, 5, 99, 255} {
		if k.valid() {
			t.Errorf("%d не должен считаться ошибкой пути к узлу", k)
		}
	}
}

// --- 5.2 Выбор и гистерезис (У2) ---------------------------------------

// T3: A = 100 мс, B колеблется 80–120 мс, 20 циклов — переключений ≤ 1.
// Охраняет tolerance: при нулевом пороге узлы перекидывают друг друга каждый цикл.
func TestT3HysteresisLimitsSwitching(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), func(c *Config) {
		// Оба узла опрашиваются в одном темпе: цикл теста — это цикл проб.
		c.CandidateInterval = c.ActiveInterval
	})
	f.prober.setRTT("A", 100*ms)
	f.prober.cycleRTT("B", 80*ms, 120*ms)
	f.startAndSettle()

	base := len(f.switches()) // стартовый обход к гистерезису отношения не имеет

	for i := 0; i < 20; i++ {
		f.advanceRound(DefaultActiveInterval)
	}

	if sw := f.switches(); len(sw)-base > 1 {
		t.Errorf("переключений %d за 20 циклов, ожидалось ≤ 1: гистерезис не держит", len(sw)-base)
		for _, ev := range sw[base:] {
			t.Logf("  %s → %s (%v)", ev.From, ev.To, ev.Reason)
		}
	}
}

// A9: tolerance асимметричен — переключение с мёртвого узла не ждёт выигрыша.
func TestA9DeadSwitchIgnoresTolerance(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 300*ms) // на 200 мс хуже — но живой
	f.startAndSettle()

	f.prober.setFailing("A", true)
	f.advanceRound(DefaultActiveInterval)
	f.advanceRound(DefaultActiveInterval)

	if f.active() != "B" {
		t.Errorf("активен %q, ожидался B: с мёртвого узла уходят к любому живому", f.active())
	}
}

// A10: при равных rtt активный узел не меняется.
func TestA10EqualRTTKeepsCurrentNode(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 100*ms)
	f.startAndSettle()
	chosen := f.active()
	base := len(f.switches())

	for i := 0; i < 5; i++ {
		f.advanceRound(DefaultActiveInterval)
	}

	if f.active() != chosen {
		t.Errorf("активен %q, ожидался %q: равные rtt не повод менять выбор", f.active(), chosen)
	}
	if sw := f.switches(); len(sw) != base {
		t.Errorf("переключений %d при равных rtt, ожидалось 0: %+v", len(sw)-base, sw[base:])
	}
}

// A11: при равных rtt выбор идёт по node_order — иначе прогон невоспроизводим.
//
// Проверка белого ящика: в живом менеджере тот же вопрос решает ещё и порядок
// прихода ответов (Р4), поэтому правило сравнения проверяется на самом правиле.
func TestA11EqualRTTFollowsNodeOrder(t *testing.T) {
	f := newFixture(t, nodes("C", "B", "A"), nil) // порядок подписки, не алфавит

	f.mgr.mu.Lock()
	for _, id := range f.mgr.order {
		s := f.mgr.nodes[id]
		s.record(OK, DefaultN)
		s.record(OK, DefaultN)
		s.rtt = 100 * ms
	}
	f.mgr.selectLocked()
	got := f.mgr.active
	f.mgr.mu.Unlock()

	if got != "C" {
		t.Errorf("выбран %q, ожидался C — первый по node_order", got)
	}
}

// A12: холодный старт (Р4) — активным становится первый ответивший, а не
// лучший; лучший забирает выбор, когда ответит.
func TestA12ColdStartTakesFirstAnswer(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 50*ms) // быстрее, но отвечает позже
	f.prober.setRTT("B", 200*ms)
	release := f.prober.gate("A")

	f.mgr.Start()
	f.waitFor("B не стал активным до конца раунда", func() bool {
		return f.active() == "B"
	})

	release()
	f.waitRound(1)

	if f.active() != "A" {
		t.Errorf("активен %q, ожидался A: по концу раунда выигрывает быстрейший", f.active())
	}
}

// A13: неподдерживаемый узел не пробуется ни разу и не может быть выбран (§6.11).
func TestA13UnsupportedNodeIsNeverProbed(t *testing.T) {
	ns := []Node{{ID: "A", Supported: true}, {ID: "X", Supported: false}}
	f := newFixture(t, ns, nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("X", 1*ms) // был бы лучшим, если бы участвовал
	f.startAndSettle()

	for i := 0; i < 3; i++ {
		f.advanceRound(DefaultActiveInterval)
	}

	if n := f.prober.callCount("X"); n != 0 {
		t.Errorf("проб неподдерживаемого узла %d, ожидалось 0", n)
	}
	if f.active() != "A" {
		t.Errorf("активен %q, ожидался A", f.active())
	}
}

// --- 5.3 Отказ всех узлов (У4) -----------------------------------------

// T4: все узлы мертвы — выбор пуст.
func TestT4AllNodesDeadEmptiesSelection(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setFailing("A", true)
	f.prober.setFailing("B", true)
	f.startAndSettle()
	// Активного узла нет, поэтому все узлы опрашиваются как кандидаты.
	f.advanceRound(DefaultCandidateInterval)

	for _, id := range []string{"A", "B"} {
		if got := f.state(id); got != Dead {
			t.Errorf("состояние %s = %v, ожидалось dead", id, got)
		}
	}
	if f.active() != "" {
		t.Errorf("активен %q, ожидался пустой выбор", f.active())
	}
}

// A14: пустой выбор доезжает до netstack как fail-close (§3.4, п. 3).
// Это единственная проверка провода между health и netstack.
func TestA14EmptySelectionIsFailClose(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	if !f.mgr.Healthy() {
		t.Fatal("Healthy() = false при живых узлах")
	}

	f.prober.setFailing("A", true)
	f.prober.setFailing("B", true)
	f.killAll("A", "B")

	if f.mgr.Healthy() {
		t.Error("Healthy() = true при всех мёртвых узлах — fail-close не наступит")
	}
}

// A15: до конца первого раунда fail-close не наступает (Р5) — иначе на старте
// пользователь получает RST вместо ожидания.
func TestA15StartupGraceKeepsTrafficWaiting(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	if !f.mgr.Healthy() {
		t.Error("Healthy() = false до первой пробы: трафик обязан ждать, а не получать RST")
	}
}

// A16: стартовый бюджет истёк, живых нет — fail-close.
func TestA16StartupBudgetExpiresIntoFailClose(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.clk.Advance(DefaultStartupBudget)
	if f.mgr.Healthy() {
		t.Error("Healthy() = true после истечения стартового бюджета")
	}
}

// A17: подписка ожила — выбор вернулся, событие несёт пустой from.
func TestA17RecoveryAfterTotalDeath(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setFailing("A", true)
	f.prober.setFailing("B", true)
	f.startAndSettle()
	f.advanceRound(DefaultCandidateInterval)
	if f.active() != "" {
		t.Fatalf("активен %q, ожидался пустой выбор", f.active())
	}

	f.prober.setFailing("A", false)
	f.prober.setRTT("A", 100*ms)
	f.advanceRound(2 * DefaultTailInterval)
	f.advanceRound(2 * DefaultTailInterval)

	if f.active() != "A" {
		t.Fatalf("активен %q, ожидался A", f.active())
	}
	if !f.mgr.Healthy() {
		t.Error("Healthy() = false после воскрешения узла")
	}
	sw := f.switches()
	last := sw[len(sw)-1]
	if last.From != "" || last.To != "A" {
		t.Errorf("событие %q → %q, ожидалось «» → A", last.From, last.To)
	}
}

// --- 5.4 Переключение и его причина (У6) -------------------------------

// T7: смерть активного узла даёт событие с reason=dead.
func TestT7DeadSwitchCarriesReasonDead(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	f.prober.setFailing("A", true)
	f.advanceRound(DefaultActiveInterval)
	f.advanceRound(DefaultActiveInterval)

	sw := f.switches()
	last := sw[len(sw)-1]
	if last.Reason != ReasonDead || last.From != "A" || last.To != "B" {
		t.Errorf("событие %q → %q (%v), ожидалось A → B (dead)", last.From, last.To, last.Reason)
	}
}

// T8: найденный более быстрый узел даёт событие с reason=faster.
func TestT8FasterSwitchCarriesReasonFaster(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	f.prober.setRTT("B", 40*ms) // выигрыш 60 мс — больше tolerance
	f.advanceRound(DefaultCandidateInterval)

	sw := f.switches()
	last := sw[len(sw)-1]
	if last.Reason != ReasonFaster || last.From != "A" || last.To != "B" {
		t.Errorf("событие %q → %q (%v), ожидалось A → B (faster)", last.From, last.To, last.Reason)
	}
}

// A18: переключение по смерти рвёт активные соединения (§5.5).
func TestA18DeadSwitchInterruptsConnections(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.perSwitch = 7
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()
	before := f.interruptCalls()

	f.prober.setFailing("A", true)
	f.advanceRound(DefaultActiveInterval)
	f.advanceRound(DefaultActiveInterval)

	if got := f.interruptCalls() - before; got != 1 {
		t.Errorf("разрывов %d, ожидался ровно 1", got)
	}
	sw := f.switches()
	if last := sw[len(sw)-1]; last.Interrupted != 7 {
		t.Errorf("interrupted_connections = %d, ожидалось 7", last.Interrupted)
	}
}

// A19: переключение по скорости соединений не рвёт (§5.5).
// Охраняет switch_reason: без него рвём всегда, как sing-box глобальным флагом.
func TestA19FasterSwitchKeepsConnections(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()
	before := f.interruptCalls()

	f.prober.setRTT("B", 40*ms)
	f.advanceRound(DefaultCandidateInterval)

	sw := f.switches()
	if last := sw[len(sw)-1]; last.Reason != ReasonFaster {
		t.Fatalf("причина последнего переключения %v, ожидалась faster", last.Reason)
	}
	if got := f.interruptCalls() - before; got != 0 {
		t.Errorf("разрывов %d при переключении ради скорости, ожидалось 0", got)
	}
}

// A20: событие несёт весь контракт §2.
func TestA20EventCarriesFullContract(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	first := f.switches()[0]
	if first.From != "" || first.To == "" || first.Reason != ReasonDead {
		t.Errorf("первый выбор: %q → %q (%v), ожидалось «» → узел (dead)", first.From, first.To, first.Reason)
	}
	if first.At.IsZero() {
		t.Error("событие без времени")
	}

	// Улучшаем тот узел, который сейчас не активен, — кто именно им стал на
	// холодном старте, решает порядок ответов (Р4).
	cur := f.active()
	other := map[string]string{"A": "B", "B": "A"}[cur]
	f.prober.setRTT(other, 20*ms)
	f.advanceRound(DefaultCandidateInterval)

	sw := f.switches()
	last := sw[len(sw)-1]
	if last.From != cur || last.To != other {
		t.Errorf("переключение %q → %q, ожидалось %q → %q", last.From, last.To, cur, other)
	}
	if !last.At.Equal(f.clk.Now()) {
		t.Errorf("время события %v, ожидалось %v — время берётся из часов", last.At, f.clk.Now())
	}
	if last.At.Before(first.At) {
		t.Error("события не упорядочены по времени")
	}
}

// A21: при живом кандидате активный узел определён всегда — переключение
// идёт A → B напрямую, без наблюдаемого промежутка с пустым выбором.
func TestA21ActiveIsDefinedBetweenSwitches(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	f.prober.setFailing("A", true)
	f.advanceRound(DefaultActiveInterval)
	f.advanceRound(DefaultActiveInterval)

	if !f.mgr.Healthy() {
		t.Error("Healthy() = false при живом кандидате")
	}
	for _, ev := range f.switches()[1:] {
		if ev.From == "" {
			t.Errorf("переключение с пустого узла при живом кандидате: %+v", ev)
		}
	}
	if f.active() != "B" {
		t.Errorf("активен %q, ожидался B", f.active())
	}
}

// A22: зафиксированный узел не заменяется даже мёртвым (Р6, §1/С3).
func TestA22PinnedNodeIsNotReplacedWhenDead(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	f.pin("B")
	if snap := f.mgr.Snapshot(); snap.Auto || snap.Active != "B" {
		t.Fatalf("после Pin: active=%q auto=%v, ожидалось B и выключенная автоматика", snap.Active, snap.Auto)
	}

	f.prober.setFailing("B", true)
	f.advanceRound(DefaultActiveInterval)
	f.advanceRound(DefaultActiveInterval)

	if f.state("B") != Dead {
		t.Fatalf("состояние B = %v, ожидалось dead", f.state("B"))
	}
	if f.active() != "B" {
		t.Errorf("активен %q, ожидался B: фиксация не отменяется смертью узла", f.active())
	}
	if f.mgr.Healthy() {
		t.Error("Healthy() = true на мёртвом зафиксированном узле — пользователь не увидит fail-close")
	}
	if last := f.switches(); last[len(last)-1].Reason != ReasonManual {
		t.Errorf("последнее событие %v, ожидалось manual: автоматика молчит", last[len(last)-1].Reason)
	}
}

// A23: hop auto on возвращает автоматику.
func TestA23AutoOnReturnsAutomation(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	f.pin("B")
	f.prober.setFailing("B", true)
	f.advanceRound(DefaultActiveInterval)
	f.advanceRound(DefaultActiveInterval)

	f.mgr.Auto(true)

	if snap := f.mgr.Snapshot(); !snap.Auto || snap.Active != "A" {
		t.Errorf("после Auto(true): active=%q auto=%v, ожидалось A и включённая автоматика", snap.Active, snap.Auto)
	}
	if !f.mgr.Healthy() {
		t.Error("Healthy() = false после возврата к автоматике при живом узле")
	}
}

// A24 в этом же разделе: Pin неизвестного узла — ошибка, а не тихий сброс.
func TestPinRejectsUnknownAndUnsupported(t *testing.T) {
	ns := []Node{{ID: "A", Supported: true}, {ID: "X", Supported: false}}
	f := newFixture(t, ns, nil)
	f.prober.setRTT("A", 100*ms)
	f.startAndSettle()

	if err := f.mgr.Pin("нет-такого"); err == nil {
		t.Error("Pin несуществующего узла прошёл")
	}
	if err := f.mgr.Pin("X"); err == nil {
		t.Error("Pin неподдерживаемого узла прошёл")
	}
	if f.active() != "A" {
		t.Errorf("активен %q, ожидался A: неудачный Pin ничего не меняет", f.active())
	}
}

// --- 5.5 Расписание и стоимость (У3, У5) -------------------------------

// T6: событие смены сети запускает пробы немедленно, не дожидаясь тикера.
// Охраняет forced_probe.
func TestT6NetworkChangeProbesImmediately(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	before := f.prober.callCount("B")
	f.mgr.NetworkChanged() // часы не двигаем: тикер тут ни при чём
	f.waitRound(2)

	if after := f.prober.callCount("B"); after <= before {
		t.Errorf("проб узла B %d → %d: событие сети не запустило прогон", before, after)
	}
}

// A24: дребезг событий коалесцируется — 10 событий за секунду не дают 10 обходов.
// Охраняет forced_probe: с выключенной политикой форс-прогонов нет вовсе.
func TestA24ForcedProbesCoalesce(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	before := f.prober.callCount("A")
	for i := 0; i < 10; i++ {
		f.mgr.NetworkChanged()
		f.clk.Advance(100 * ms) // 900 мс суммарно — внутри окна коалесцирования
	}
	f.clk.Advance(200 * ms) // окно вышло: отложенный прогон вправе случиться

	f.waitFor("форс-прогон не случился ни разу", func() bool {
		return f.prober.callCount("A") > before
	})
	if got := f.prober.callCount("A") - before; got > 2 {
		t.Errorf("форс-прогонов %d за 10 событий, ожидалось ≤ 2", got)
	}
}

// A25: стоимость измерения ограничена (У5). Считается по расписанию, а не
// прогоном модельного часа: расписание детерминировано, а гонка цикла с
// часами — нет. Порог тот же, что у B2 на настоящей сети.
// Охраняет probe_tiers.
func TestA25ProbeCostStaysBounded(t *testing.T) {
	const total = 200
	ids := make([]string, 0, total)
	for i := 0; i < total; i++ {
		ids = append(ids, nodeID(i))
	}
	f := newFixture(t, nodes(ids...), nil)
	for i, id := range ids {
		f.prober.setRTT(id, time.Duration(100+i)*ms)
	}
	f.startAndSettle()

	probesPerHour := 0.0
	f.mgr.mu.Lock()
	for _, id := range f.mgr.order {
		probesPerHour += float64(time.Hour) / float64(f.mgr.intervalLocked(f.mgr.nodes[id]))
	}
	f.mgr.mu.Unlock()

	if probesPerHour > 1000 {
		t.Errorf("%0.f проб в час на %d узлов, порог 1000: расписание деградировало до полного обхода",
			probesPerHour, total)
	}
}

// A26: хвост разнесён джиттером, а не выпущен одним залпом (§6.5).
// Охраняет probe_tiers.
func TestA26TailProbesAreSpread(t *testing.T) {
	const total = 200
	ids := make([]string, 0, total)
	for i := 0; i < total; i++ {
		ids = append(ids, nodeID(i))
	}
	f := newFixture(t, nodes(ids...), nil)
	for i, id := range ids {
		f.prober.setRTT(id, time.Duration(100+i)*ms)
	}
	f.startAndSettle()

	seen := map[time.Time]int{}
	f.mgr.mu.Lock()
	for _, id := range f.mgr.order {
		seen[f.mgr.nodes[id].nextProbe]++
	}
	f.mgr.mu.Unlock()

	if len(seen) < total/2 {
		t.Errorf("различных сроков %d на %d узлов: подписка опрашивается залпом", len(seen), total)
	}
}

// A27: зависшая проба не повторяется и не копит горутины; по таймауту она
// становится обычной неудачей окна.
func TestA27HungProbeIsNotRepeated(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.prober.setHung("A", true)

	f.mgr.Start()
	f.prober.waitEntered(t, "A")

	// Проба зарегистрировала ожидание таймаута до входа в Probe, поэтому
	// двигать часы теперь безопасно.
	f.clk.Advance(DefaultProbeTimeout)
	f.waitRound(1)

	h, _ := f.mgr.Snapshot().Node("A")
	if len(h.Window) == 0 || h.Window[len(h.Window)-1] != Timeout {
		t.Errorf("окно A = %v, ожидался таймаут последним", h.Window)
	}
	if got := f.prober.maxParallel("A"); got != 1 {
		t.Errorf("одновременных проб узла A = %d, ожидалась 1", got)
	}

	before := f.prober.callCount("A")
	f.prober.setHung("A", false)
	f.advanceRound(2 * DefaultTailInterval)
	if f.prober.callCount("A") <= before {
		t.Error("после таймаута узел перестал опрашиваться")
	}
	if got := f.prober.maxParallel("A"); got != 1 {
		t.Errorf("одновременных проб узла A = %d, ожидалась 1", got)
	}
}

// A28: смерть активного узла в простое укладывается в бюджет 45 с (§4 верификации).
func TestA28IdleDeathFitsBudget(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	f.prober.setFailing("A", true)
	f.advanceRound(DefaultActiveInterval)
	f.advanceRound(DefaultActiveInterval)

	sw := f.switches()
	last := sw[len(sw)-1]
	if last.To != "B" {
		t.Fatalf("переключение на %q, ожидалось B", last.To)
	}
	if budget := 45 * time.Second; last.At.Sub(f.start) > budget {
		t.Errorf("смерть в простое обнаружена за %v, бюджет %v", last.At.Sub(f.start), budget)
	}
}

// A29: смерть активного узла под трафиком укладывается в бюджет 5 с.
// Охраняет traffic_kills: без него переключения ждать до следующей пробы.
func TestA29SwitchUnderTrafficIsFast(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	f.clk.Advance(1 * time.Second) // соединение прожило секунду и упало
	f.mgr.ReportFailure("A", DialTimeout)
	f.mgr.ReportFailure("A", ProxyRefused)

	f.waitFor("переключения под трафиком не случилось", func() bool {
		return f.active() == "B"
	})
	sw := f.switches()
	last := sw[len(sw)-1]
	if budget := 5 * time.Second; last.At.Sub(f.start) > budget {
		t.Errorf("смерть под трафиком обнаружена за %v, бюджет %v", last.At.Sub(f.start), budget)
	}
}

// --- 5.6 Мульти-URL (У1) -----------------------------------------------

// T5: один тестовый URL заблокирован, второй отвечает — узлы живы.
// Охраняет multi_url: с единственным URL умрёт вся подписка разом.
func TestT5OneBlockedURLDoesNotKillNodes(t *testing.T) {
	blocked := &testTarget{name: "blocked", err: errors.New("403")}
	good := &testTarget{name: "good", rtt: 80 * ms}
	f := newFixture(t, nodes("A", "B"), func(c *Config) {
		c.Prober = &MultiProber{Targets: []Target{blocked, good}}
	})
	f.startAndSettle()

	for _, id := range []string{"A", "B"} {
		if got := f.state(id); got != Alive {
			t.Errorf("состояние %s = %v, ожидалось alive: второй URL отвечает", id, got)
		}
	}
	if f.active() == "" {
		t.Error("выбор пуст при живых узлах")
	}
}

// A30: все URL заблокированы — узел мёртв. Без этой проверки T5 не охраняет
// свою политику: она зелена и в реализации, где вердикт всегда «успех».
func TestA30AllURLsBlockedKillsNode(t *testing.T) {
	one := &testTarget{name: "one", err: errors.New("403")}
	two := &testTarget{name: "two", err: errors.New("403")}
	f := newFixture(t, nodes("A", "B"), func(c *Config) {
		c.Prober = &MultiProber{Targets: []Target{one, two}}
	})
	f.startAndSettle()
	f.advanceRound(DefaultCandidateInterval)

	if got := f.state("A"); got != Dead {
		t.Errorf("состояние A = %v, ожидалось dead: ни один URL не ответил", got)
	}
	if f.mgr.Healthy() {
		t.Error("Healthy() = true при всех заблокированных URL")
	}
}

// A31: rtt пробы — латентность самого быстрого URL (Р3).
// Охраняет multi_url: с одним URL это будет латентность медленного.
func TestA31RTTIsTheFastestURL(t *testing.T) {
	slow := &testTarget{name: "slow", block: true} // отвечает только по отмене
	fast := &testTarget{name: "fast", rtt: 80 * ms}
	p := &MultiProber{Targets: []Target{slow, fast}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := probeWithWatchdog(t, p, ctx, "A")

	if res.Err != nil {
		t.Fatalf("проба не прошла: %v", res.Err)
	}
	if res.RTT != 80*ms {
		t.Errorf("rtt = %v, ожидалось 80ms — латентность быстрейшего URL", res.RTT)
	}
}

// A32: висящий URL не растягивает раунд — вердикт ставится по ответившему.
// Охраняет multi_url.
func TestA32HangingURLDoesNotStretchRound(t *testing.T) {
	hanging := &testTarget{name: "hanging", block: true}
	good := &testTarget{name: "good", rtt: 80 * ms}
	p := &MultiProber{Targets: []Target{hanging, good}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := probeWithWatchdog(t, p, ctx, "A")

	// Что раунд не растянулся, доказывает сам возврат: висящий URL отпускает
	// только отмена контекста, а её делает уже `defer cancel()` внутри Probe.
	// Дождись Probe этого URL — probeWithWatchdog свалил бы тест по сторожевому
	// таймеру. Утверждать что-либо о состоянии таргета ПОСЛЕ возврата нельзя:
	// он в этот момент как раз разблокируется отменой, и проверка состязалась
	// бы с его горутиной.
	if res.Err != nil {
		t.Fatalf("проба не прошла: %v", res.Err)
	}
	if res.RTT != 80*ms {
		t.Errorf("rtt = %v, ожидалось 80ms от ответившего URL", res.RTT)
	}
}

// --- 5.7 Пробы идут тем же путём, что и трафик (§6.7) ------------------

// A33: пробер получает id узла — на L1 это всё, что можно проверить;
// «тот же путь» окончательно доказывает A34 на инжекторе (L2, этап 4).
func TestA33ProberIsCalledWithNodeID(t *testing.T) {
	f := newFixture(t, nodes("A", "B", "C"), nil)
	for _, id := range []string{"A", "B", "C"} {
		f.prober.setRTT(id, 100*ms)
	}
	f.startAndSettle()

	for _, id := range []string{"A", "B", "C"} {
		if n := f.prober.callCount(id); n < 1 {
			t.Errorf("узел %s не пробовался ни разу", id)
		}
	}
	f.prober.mu.Lock()
	defer f.prober.mu.Unlock()
	for id := range f.prober.calls {
		if id != "A" && id != "B" && id != "C" {
			t.Errorf("проба ушла к неизвестному узлу %q", id)
		}
	}
}

// A36: отказ пробера до истечения таймаута — это Fail, а не Timeout.
// probe() отменяет контекст на выходе безусловно (уборка ресурсов), поэтому
// ctx.Err() != nil верно и для настоящего таймаута, и для пробы, вернувшейся
// сама. Классификация обязана различать эти случаи, а не читать общий признак
// отмены (§5.9: `hop status` показывает LastError как есть).
func TestA36ProbeDistinguishesFailFromTimeout(t *testing.T) {
	f := newFixture(t, nodes("A", "B"), nil)
	f.prober.setRTT("A", 100*ms)
	f.prober.setRTT("B", 200*ms)
	f.startAndSettle()

	f.prober.setFailing("A", true)
	f.advanceRound(DefaultActiveInterval)

	h, _ := f.mgr.Snapshot().Node("A")
	if len(h.Window) == 0 || h.Window[len(h.Window)-1] != Fail {
		t.Errorf("окно A = %v, ожидался Fail последним (узел ответил отказом до таймаута)", h.Window)
	}
	if h.LastError != errProbe.Error() {
		t.Errorf("LastError = %q, ожидалась причина отказа пробера %q", h.LastError, errProbe.Error())
	}
}

// --- вспомогательное ---------------------------------------------------

// testTarget — тестовый URL для MultiProber.
type testTarget struct {
	name  string
	rtt   time.Duration
	err   error
	block bool // отвечает только по отмене контекста

	mu    sync.Mutex
	entry bool // защёлка: заблокировался хотя бы раз
}

func (t *testTarget) Name() string { return t.name }

func (t *testTarget) Check(ctx context.Context, nodeID string) (time.Duration, error) {
	if t.block {
		t.mu.Lock()
		t.entry = true
		t.mu.Unlock()
		<-ctx.Done()
		return 0, ctx.Err()
	}
	return t.rtt, t.err
}

// everBlocked — защёлка, а не текущее состояние. Флаг «заблокирован сейчас»
// пришлось бы читать после возврата из Probe, то есть ровно в тот момент,
// когда отмена контекста этот таргет разблокирует: утверждение состязалось бы
// с его горутиной и краснело бы через раз под -race.
func (t *testTarget) everBlocked() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.entry
}

// probeWithWatchdog не даёт красной проверке висеть до таймаута go test.
func probeWithWatchdog(t *testing.T, p Prober, ctx context.Context, nodeID string) Result {
	t.Helper()
	type done struct{ res Result }
	ch := make(chan done, 1)
	go func() { ch <- done{p.Probe(ctx, nodeID)} }()
	select {
	case d := <-ch:
		return d.res
	case <-time.After(watchdog): //hop:realtime
		t.Fatal("проба не вернулась: висящий URL растянул раунд")
		return Result{}
	}
}

// nodeID — устойчивое имя узла подписки для тестов на 200 узлов.
func nodeID(i int) string {
	const digits = "0123456789"
	return "node-" + string([]byte{digits[i/100%10], digits[i/10%10], digits[i%10]})
}
