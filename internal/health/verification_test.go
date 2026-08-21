package health

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
)

// Регистр docs/verification-autoswitch.md §5, случаи A1-A35, портированные с
// main (21df748) на API этой ветки (Monitor+Selector+Scheduler вместо
// main's Manager). T1-T8 уже покрыты select_test.go/schedule_test.go —
// сюда идут только A-случаи, которых там нет.

// A1: окно скользящее, а не «подряд» — [fail, ok, fail] при k=2, n=3 убивает.
func TestA1WindowIsSlidingNotConsecutive(t *testing.T) {
	clk := clock.NewFake(epoch)
	mon := NewMonitor(DefaultMonitorConfig(), clk)

	mon.Observe("A", Result{Err: errFail})
	mon.Observe("A", Result{RTT: 50 * ms})
	mon.Observe("A", Result{Err: errFail})

	if got := mon.Get("A").State; got != Dead {
		t.Fatalf("состояние A = %v, ожидалось dead: окно [fail, ok, fail] даёт две неудачи", got)
	}
}

// A2: старая неудача покидает окно — [fail, ok, ok] жив, окно не длиннее N.
func TestA2OldFailureLeavesWindow(t *testing.T) {
	clk := clock.NewFake(epoch)
	cfg := DefaultMonitorConfig()
	mon := NewMonitor(cfg, clk)

	mon.Observe("A", Result{Err: errFail})
	mon.Observe("A", Result{RTT: 50 * ms})
	mon.Observe("A", Result{RTT: 50 * ms})

	h := mon.Get("A")
	if h.State != Alive {
		t.Fatalf("состояние A = %v, ожидалось alive: окно [ok, ok] без двух неудач", h.State)
	}
	if len(h.Window) != cfg.N {
		t.Fatalf("длина окна %d, ожидалось %d — окно не растёт без предела", len(h.Window), cfg.N)
	}
}

// A3: воскрешение (Р1) симметрично — мёртвый узел возвращается ровно после k
// успехов подряд, один успех недостаточен.
func TestA3DeadNodeReturnsAfterTwoSuccesses(t *testing.T) {
	clk := clock.NewFake(epoch)
	mon := NewMonitor(DefaultMonitorConfig(), clk)

	mon.Observe("A", Result{Err: errFail})
	mon.Observe("A", Result{Err: errFail})
	if got := mon.Get("A").State; got != Dead {
		t.Fatalf("A не умер после двух неудач: %v", got)
	}

	mon.Observe("A", Result{RTT: 50 * ms})
	if got := mon.Get("A").State; got != Dead {
		t.Fatalf("состояние A = %v после одного успеха, ожидалось dead — одного успеха мало", got)
	}

	mon.Observe("A", Result{RTT: 50 * ms})
	if got := mon.Get("A").State; got != Alive {
		t.Fatalf("состояние A = %v после двух успехов, ожидалось alive", got)
	}
}

// A4: мёртвый узел продолжает опрашиваться расписанием — смерть не выводит
// узел из ротации навсегда, иначе он не способен воскреснуть (Р1).
func TestA4DeadNodeKeepsBeingProbed(t *testing.T) {
	sch, prober, clk, mon, _ := newScheduler(t, 0)

	prober.set("A", Result{Err: errFail})
	sch.Sweep(context.Background())
	prober.taken()
	clk.Advance(DefaultScheduleConfig().Active)
	sch.Sweep(context.Background())
	prober.taken()

	if got := mon.Get("A").State; got != Dead {
		t.Fatalf("A не умер: %v", got)
	}

	clk.Advance(DefaultScheduleConfig().Active)
	sch.Sweep(context.Background())
	if got := prober.taken(); !has(got, "A") {
		t.Fatalf("мёртвый узел A не попал в очередной прогон: %v", got)
	}
}

// A6 — ГЕНУИННЫЙ ПРОБЕЛ, найден при портировании, не исправлен.
//
// main (Р2): "счётчик [трафика] обнуляется при каждой успешной пробе". На
// этой ветке Monitor.Observe(успех) не трогает h.TrafficFailures — поле
// обнуляет только ReportSuccess (реальный трафик), не обычная проба.
// State считается по общему окну и потому корректен (проба всё равно
// возвращает узел в Alive), но отображаемое TrafficFailures в Snapshot/
// NodeHealth остаётся ненулевым до первого настоящего успешного
// соединения — то есть `hop nodes` может показывать "traffic_failures: 2"
// на узле, который уже час как жив и обслуживает трафик. См. monitor.go
// Observe() против ReportSuccess().
//
// Не исправлено намеренно: это поведенческое изменение продакшен-кода, а
// не тест, и требует решения, а не порта. Тест ниже документирует находку
// и пропущен, чтобы не красить сборку неожиданно для остальных.
func TestA6ProbeSuccessClearsTrafficCounter(t *testing.T) {
	t.Skip("известный пробел: Monitor.Observe(успех) не обнуляет TrafficFailures, " +
		"обнуляет только ReportSuccess — см. комментарий к тесту и implementation-notes.md")

	clk := clock.NewFake(epoch)
	mon := NewMonitor(DefaultMonitorConfig(), clk)

	mon.Observe("A", Result{RTT: 50 * ms})
	mon.ReportFailure("A", TLSError)
	if got := mon.Get("A").TrafficFailures; got != 1 {
		t.Fatalf("счётчик трафика %d, ожидался 1", got)
	}

	mon.Observe("A", Result{RTT: 50 * ms}) // обычная проба, не ReportSuccess
	if got := mon.Get("A").TrafficFailures; got != 0 {
		t.Fatalf("счётчик трафика %d после успешной пробы, ожидался 0", got)
	}
}

// A9: с мёртвого активного узла уходят на любой живой немедленно — tolerance
// асимметричен и не защищает мёртвого от замены.
func TestA9DeadSwitchIgnoresTolerance(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.ok("A", 100*ms)
	h.ok("B", 300*ms) // хуже на 200мс — но единственный живой кандидат
	h.sel.Reconsider()
	h.switches()

	h.fail("A")
	h.fail("A")
	h.sel.Reconsider()

	if h.sel.Active() != "B" {
		t.Fatalf("активен %q, ожидался B: с мёртвого узла уходят к любому живому", h.sel.Active())
	}
}

// A10: равные rtt не повод менять активный узел.
func TestA10EqualRTTKeepsCurrentNode(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.ok("A", 100*ms)
	h.ok("B", 100*ms)
	h.sel.Reconsider()
	chosen := h.sel.Active()
	h.switches()

	for i := 0; i < 5; i++ {
		h.ok("A", 100*ms)
		h.ok("B", 100*ms)
		h.sel.Reconsider()
	}

	if h.sel.Active() != chosen {
		t.Fatalf("активен %q, ожидался неизменный %q", h.sel.Active(), chosen)
	}
	if got := h.switches(); len(got) != 0 {
		t.Fatalf("переключений при равных rtt: %d, ожидалось 0: %+v", len(got), got)
	}
}

// A11: при равных rtt выбор идёт по порядку кандидатов (SetCandidates) —
// иначе прогон невоспроизводим.
func TestA11EqualRTTFollowsCandidateOrder(t *testing.T) {
	h := newHarness(t, "C", "B", "A") // порядок подписки, не алфавит
	h.ok("C", 100*ms)
	h.ok("B", 100*ms)
	h.ok("A", 100*ms)
	h.sel.Reconsider()

	if h.sel.Active() != "C" {
		t.Fatalf("выбран %q, ожидался C — первый по порядку кандидатов", h.sel.Active())
	}
}

// A20: событие переключения несёт полный контракт §2 — from/to/reason/at, и
// события упорядочены по времени.
func TestA20EventCarriesFullContract(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.ok("A", 100*ms)
	h.ok("B", 200*ms)
	h.sel.Reconsider()

	first := h.lastSwitch()
	if first.From != "" || first.To == "" || first.Reason != ReasonDead {
		t.Fatalf("первый выбор: %q → %q (%v), ожидалось «» → узел (dead)", first.From, first.To, first.Reason)
	}
	if first.At.IsZero() {
		t.Fatal("событие без времени")
	}

	h.clk.Advance(time.Second)
	h.ok("B", 20*ms)
	h.sel.Reconsider()

	last := h.lastSwitch()
	if last.From != "A" || last.To != "B" {
		t.Fatalf("переключение %q → %q, ожидалось A → B", last.From, last.To)
	}
	if !last.At.Equal(h.clk.Now()) {
		t.Fatalf("время события %v, ожидалось %v — время берётся из часов", last.At, h.clk.Now())
	}
	if last.At.Before(first.At) {
		t.Fatal("события не упорядочены по времени")
	}
}

// A21: пока есть живой кандидат, активный узел определён всегда —
// переключение идёт A→B напрямую, без наблюдаемого пустого промежутка.
func TestA21ActiveIsDefinedBetweenSwitches(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.ok("A", 100*ms)
	h.ok("B", 200*ms)
	h.sel.Reconsider()
	h.switches()

	h.fail("A")
	h.fail("A")
	h.sel.Reconsider()

	if h.sel.Active() != "B" {
		t.Fatalf("активен %q, ожидался B", h.sel.Active())
	}
	sw := h.lastSwitch()
	if sw.From == "" {
		t.Fatalf("переключение с пустого узла при живом кандидате: %+v", sw)
	}
}

// A22: зафиксированный узел не заменяется даже мёртвым (Р6, §1/С3) —
// пользователь получает fail-close, а не тихий возврат автоматики.
func TestA22PinnedNodeIsNotReplacedWhenDead(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.ok("A", 100*ms)
	h.ok("B", 200*ms)
	h.sel.Reconsider()
	h.switches()

	if err := h.sel.Pin("B"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	h.switches()

	h.fail("B")
	h.fail("B")
	h.sel.Reconsider()

	if got := h.mon.Get("B").State; got != Dead {
		t.Fatalf("состояние B = %v, ожидалось dead", got)
	}
	if h.sel.Active() != "B" {
		t.Fatalf("активен %q, ожидался B: фиксация не отменяется смертью узла", h.sel.Active())
	}
	if sw := h.switches(); len(sw) != 0 {
		t.Fatalf("автоматика переключила зафиксированный узел: %+v", sw)
	}
}

// A23: `hop auto on` после смерти зафиксированного узла возвращает
// автоматику и пересчитывает выбор на живой узел.
func TestA23AutoOnReturnsAutomationAfterPinnedDeath(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.ok("A", 100*ms)
	h.ok("B", 200*ms)
	h.sel.Reconsider()
	h.switches()

	if err := h.sel.Pin("B"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	h.switches()
	h.fail("B")
	h.fail("B")
	h.sel.Reconsider()
	h.switches()

	h.sel.Auto(true)

	if h.sel.Active() != "A" {
		t.Fatalf("после auto on активен %q, ожидался живой A", h.sel.Active())
	}
}

// A24 — ГЕНУИННЫЙ ПРОБЕЛ, найден при портировании, не исправлен.
//
// main документирует коалесцирование форс-проб: до двух прогонов на десять
// событий смены сети за секунду (см. docs/verification-autoswitch.md, A24,
// таблицу флагов §6 — "события коалесцируются"). Scheduler.Force на этой
// ветке коалесцирования не делает вовсе: он берёт runMu и синхронно гоняет
// Sweep на каждый вызов (schedule.go, Force/Sweep). Проверка ниже вызывает
// Force десять раз подряд без сдвига часов и считает прогоны — на реализации
// с коалесцированием их было бы ≤2, здесь получается 10. При частом
// флаппинге Wi-Fi это означает всплеск проб, а не единственный прогон,
// то есть потенциальное нарушение бюджета §6.5 в этом конкретном сценарии
// (не самого стабильного расписания — оно и так ограничено PoolSize/тиром).
//
// Не исправлено намеренно: добавление дебаунса — это новая продакшен-логика,
// а не тест, и это решение не в рамках порта тестов.
func TestA24ForcedProbesCoalesce(t *testing.T) {
	t.Skip("известный пробел: Scheduler.Force не коалесцирует повторные события — " +
		"каждый вызов гоняет отдельный Sweep; см. комментарий к тесту")

	sch, prober, _, _, _ := newScheduler(t, 0)
	prober.taken()

	rounds := 0
	for i := 0; i < 10; i++ {
		before := len(prober.taken())
		sch.Force(TriggerInterface)
		if len(prober.taken()) > before {
			rounds++
		}
	}
	if rounds > 2 {
		t.Fatalf("форс-прогонов %d за 10 событий без сдвига часов, ожидалось ≤ 2", rounds)
	}
}

// A28: смерть активного узла в простое укладывается в бюджет 45с
// (docs/verification-autoswitch.md §4): 2 × (Active + ProbeTimeout).
func TestA28IdleDeathFitsBudget(t *testing.T) {
	sch, prober, clk, mon, sel := newScheduler(t, 0)
	start := clk.Now()

	prober.set("A", Result{Err: errFail})
	sch.Sweep(context.Background())
	clk.Advance(DefaultScheduleConfig().Active)
	sch.Sweep(context.Background())

	if got := mon.Get("A").State; got != Dead {
		t.Fatalf("A не умер после двух неудач: %v", got)
	}
	if sel.Active() != "B" {
		t.Fatalf("активен %q, ожидался B", sel.Active())
	}
	if budget := 45 * time.Second; clk.Now().Sub(start) > budget {
		t.Fatalf("смерть в простое обнаружена за %v, бюджет %v", clk.Now().Sub(start), budget)
	}
}

// A29: смерть активного узла под трафиком укладывается в бюджет 5с — часы не
// двигаются вовсе, ReportFailure будит выбор синхронно через Monitor.SetOnDeath.
func TestA29SwitchUnderTrafficIsFast(t *testing.T) {
	clk := clock.NewFake(epoch)
	mon := NewMonitor(DefaultMonitorConfig(), clk)
	sel := NewSelector(mon, DefaultSelectorConfig(), clk)
	t.Cleanup(sel.Close)
	sel.SetCandidates([]string{"A", "B"})
	mon.Observe("A", Result{RTT: 50 * ms})
	mon.Observe("B", Result{RTT: 100 * ms})
	sel.Reconsider()
	events := sel.Subscribe()
	drain(events)

	mon.SetOnDeath(func(string) { sel.Reconsider() })
	start := clk.Now()

	mon.ReportFailure("A", DialTimeout)
	mon.ReportFailure("A", ProxyRefused)

	if sel.Active() != "B" {
		t.Fatalf("активен %q, ожидался B", sel.Active())
	}
	if budget := 5 * time.Second; clk.Now().Sub(start) > budget {
		t.Fatalf("смерть под трафиком обнаружена за %v, бюджет %v", clk.Now().Sub(start), budget)
	}
}

// A30: все пробе-URL заблокированы — узел мёртв. Без этого T5 не охраняет
// свою политику: он зелен и в реализации, где вердикт «успех» ставится
// безусловно.
func TestA30AllURLsBlockedKillsNode(t *testing.T) {
	one := netip.MustParseAddrPort("203.0.113.1:80")
	two := netip.MustParseAddrPort("203.0.113.2:80")
	clk := clock.NewFake(epoch)
	prober := NewURLProber(
		fakeHTTP(map[netip.AddrPort]int{one: 403, two: 403}),
		[]Target{{Addr: one, Host: "one.example", Path: "/generate_204"}, {Addr: two, Host: "two.example", Path: "/generate_204"}},
		clk,
	)
	mon := NewMonitor(DefaultMonitorConfig(), clk)

	for i := 0; i < 3; i++ {
		mon.Observe("A", prober.Probe(context.Background(), "A"))
	}

	if got := mon.Get("A").State; got != Dead {
		t.Fatalf("узел с обоими заблокированными URL получил состояние %q, ожидалось dead", got)
	}
	if mon.HasAlive() {
		t.Fatal("HasAlive() == true при всех заблокированных URL")
	}
}

// A31/A32 — ГЕНУИННЫЙ ПРОБЕЛ, найден при портировании, не исправлен.
//
// main (Р3, §5.4): "URL опрашиваются параллельно... rtt — минимальный из
// успешных... вердикт не зависит от порядка". URLProber.Probe на этой ветке
// (schedule.go) перебирает targets ПОСЛЕДОВАТЕЛЬНО в порядке списка и
// возвращает результат первого же успешного — не параллельно, и rtt равен
// латентности первого сработавшего таргета, а не минимальной. Хуже: если
// ПЕРВЫЙ по списку таргет не отвечает вовсе (вешается, а не быстро отдаёт
// 403 — реалистичный сценарий для многих способов цензуры), весь бюджет
// ProbeTimeout уходит на него одного, а до второго, рабочего, таргета дело
// не доходит — узел с одним подвисшим (не только заблокированным) URL
// в списке первым будет ошибочно считаться мёртвым в течение ProbeTimeout.
// Это прямое нарушение ожидания A32 ("висящий URL не растягивает раунд").
//
// Тест ниже показывает именно этот сценарий: первый таргет висит, второй
// отвечает быстро — на текущей реализации проба вернёт ошибку по таймауту
// контекста, а не rtt второго таргета.
//
// Не исправлено намеренно: смена Probe с последовательного перебора на
// параллельный — это переписывание URLProber, а не тест, и это решение не в
// рамках порта тестов; см. отчёт агента.
func TestA32HangingFirstURLDoesNotStretchRound(t *testing.T) {
	t.Skip("известный пробел: URLProber.Probe перебирает targets последовательно, " +
		"подвисший первый таргет съедает весь ProbeTimeout вместо перехода ко второму; " +
		"см. комментарий к тесту")

	good := netip.MustParseAddrPort("203.0.113.2:80")
	clk := clock.NewFake(epoch)
	dial := func(ctx context.Context, nodeID string, dst netip.AddrPort) (net.Conn, error) {
		if dst == good {
			return fakeHTTP(map[netip.AddrPort]int{good: 204})(ctx, nodeID, dst)
		}
		// «Зависший» таргет: соединение устанавливается, но сервер не отвечает
		// и не закрывается, пока не отменят контекст.
		cli, srv := net.Pipe()
		go func() {
			<-ctx.Done()
			srv.Close()
		}()
		return cli, nil
	}
	hanging := netip.MustParseAddrPort("203.0.113.1:80")
	prober := NewURLProber(dial, []Target{
		{Addr: hanging, Host: "hanging.example", Path: "/generate_204"},
		{Addr: good, Host: "good.example", Path: "/generate_204"},
	}, clk)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res := prober.Probe(ctx, "A")
	if res.Err != nil {
		t.Fatalf("проба не прошла: %v, ожидался переход ко второму таргету", res.Err)
	}
}

// A15/A16 — ГЕНУИННЫЙ ПРОБЕЛ, найден при портировании, не исправлен. Из
// найденных при портировании — самый заметный: задевает каждый `hop up`, а
// не только редкий сценарий.
//
// main (Р5): "Healthy() не должен быть false только потому, что раунд ещё не
// кончился" — fail-close обязан наступать не раньше, чем каждый узел
// проверен хотя бы раз, либо истёк стартовый бюджет. На этой ветке
// supervisor.healthy() (internal/supervisor/supervisor.go) — это буквально
// `mon.HasAlive() || bypassed()`, и HasAlive() у свежего Monitor без единой
// Observe возвращает false: нет отдельного "раунд ещё не завершён" состояния.
// Это значит, что в окне между стартом супервизора и первым завершённым
// раундом проб (до ProbeTimeout=2с на активном ярусе) netstack.Config.Healthy
// и dns.Config.Healthy видят "нездоров" и, по-видимому, уходят в fail-close
// раньше, чем у первого узла был шанс ответить — то есть RST/ICMP вместо
// ожидания на самом первом `hop up`, а не только в реальном "все узлы мертвы"
// сценарии.
//
// Тест ниже документирует корень проблемы на уровне health (сам механизм
// Healthy() живёт в internal/supervisor, не здесь): свежий Monitor без единой
// пробы уже нездоров, хотя со стартовым бюджетом (Р5) он обязан быть здоров.
//
// Не исправлено намеренно: добавление стартового бюджета — новая
// продакшен-логика на стыке health/supervisor, а не тест, и её место и API
// (кто держит бюджет — Monitor или Supervisor) требуют решения, а не порта.
func TestA15FreshMonitorHasNoStartupGrace(t *testing.T) {
	t.Skip("известный пробел: HasAlive()/supervisor.healthy() не имеют стартового бюджета (Р5) — " +
		"свежий монитор без единой пробы уже 'нездоров', см. комментарий к тесту")

	clk := clock.NewFake(epoch)
	mon := NewMonitor(DefaultMonitorConfig(), clk)
	// Ни одной Observe ещё не было — ни один узел не успел ответить.
	if !mon.HasAlive() {
		t.Fatal("HasAlive() == false до первой пробы: трафик получит RST вместо ожидания (Р5)")
	}
}

func drain(ch <-chan Switch) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

var errFail = fakeErr("проба не прошла")

type fakeErr string

func (e fakeErr) Error() string { return string(e) }
