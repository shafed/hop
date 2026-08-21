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

// A6 (Р2) — успешная проба обнуляет счётчик ошибок трафика.
//
// §5.4 считает пробу и трафик одним свидетельством о живости, поэтому
// обнулять счётчик обязана не только ReportSuccess. Иначе `hop nodes`
// показывает "traffic_failures: 2" на узле, который час как жив: состояние
// при этом верное (оно считается по общему окну), врёт только показанное.
func TestA6ProbeSuccessClearsTrafficCounter(t *testing.T) {
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

// A24 — склейка форс-событий (§6.6).
//
// Одна смена сети приезжает залпом: интерфейс, маршрут и адрес порознь за доли
// секунды. Без склейки каждое событие давало бы свой прогон горячего яруса, и
// флаппинг Wi-Fi выливался бы во всплеск проб мимо бюджета §6.5.
//
// Склеиваются прогоны, а не намерение: срок узлам проставлен в любом случае,
// подавленное событие уйдёт в ближайший прогон. Первое событие проходит всегда
// — §6.6 требует прогона без единого тика (T6).
func TestA24ForcedProbesCoalesce(t *testing.T) {
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

// A32 — молчащий таргет не растягивает раунд (Р3, §5.4).
//
// Первый таргет висит: соединение принято, ответа нет, закрытия нет — так
// выглядит цензура, роняющая пакеты, а не отдающая отказ. Строгая очередь
// съедала бы на нём весь ProbeTimeout, и узел с одним рабочим URL в списке
// вторым числился бы мёртвым. Подстраховка обязана пустить второй таргет и
// вернуть его латентность.
//
// Часы крутит тест: проба синхронна, и ждать подстраховки на неподвижных
// фейковых часах означало бы ждать себя.
func TestA32HangingFirstURLDoesNotStretchRound(t *testing.T) {
	good := netip.MustParseAddrPort("203.0.113.2:80")
	hanging := netip.MustParseAddrPort("203.0.113.1:80")

	clk := clock.NewFake(epoch)
	dialed := make(chan netip.AddrPort, 2)
	dial := func(ctx context.Context, nodeID string, dst netip.AddrPort) (net.Conn, error) {
		dialed <- dst
		if dst == good {
			return fakeHTTP(map[netip.AddrPort]int{good: 204})(ctx, nodeID, dst)
		}
		cli, srv := net.Pipe()
		go func() {
			<-ctx.Done()
			srv.Close()
		}()
		return cli, nil
	}
	prober := NewURLProber(dial, []Target{
		{Addr: hanging, Host: "hanging.example", Path: "/generate_204"},
		{Addr: good, Host: "good.example", Path: "/generate_204"},
	}, clk)

	res := make(chan Result, 1)
	go func() { res <- prober.Probe(context.Background(), "A") }()

	if got := <-dialed; got != hanging {
		t.Fatalf("первым опрошен %v, ожидался первый по списку %v", got, hanging)
	}
	// До подстраховки второго соединения нет: иначе цена пробы удваивалась бы
	// на каждой пробе здоровой подписки (§6.5, B2).
	select {
	case got := <-dialed:
		t.Fatalf("второй таргет %v опрошен до подстраховки", got)
	default:
	}

	clk.Advance(DefaultProbeHedge)

	select {
	case r := <-res:
		if r.Err != nil {
			t.Fatalf("проба не прошла: %v, ожидался переход ко второму таргету", r.Err)
		}
	case <-clock.System{}.After(5 * time.Second):
		t.Fatal("проба не кончилась: подстраховка не пустила второй таргет")
	}
}

// A15/A16 (стартовое окно Р5) проверяются в internal/supervisor:
// TestStartupGrace*. Здесь для них нет места по построению — окно опирается на
// список поддержанных узлов (§6.11), а монитор знает лишь те узлы, о которых
// ему уже сообщили.
//
// HasAlive() при этом остаётся буквальным: «есть ли узел в состоянии alive».
// Смешивать в нём «живых нет» и «ещё никого не спросили» значило бы вернуть
// ту же неоднозначность одним слоем ниже.

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
