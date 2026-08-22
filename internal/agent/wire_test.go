package agent

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/tunnel"
)

// Регистр — docs/verification-agent.md. Нумерация W* оттуда же.

// ── 5.1 Сборка и разборка (У1) ────────────────────────────────────────────

// TestW1NewAndCloseLeakNothing — W1: связка, которую не поднимали, не оставляет
// после себя горутин.
func TestW1NewAndCloseLeakNothing(t *testing.T) {
	before := runtime.NumGoroutine()

	r := newRig(t, "a")
	if err := r.a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitGoroutines(t, before)
}

// TestW2UpThenCloseLeakNothing — W2: то же после полного цикла.
func TestW2UpThenCloseLeakNothing(t *testing.T) {
	before := runtime.NumGoroutine()

	r := newRig(t, "a")
	r.a.Start()
	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := r.a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitGoroutines(t, before)

	if _, rel := r.tr.counts(); rel == 0 {
		t.Fatal("туннель не был снят: Release не вызывался")
	}
}

// TestW3CloseIsIdempotent — W3: второй Close не паникует и не виснет.
func TestW3CloseIsIdempotent(t *testing.T) {
	r := newRig(t, "a")
	r.a.Start()
	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := r.a.Close(); err != nil {
		t.Fatalf("первый Close: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- r.a.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("второй Close: %v", err)
		}
	case <-time.After(5 * time.Second): //hop:realtime
		t.Fatal("второй Close заблокировался")
	}
}

// TestW5SnapshotIsRaceFree — W5: снимок из другой горутины во время Up и Down.
// Смысл под -race: замок агента и замок живости берутся в одном порядке.
func TestW5SnapshotIsRaceFree(t *testing.T) {
	r := newRig(t, "a", "b")
	r.a.Start()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = r.a.Snapshot()
			}
		}
	}()

	for i := 0; i < 20; i++ {
		if err := r.a.Up(); err != nil {
			t.Errorf("Up: %v", err)
			break
		}
		if err := r.a.Down(); err != nil {
			t.Errorf("Down: %v", err)
			break
		}
	}
	close(stop)
	wg.Wait()
}

// ── 5.3 Переключение доходит и в порядке (У3) ─────────────────────────────

// TestW11SwitchReactionsFollowOrder — W11: четыре реакции в порядке Р33.
//
// Охраняет switch_order. С выключенной политикой сброс кэша уезжает за
// рассылку события, и порядок ломается.
func TestW11SwitchReactionsFollowOrder(t *testing.T) {
	// Цикл проб не запускается: проверяются кольцо и журнал реакций, а
	// живая подписка подмешала бы в них собственные переключения.
	r := newRig(t, "a")

	r.a.onSwitch(health.SwitchEvent{To: "a", Reason: health.ReasonDead})

	got := strings.Join(r.a.Reactions(), ",")
	want := "flush,interrupt,event,persist"
	if got != want {
		t.Fatalf("порядок реакций %q, ожидался %q", got, want)
	}
}

// TestW13CacheFlushPrecedesEvent — W13: кэш резолвера сброшен раньше, чем
// событие ушло подписчику.
//
// Проверяется не порядок записей в журнале, а наблюдаемая
// последовательность: подписчик, разбуженный событием, обязан увидеть уже
// сброшенный кэш. Иначе клиент, реагирующий на событие повторным резолвом,
// получит адрес, добытый через мёртвый узел, — §5.7(в) выполнен формально.
func TestW13CacheFlushPrecedesEvent(t *testing.T) {
	// Цикл проб не запускается: проверяются кольцо и журнал реакций, а
	// живая подписка подмешала бы в них собственные переключения.
	r := newRig(t, "a")

	// Порядок наблюдается по состоянию кольца в момент сброса, а не по
	// времени доставки подписчику: подписчик просыпается тогда, когда его
	// разбудит планировщик, и проверка на этом превращается в гонку.
	flushed := false
	ringAtFlush := -1
	r.res.onFlush = func() {
		flushed = true
		ringAtFlush = len(r.a.History())
	}

	r.a.onSwitch(health.SwitchEvent{To: "a", Reason: health.ReasonDead})

	if !flushed {
		t.Fatal("кэш резолвера не сбрасывался вовсе")
	}
	if ringAtFlush != 0 {
		t.Fatalf("на момент сброса кэша в кольце уже %d событий — значит "+
			"событие ушло раньше сброса, и клиент, ответивший на него "+
			"повторным резолвом, получит адрес через мёртвый узел (§5.7в)",
			ringAtFlush)
	}
}

// TestW16LateSubscriberSeesRing — W16: клиент, подписавшийся после
// переключения, получает его из кольца (§2).
func TestW16LateSubscriberSeesRing(t *testing.T) {
	// Цикл проб не запускается: проверяются кольцо и журнал реакций, а
	// живая подписка подмешала бы в них собственные переключения.
	r := newRig(t, "a")

	r.a.onSwitch(health.SwitchEvent{To: "a", Reason: health.ReasonDead})

	hist, ch := r.a.Events(1)
	defer r.a.Unsubscribe(ch)

	if len(hist) != 1 || hist[0].To != "a" {
		t.Fatalf("подписчик получил историю %v, ожидалось одно событие на a", hist)
	}
}

// TestW17RingKeepsLast256 — W17: кольцо держит последние 256 и не растёт.
func TestW17RingKeepsLast256(t *testing.T) {
	r := newRig(t, "a")

	for i := 0; i < 300; i++ {
		r.a.ring.push(health.SwitchEvent{To: "a", Interrupted: i})
	}
	h := r.a.History()
	if len(h) != eventRingSize {
		t.Fatalf("в кольце %d событий, ожидалось %d", len(h), eventRingSize)
	}
	if h[0].Interrupted != 300-eventRingSize {
		t.Fatalf("первое событие в кольце %d, ожидалось %d",
			h[0].Interrupted, 300-eventRingSize)
	}
	if h[len(h)-1].Interrupted != 299 {
		t.Fatalf("последнее событие %d, ожидалось 299", h[len(h)-1].Interrupted)
	}
}

// ── 5.5 Две фазы (У5) ─────────────────────────────────────────────────────

// TestW24TunnelUpWithNoLiveNodes — W24: туннель поднят, живых узлов нет, и
// снаружи видны обе половины правды.
//
// Охраняет phase_split. Одно поле выразить это не может: и «up», и «failing»
// истинны одновременно.
func TestW24TunnelUpWithNoLiveNodes(t *testing.T) {
	r := newRig(t, "a")
	r.prob.set("a", health.Result{Err: errDead})
	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	r.start()

	// Бюджет §5.6 истёк и узел мёртв: fail-close наступил.
	r.killAll("a")
	r.clk.Advance(health.DefaultStartupBudget)

	s := r.a.Snapshot()
	if s.Tunnel != tunnel.Up {
		t.Fatalf("фаза туннеля %q, ожидалась up", s.Tunnel)
	}
	if s.Traffic != PhaseFailing {
		t.Fatalf("фаза трафика %q, ожидалась failing", s.Traffic)
	}
}

// TestW25BypassTakesTunnelDown — W25: обход снимает туннель (Р35).
//
// Охраняет bypass_teardown. С выключенной политикой туннель остаётся поднятым,
// и «выпустить трафик напрямую» (§1/С6) ничего не выпускает.
func TestW25BypassTakesTunnelDown(t *testing.T) {
	r := newRig(t, "a")
	r.a.Start()

	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	_, relBefore := r.tr.counts()

	if err := r.a.Bypass(true); err != nil {
		t.Fatalf("Bypass(true): %v", err)
	}

	s := r.a.Snapshot()
	_, relAfter := r.tr.counts()

	if relAfter != relBefore+1 {
		t.Fatalf("туннель не снят: Release вызывался %d раз, было %d", relAfter, relBefore)
	}
	if s.Tunnel != tunnel.Down {
		t.Fatalf("фаза туннеля %q, ожидалась down", s.Tunnel)
	}
}

// TestW26BypassOffRaisesTunnel — W26: снятие обхода поднимает туннель обратно.
func TestW26BypassOffRaisesTunnel(t *testing.T) {
	r := newRig(t, "a")
	r.a.Start()

	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := r.a.Bypass(true); err != nil {
		t.Fatalf("Bypass(true): %v", err)
	}
	acqBefore, _ := r.tr.counts()

	if err := r.a.Bypass(false); err != nil {
		t.Fatalf("Bypass(false): %v", err)
	}
	acqAfter, _ := r.tr.counts()
	s := r.a.Snapshot()

	if acqAfter != acqBefore+1 {
		t.Fatalf("туннель не поднят заново: Acquire %d, было %d", acqAfter, acqBefore)
	}
	if s.Tunnel != tunnel.Up {
		t.Fatalf("фаза туннеля %q, ожидалась up", s.Tunnel)
	}
}

// TestW27ServiceDeathIsVisible — W27: смерть сервиса переводит агента в
// failing и показывает причину, но не роняет его (Р34).
func TestW27ServiceDeathIsVisible(t *testing.T) {
	r := newRig(t, "a")
	r.a.Start()

	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	r.tr.die()

	deadline := time.Now().Add(5 * time.Second) //hop:realtime
	for time.Now().Before(deadline) {           //hop:realtime
		if s := r.a.Snapshot(); s.Detached != "" {
			if s.Traffic != PhaseFailing {
				t.Fatalf("фаза трафика %q, ожидалась failing", s.Traffic)
			}
			return
		}
		time.Sleep(5 * time.Millisecond) //hop:realtime
	}
	t.Fatal("смерть сервиса не отразилась в снимке")
}

// TestW28BypassDoesNotSurviveRestart — W28: обход не переживает пересоздание
// агента (§5.6, Р22 регистра решений: на диск он не пишется).
func TestW28BypassDoesNotSurviveRestart(t *testing.T) {
	r := newRig(t, "a")
	r.a.Start()

	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := r.a.Bypass(true); err != nil {
		t.Fatalf("Bypass: %v", err)
	}
	if err := r.a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Новый агент на том же сторе.
	again, err := New(Config{
		Store: r.st, Health: health.New(health.Config{Clock: r.clk, Prober: r.prob}),
		Trans: newFakeTransport(), Clock: r.clk, NewXray: r.xrays.factory(),
	})
	if err != nil {
		t.Fatalf("второй агент не собрался: %v", err)
	}
	defer again.Close()

	if s := again.Snapshot(); s.Traffic == PhaseBypass {
		t.Fatal("обход пережил пересоздание агента, хотя на диск не пишется")
	}
}

// ── 5.7 Стартовый бюджет (У7) ─────────────────────────────────────────────

// TestW32StartupBudgetIsWaiting — W32: сразу после Up фаза waiting, и это не
// failing (§5.6).
//
// Охраняет phase_split: в прежнем едином перечислении значения waiting не было
// вовсе, и стартовые тридцать секунд показывались либо как «работает», либо
// как «нет живых узлов» — оба ответа неверны.
func TestW32StartupBudgetIsWaiting(t *testing.T) {
	r := newRig(t, "a")
	r.prob.set("a", health.Result{Err: errDead})

	// Цикл проб намеренно не запускается: утверждение W32 — про состояние «ни
	// один узел ещё не проверен», и запуск сделал бы его гонкой с первым
	// раундом, а не проверкой.
	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	if s := r.a.Snapshot(); s.Traffic != PhaseWaiting {
		t.Fatalf("фаза трафика %q, ожидалась waiting: стартовый бюджет §5.6 — "+
			"незнание, а не отказ", s.Traffic)
	}
}

// TestW34FirstAliveNodeSwitchesToProxied — W34: первый успешно ответивший узел
// переводит трафик в proxied, не дожидаясь конца обхода (§6.4, холодный старт).
func TestW34FirstAliveNodeSwitchesToProxied(t *testing.T) {
	r := newRig(t, "a", "b", "c")
	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	r.start()

	if s := r.a.Snapshot(); s.Traffic != PhaseProxied {
		t.Fatalf("фаза трафика %q, ожидалась proxied (активный %q)", s.Traffic, s.Active)
	}
}

// TestW35BudgetExpiryTurnsIntoFailing — W35: бюджет истёк, никто не ответил —
// теперь это fail-close, а не ожидание.
func TestW35BudgetExpiryTurnsIntoFailing(t *testing.T) {
	r := newRig(t, "a")
	r.prob.set("a", health.Result{Err: errDead})
	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if s := r.a.Snapshot(); s.Traffic != PhaseWaiting {
		t.Fatalf("до первой пробы фаза %q, ожидалась waiting", s.Traffic)
	}

	r.start()
	r.killAll("a")
	r.clk.Advance(health.DefaultStartupBudget)

	if s := r.a.Snapshot(); s.Traffic != PhaseFailing {
		t.Fatalf("после бюджета фаза %q, ожидалась failing", s.Traffic)
	}
}

// ── вспомогательное ───────────────────────────────────────────────────────

type dialErr string

func (e dialErr) Error() string { return string(e) }

const errDead = dialErr("узел мёртв")

// waitGoroutines ждёт, пока число горутин вернётся к исходному. Именно ждёт, а
// не сравнивает сразу: рантайм убирает завершившиеся горутины не мгновенно, и
// мгновенное сравнение дало бы флейк, а не проверку.
func waitGoroutines(t *testing.T, before int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second) //hop:realtime
	var last int
	for time.Now().Before(deadline) { //hop:realtime
		runtime.GC()
		last = runtime.NumGoroutine()
		if last <= before {
			return
		}
		time.Sleep(10 * time.Millisecond) //hop:realtime
	}
	t.Fatalf("горутин было %d, стало %d — что-то не остановилось", before, last)
}

var seqMu sync.Mutex

func atomicNext(n *int64) int64 {
	seqMu.Lock()
	defer seqMu.Unlock()
	*n++
	return *n
}

// TestW33WaitingHoldsTrafficInsteadOfRejecting — W33: в стартовом окне трафик
// придерживается, а не отвергается.
//
// §5.6 называет именно этот отказ: «иначе первое же приложение получает RST в
// те секунды, пока идёт стартовый обход подписки». Различие наблюдаемо
// клиентом: netstack не отвечает на SYN вовсе, и клиент повторяет его сам.
//
// Проверка появилась не сразу: первая редакция регистра отнесла W33 к
// свойствам netstack и не написала её. Шов между «живость говорит healthy» и
// «активного узла ещё нет» лежит ровно в связке, и до этой проверки трафик в
// waiting получал RST.
func TestW33WaitingHoldsTrafficInsteadOfRejecting(t *testing.T) {
	r := newRig(t, "a")
	// Цикл проб не запускается: стартовое окно — это состояние «ещё не
	// проверяли», и запуск его бы закрыл.
	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if s := r.a.Snapshot(); s.Traffic != PhaseWaiting {
		t.Fatalf("фаза %q, ожидалась waiting", s.Traffic)
	}

	d := newDialer(r.hm, r.a.engine)
	_, err := d.DialTCP(netip.MustParseAddrPort("93.184.216.34:443"))
	if err == nil {
		t.Fatal("дозвон удался без активного узла")
	}
	if !errors.Is(err, netstack.ErrNotReady) {
		t.Fatalf("в стартовом окне диалер вернул %v, ожидалась ErrNotReady: "+
			"иначе netstack отвечает RST там, где §5.6 требует ожидания", err)
	}

	// А после того, как бюджет истёк и живых узлов нет, — уже отказ, а не
	// ожидание: знание вместо незнания.
	r.prob.set("a", health.Result{Err: errDead})
	r.start()
	r.killAll("a")
	r.clk.Advance(health.DefaultStartupBudget)

	if s := r.a.Snapshot(); s.Traffic != PhaseFailing {
		t.Fatalf("фаза %q, ожидалась failing", s.Traffic)
	}
	_, err = d.DialTCP(netip.MustParseAddrPort("93.184.216.34:443"))
	if !errors.Is(err, ErrNoNode) {
		t.Fatalf("при fail-close диалер вернул %v, ожидалась ErrNoNode", err)
	}
}

// TestW37ProbeGoesToNamedNodeMarked — проба идёт в названный узел и с меткой.
//
// Два утверждения в одной проверке, потому что порознь они не значат ничего.
// Метка без правильного узла означала бы, что счётчики разведены, но мерится
// не тот узел; правильный узел без метки — что мерится тот, но один его провал
// идёт в оба счётчика (Р38, §5.4).
//
// Узел берётся заведомо **не** активный: живость выбрала первый, а проба
// обязана уметь спросить кандидата, которым никто не пользуется.
func TestW37ProbeGoesToNamedNodeMarked(t *testing.T) {
	r := newRig(t, "n1", "n2")
	r.start()
	r.runRound()

	active := r.a.Snapshot().Active
	if active == "" {
		t.Fatal("активного узла нет — стенд не дошёл до состояния, в котором проба осмысленна")
	}
	other := "n1"
	if active == "n1" {
		other = "n2"
	}

	c, err := r.a.ProbeDial(context.Background(), other, "tcp", "203.0.113.1:80")
	if err != nil {
		t.Fatalf("проба не дозвонилась: %v", err)
	}
	defer c.Close()

	x := r.xrays.at(r.xrays.count() - 1)
	seen := x.dialed()
	if len(seen) == 0 {
		t.Fatal("инстанс не увидел ни одного дозвона")
	}
	last := seen[len(seen)-1]

	if last.node != other {
		t.Errorf("проба ушла в узел %q, просили %q: пробер мерил бы активный узел под всеми именами", last.node, other)
	}
	if !last.probe {
		t.Error("на контексте пробы нет метки Р38: её провал пойдёт и в окно проб, и в счётчик трафика (§5.4)")
	}
}

// TestW37ProbeRefusesNonTCP — пробер, попросивший не tcp, получает ошибку.
//
// Через outbound Xray ходит только TCP, и молчаливая подмена протокола
// выглядела бы смертью узла — то есть увела бы пользователя с живого.
func TestW37ProbeRefusesNonTCP(t *testing.T) {
	r := newRig(t, "n1")
	r.start()
	r.runRound()

	if _, err := r.a.ProbeDial(context.Background(), "n1", "udp", "203.0.113.1:53"); err == nil {
		t.Error("проба по udp принята молча: сломанный пробер выглядел бы мёртвым узлом")
	}
}
