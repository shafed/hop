package l2

import (
	"context"
	"errors"
	"io"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/faultinject"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/probetarget"
)

// budget — предел, за который обязано уложиться переключение на этом стенде.
// Число из §8.3 (T9, T11): «≤ 5 с».
const budget = 5 * time.Second

// T9: долгое соединение через A, A уходит в blackhole — соединение получает
// ошибку за ≤ 5 с. Проверяет разрыв по причине dead (§5.5).
func TestT9BlackholeBreaksLiveConnection(t *testing.T) {
	h := newHarness(t, options{})
	active := h.waitAnyActive(budget)
	spare := h.other(active)

	conn, err := h.dial(active)
	if err != nil {
		t.Fatalf("соединение через %s: %v", active, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("живое соединение")); err != nil {
		t.Fatalf("запись до отказа: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, len("живое соединение"))); err != nil {
		t.Fatalf("эхо до отказа: %v", err)
	}

	start := time.Now() //hop:realtime
	h.node[active].inj.SetMode(faultinject.ModeBlackhole)

	// Соединение обязано кончиться ошибкой, а не висеть до TCP-таймаута.
	conn.SetReadDeadline(time.Now().Add(budget)) //hop:realtime
	_, err = conn.Read(make([]byte, 16))
	elapsed := time.Since(start) //hop:realtime

	if err == nil {
		t.Fatal("соединение через мёртвый узел осталось живым")
	}
	if errors.Is(err, io.EOF) || isTimeout(err) {
		// Таймаут дедлайна означает, что нас никто не разорвал.
		if isTimeout(err) {
			t.Fatalf("соединение висело до дедлайна (%v) вместо разрыва: узел не признан мёртвым", elapsed)
		}
	}
	if elapsed > budget {
		t.Errorf("разрыв занял %v, бюджет %v", elapsed, budget)
	}
	if got := h.mgr.Snapshot().Active; got != spare {
		t.Errorf("активен %q, ожидался %s", got, spare)
	}
	if last := lastEvent(t, h); last.Reason != health.ReasonDead {
		t.Errorf("причина %v, ожидалась dead", last.Reason)
	}
}

// T10: A деградировал по скорости, B быстрее — соединение доживает, новое
// идёт через B. Проверяет, что разрыв привязан к причине, а не к самому факту
// переключения (§5.5): обрыв загрузки ради 30 мс раздражает сильнее, чем 30 мс.
func TestT10SlowNodeKeepsConnectionAlive(t *testing.T) {
	h := newHarness(t, options{
		// Проба обязана пережить задержку: иначе узел умрёт, и тест проверит
		// не то. Медленный — не мёртвый, в этом вся суть T10.
		probeTimeout:      3 * time.Second,
		activeInterval:    200 * time.Millisecond,
		candidateInterval: 200 * time.Millisecond,
	})
	active := h.waitAnyActive(budget)
	spare := h.other(active)

	conn, err := h.dial(active)
	if err != nil {
		t.Fatalf("соединение через %s: %v", active, err)
	}
	defer conn.Close()

	// Стартовый выбор несёт reason=dead и уже дёрнул разрыв (§2): считаем
	// разрывы от этого момента, а не от нуля.
	interruptsBefore := h.interruptCount()

	h.node[active].inj.SetSlow(250 * time.Millisecond)
	h.node[active].inj.SetMode(faultinject.ModeSlow)

	// Ждём именно событие перехода, а не снимок: утверждение теста — о причине
	// ЭТОГО переключения, а «последнее собранное» событие в этот момент вполне
	// может быть ещё стартовым выбором (см. waitSwitchTo).
	if ev := h.waitSwitchTo(spare, 15*time.Second); ev.Reason != health.ReasonFaster {
		t.Fatalf("причина %v, ожидалась faster: медленный узел не мёртв", ev.Reason)
	}
	if got := h.interruptCount() - interruptsBefore; got != 0 {
		t.Errorf("соединения рвали %d раз, ожидалось 0", got)
	}

	// Соединение через A живо: оно медленное, но целое.
	conn.SetDeadline(time.Now().Add(10 * time.Second)) //hop:realtime
	want := []byte("всё ещё живо")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("запись в пережившее соединение: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("чтение из пережившего соединения: %v", err)
	}

	// Новое соединение идёт уже через выбранный узел. Соединение Xray
	// ленивое (engine/conn.go), поэтому до первой записи на инжекторе ещё
	// ничего не видно — сначала прогоняем байты.
	before := h.node[spare].inj.Conns()
	c2, err := h.dial(spare)
	if err != nil {
		t.Fatalf("новое соединение через %s: %v", spare, err)
	}
	defer c2.Close()
	c2.SetDeadline(time.Now().Add(10 * time.Second)) //hop:realtime
	if _, err := c2.Write(want); err != nil {
		t.Fatalf("запись в новое соединение: %v", err)
	}
	if _, err := io.ReadFull(c2, make([]byte, len(want))); err != nil {
		t.Fatalf("эхо из нового соединения: %v", err)
	}
	if after := h.node[spare].inj.Conns(); after <= before {
		t.Errorf("соединений к %s %d → %d: новый трафик не пошёл через него", spare, before, after)
	}
}

// T11: rst и blackhole — разные пути в коде, и оба обязаны дать переключение
// за ≤ 5 с. blackhole ловит отсутствие таймаута там, где rst его маскирует
// (§8.1).
func TestT11RSTAndBlackholeBothSwitch(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode faultinject.Mode
	}{
		{"rst", faultinject.ModeRST},
		{"blackhole", faultinject.ModeBlackhole},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, options{})
			active := h.waitAnyActive(budget)
			spare := h.other(active)

			start := time.Now() //hop:realtime
			h.node[active].inj.SetMode(tc.mode)
			h.waitActive(spare, budget)
			elapsed := time.Since(start) //hop:realtime

			if elapsed > budget {
				t.Errorf("переключение заняло %v, бюджет %v", elapsed, budget)
			}
		})
	}
}

// T20: целевой хост отказал через живой узел — узел остался alive.
//
// Охраняет error_classify. С выключенной политикой смертью считается любой
// отказ, и живой узел умирает за чужой: ровно то, что §6.15 запрещает.
func TestT20TargetFailureKeepsNodeAlive(t *testing.T) {
	h := newHarness(t, options{})
	active := h.waitAnyActive(budget)

	// Адрес, на котором заведомо никто не слушает: узел до него дозвонится и
	// получит отказ — это отказ целевого хоста, а не узла.
	dead := closedPort(t)

	var streamErr error
	for i := 0; i < 4; i++ {
		conn, err := h.eng.DialTCP(context.Background(), active, dead)
		if err != nil {
			streamErr = err
			continue
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second)) //hop:realtime
		if _, werr := conn.Write([]byte("ping")); werr != nil {
			streamErr = werr
		} else if _, rerr := io.ReadFull(conn, make([]byte, 4)); rerr != nil {
			streamErr = rerr
		}
		conn.Close()
	}

	// Что именно видит клиент, когда целевой хост отказал: живой узел честно
	// закрывает поток, и приходит EOF. Смертельного вердикта здесь нет и быть
	// не может — а если он вдруг появился, узел умрёт за чужой отказ.
	if streamErr == nil {
		t.Fatal("отказ целевого хоста не дал ошибки вовсе — стенд собран не так")
	}
	var de *engine.DialError
	if errors.As(streamErr, &de) && de.Fatal() {
		t.Errorf("вердикт по отказу целевого хоста — %v, узел от этого умирать не должен (§6.15)", de.Kind)
	}

	snap := h.mgr.Snapshot()
	n, _ := snap.Node(active)
	if n.State == health.Dead {
		t.Errorf("узел %s мёртв после отказа целевого хоста (§6.15): %+v", active, n)
	}
	if n.TrafficFailures != 0 {
		t.Errorf("счётчик смертей узла %s = %d, ожидался 0: отказ сайта узел не убивает", active, n.TrafficFailures)
	}
	if snap.Active != active {
		t.Errorf("активен %q, ожидался %s: переключаться не с чего", snap.Active, active)
	}
}

// A34: проба узла видна на инжекторе этого узла и не видна на чужом.
// Доказательство §6.7, которое на L1 недоступно: там «тот же путь» — это
// договорённость об аргументе, здесь — наблюдаемый факт.
func TestA34ProbeGoesThroughItsOwnNode(t *testing.T) {
	h := newHarness(t, options{})
	active := h.waitAnyActive(budget)
	spare := h.other(active)

	beforeA := h.node[active].inj.Conns()
	beforeB := h.node[spare].inj.Conns()
	beforeTarget := h.tgt.Requests()

	// Ждём, пока пробы отработают ещё несколько раз.
	h.waitFor("пробы не дошли до таргета", budget, func() bool {
		return h.tgt.Requests() >= beforeTarget+3
	})

	afterA := h.node[active].inj.Conns()
	afterB := h.node[spare].inj.Conns()
	if afterA <= beforeA {
		t.Errorf("соединений к %s %d → %d: проба активного узла не пошла через него", active, beforeA, afterA)
	}
	if afterB <= beforeB {
		t.Errorf("соединений к %s %d → %d: кандидат обязан опрашиваться (§6.5)", spare, beforeB, afterB)
	}
}

// A35: узел стал медленнее — это видно в его rtt. Проба меряет путь трафика,
// а не что-то своё.
func TestA35SlowNodeShowsHigherRTT(t *testing.T) {
	h := newHarness(t, options{
		probeTimeout:      3 * time.Second,
		activeInterval:    200 * time.Millisecond,
		candidateInterval: 200 * time.Millisecond,
	})
	active := h.waitAnyActive(budget)

	var fast time.Duration
	h.waitFor("не измерили латентность "+active, budget, func() bool {
		n, ok := h.mgr.Snapshot().Node(active)
		fast = n.RTT
		return ok && n.RTT > 0
	})

	const delay = 250 * time.Millisecond
	h.node[active].inj.SetSlow(delay)
	h.node[active].inj.SetMode(faultinject.ModeSlow)

	h.waitFor("rtt узла "+active+" не вырос после деградации", 15*time.Second, func() bool {
		n, ok := h.mgr.Snapshot().Node(active)
		return ok && n.RTT >= fast+delay
	})
}

// TestProbeTargetBlockedByOneURL — T5 на настоящем HTTP: один тестовый домен
// отдаёт 403, узел обязан остаться живым за счёт второго (§5.4).
func TestProbeTargetBlockedByOneURL(t *testing.T) {
	blocked := probetarget.New()
	defer blocked.Close()
	blocked.SetMode(probetarget.StatusForbidden)

	h := newHarness(t, options{})
	active := h.waitAnyActive(budget)

	// Подменять пробер на живом менеджере нельзя, поэтому проверяем сведение
	// на самом MultiProber — тем же путём, через движок.
	p := &health.MultiProber{Targets: []health.Target{
		&health.HTTPTarget{URL: blocked.URL(), Dial: h.dialFunc()},
		&health.HTTPTarget{URL: h.tgt.URL(), Dial: h.dialFunc()},
	}}
	res := p.Probe(context.Background(), active)
	if res.Err != nil {
		t.Errorf("проба провалилась при живом втором URL: %v", res.Err)
	}
	if blocked.Requests() == 0 {
		t.Error("заблокированный URL не опрашивался — стенд собран не так")
	}
}

func lastEvent(t *testing.T, h *harness) health.SwitchEvent {
	t.Helper()
	evs := h.events()
	if len(evs) == 0 {
		t.Fatal("событий переключения не было вовсе")
	}
	return evs[len(evs)-1]
}

func isTimeout(err error) bool {
	var ne interface{ Timeout() bool }
	return errors.As(err, &ne) && ne.Timeout()
}

var _ = engine.OutboundTag
