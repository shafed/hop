package health

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
)

// Стенд L1 (§8.1): фейковый пробер, фейковые часы, узлы без сети. Настоящее
// время здесь есть только в сторожевых таймерах ниже — они не участвуют в
// логике, а лишь не дают красному тесту висеть до таймаута go test.

// errProbe — обычная неудача пробы (не таймаут).
var errProbe = errors.New("проба не прошла")

// fakeProber — программируемый пробер. Считает вызовы по узлам и следит, чтобы
// к одному узлу не уходило двух проб разом (A27).
type fakeProber struct {
	mu       sync.Mutex
	rtts     map[string][]time.Duration // кольцо латентностей
	rttIdx   map[string]int
	failing  map[string]bool
	hung     map[string]bool          // проба висит до отмены контекста
	gates    map[string]chan struct{} // проба ждёт разрешения теста
	calls    map[string]int
	inFlight map[string]int
	maxPar   map[string]int
	entered  chan string
}

func newFakeProber() *fakeProber {
	return &fakeProber{
		rtts:     map[string][]time.Duration{},
		rttIdx:   map[string]int{},
		failing:  map[string]bool{},
		hung:     map[string]bool{},
		gates:    map[string]chan struct{}{},
		calls:    map[string]int{},
		inFlight: map[string]int{},
		maxPar:   map[string]int{},
		entered:  make(chan string, 1024),
	}
}

// setRTT задаёт постоянную латентность узла.
func (p *fakeProber) setRTT(id string, d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rtts[id] = []time.Duration{d}
	p.rttIdx[id] = 0
	p.failing[id] = false
}

// cycleRTT задаёт кольцо латентностей: узел отдаёт их по кругу (T3).
func (p *fakeProber) cycleRTT(id string, ds ...time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rtts[id] = ds
	p.rttIdx[id] = 0
	p.failing[id] = false
}

// setFailing включает и выключает отказ узла.
func (p *fakeProber) setFailing(id string, v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failing[id] = v
}

// setHung заставляет пробу узла висеть до отмены контекста.
func (p *fakeProber) setHung(id string, v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hung[id] = v
}

// gate заставляет пробу узла ждать разрешения. Возвращает функцию, которая её
// отпускает: так тест задаёт порядок ответов, не трогая часы (A12).
func (p *fakeProber) gate(id string) func() {
	p.mu.Lock()
	ch := make(chan struct{})
	p.gates[id] = ch
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		delete(p.gates, id)
		p.mu.Unlock()
		close(ch)
	}
}

func (p *fakeProber) callCount(id string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[id]
}

func (p *fakeProber) maxParallel(id string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxPar[id]
}

// Probe реализует Prober. Узел получает пробу по своему id (A33).
func (p *fakeProber) Probe(ctx context.Context, nodeID string) Result {
	p.mu.Lock()
	p.calls[nodeID]++
	p.inFlight[nodeID]++
	if p.inFlight[nodeID] > p.maxPar[nodeID] {
		p.maxPar[nodeID] = p.inFlight[nodeID]
	}
	hung, failing, gate := p.hung[nodeID], p.failing[nodeID], p.gates[nodeID]
	var rtt time.Duration
	if ring := p.rtts[nodeID]; len(ring) > 0 {
		rtt = ring[p.rttIdx[nodeID]%len(ring)]
		p.rttIdx[nodeID]++
	}
	p.mu.Unlock()

	select {
	case p.entered <- nodeID:
	default:
	}

	defer func() {
		p.mu.Lock()
		p.inFlight[nodeID]--
		p.mu.Unlock()
	}()

	if hung {
		<-ctx.Done()
		return Result{Err: ctx.Err()}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return Result{Err: ctx.Err()}
		}
	}
	if failing {
		return Result{Err: errProbe}
	}
	return Result{RTT: rtt}
}

// waitEntered ждёт входа в пробу узла: тест вправе двигать часы только после
// того, как проба зарегистрировала своё ожидание таймаута.
func (p *fakeProber) waitEntered(t *testing.T, id string) {
	t.Helper()
	deadline := time.After(watchdog) //hop:realtime
	for {
		select {
		case got := <-p.entered:
			if got == id {
				return
			}
		case <-deadline:
			t.Fatalf("проба узла %s не началась", id)
		}
	}
}

// --- фикстура ----------------------------------------------------------

// watchdog — предел ожидания в сторожевых помощниках. К модельному времени
// отношения не имеет: он существует, чтобы красный тест падал за секунды, а не
// висел до таймаута go test — negcheck гоняет каждый охраняющий тест дважды.
const watchdog = 10 * time.Second

type fixture struct {
	t      *testing.T
	clk    *clock.Fake
	prober *fakeProber
	mgr    *Manager
	start  time.Time

	mu         sync.Mutex
	events     []SwitchEvent
	interrupts int
	perSwitch  int
}

// newFixture поднимает менеджер на фейковых часах и фейковом пробере.
// tweak меняет конфигурацию до создания менеджера.
func newFixture(t *testing.T, nodes []Node, tweak func(*Config)) *fixture {
	t.Helper()
	f := &fixture{
		t:         t,
		clk:       clock.NewFake(time.Unix(1000, 0)),
		prober:    newFakeProber(),
		perSwitch: 1,
	}
	f.start = f.clk.Now()

	cfg := Config{
		Nodes:  nodes,
		Clock:  f.clk,
		Prober: f.prober,
		Interrupt: func() int {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.interrupts++
			return f.perSwitch
		},
	}
	if tweak != nil {
		tweak(&cfg)
	}
	f.mgr = New(cfg)
	go f.collect()
	t.Cleanup(f.mgr.Close)
	return f
}

// collect вычитывает поток событий (§3.3: подписчиков может быть несколько).
func (f *fixture) collect() {
	for ev := range f.mgr.Events() {
		f.mu.Lock()
		f.events = append(f.events, ev)
		f.mu.Unlock()
	}
}

// barrier гарантирует, что всё испущенное до вызова уже собрано: очередь
// событий — FIFO, поэтому приход маркера означает приход всего, что раньше.
// Нужен для отрицательных утверждений вида «переключений не было».
func (f *fixture) barrier() {
	const mark = "\x00barrier"
	f.mgr.events.push(SwitchEvent{To: mark})
	f.waitFor("маркер очереди событий не дошёл", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		for i, ev := range f.events {
			if ev.To == mark {
				f.events = append(f.events[:i], f.events[i+1:]...)
				return true
			}
		}
		return false
	})
}

// switches возвращает собранные события переключения.
func (f *fixture) switches() []SwitchEvent {
	f.barrier()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]SwitchEvent, len(f.events))
	copy(out, f.events)
	return out
}

func (f *fixture) interruptCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.interrupts
}

// waitFor ждёт условия под сторожевым таймером.
func (f *fixture) waitFor(what string, cond func() bool) {
	f.t.Helper()
	deadline := time.After(watchdog)               //hop:realtime
	tick := time.NewTicker(200 * time.Microsecond) //hop:realtime
	defer tick.Stop()
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			f.t.Fatalf("не дождались: %s", what)
		case <-tick.C:
		}
	}
}

// waitRound ждёт завершения раунда n. После возврата следующий таймер уже
// зарегистрирован, поэтому часы можно двигать сразу.
func (f *fixture) waitRound(n uint64) {
	f.t.Helper()
	done := make(chan struct{})
	go func() { f.mgr.WaitRound(n); close(done) }()
	select {
	case <-done:
	case <-time.After(watchdog): //hop:realtime
		f.t.Fatalf("раунд %d не наступил (проб A=%d)", n, f.prober.callCount("A"))
	}
}

// startAndSettle запускает цикл и дожидается стартового обхода.
func (f *fixture) startAndSettle() {
	f.t.Helper()
	f.mgr.Start()
	f.waitRound(1)
}

// advanceRound двигает часы на d и ждёт очередного раунда.
func (f *fixture) advanceRound(d time.Duration) {
	f.t.Helper()
	r := f.mgr.Snapshot().Round
	f.clk.Advance(d)
	f.waitRound(r + 1)
}

func (f *fixture) active() string { return f.mgr.Snapshot().Active }

// killAll крутит раунды, пока все перечисленные узлы не станут мёртвыми.
// Ярус узла меняется по ходу дела — активный опрашивается чаще кандидата, —
// поэтому число раундов заранее неизвестно.
func (f *fixture) killAll(ids ...string) {
	f.t.Helper()
	for i := 0; i < 3*len(ids)+3; i++ {
		allDead := true
		for _, id := range ids {
			if f.state(id) != Dead {
				allDead = false
			}
		}
		if allDead {
			return
		}
		f.advanceRound(DefaultCandidateInterval)
	}
	f.t.Fatalf("узлы %v не умерли за отведённые раунды", ids)
}

func (f *fixture) state(id string) State {
	f.t.Helper()
	h, ok := f.mgr.Snapshot().Node(id)
	if !ok {
		f.t.Fatalf("узла %s нет в снимке", id)
	}
	return h.State
}

// nodes — стандартный набор стенда.
func nodes(ids ...string) []Node {
	out := make([]Node, 0, len(ids))
	for _, id := range ids {
		out = append(out, Node{ID: id, Supported: true})
	}
	return out
}
