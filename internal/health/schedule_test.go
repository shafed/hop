package health

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/shafed/hop/internal/clock"
)

// fakeProber — пробер без сети: исход каждого узла задаёт тест.
type fakeProber struct {
	mu     sync.Mutex
	res    map[string]Result
	calls  []string
	probed chan string
}

func newFakeProber() *fakeProber {
	return &fakeProber{res: make(map[string]Result), probed: make(chan string, 256)}
}

func (p *fakeProber) set(id string, r Result) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.res[id] = r
}

func (p *fakeProber) Probe(_ context.Context, nodeID string) Result {
	p.mu.Lock()
	r, ok := p.res[nodeID]
	if !ok {
		r = Result{Err: errors.New("узел не отвечает")}
	}
	p.calls = append(p.calls, nodeID)
	p.mu.Unlock()

	select {
	case p.probed <- nodeID:
	default:
	}
	return r
}

// taken — кого пробовали с прошлого раза.
func (p *fakeProber) taken() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.calls
	p.calls = nil
	return out
}

func countOf(ids []string, prefix string) int {
	n := 0
	for _, id := range ids {
		if strings.HasPrefix(id, prefix) {
			n++
		}
	}
	return n
}

func has(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// T5. Первый пробе-URL отдаёт 403 всем, второй отдаёт 204 — узлы живы. С одним
// URL заблокированный домен убил бы всю подписку разом (§5.4).
func TestT5OneDeadURLDoesNotKillNode(t *testing.T) {
	blocked := netip.MustParseAddrPort("203.0.113.1:80")
	good := netip.MustParseAddrPort("203.0.113.2:80")

	clk := clock.NewFake(epoch)
	prober := NewURLProber(
		fakeHTTP(map[netip.AddrPort]int{blocked: 403, good: 204}),
		[]Target{
			{Addr: blocked, Host: "blocked.example", Path: "/generate_204"},
			{Addr: good, Host: "good.example", Path: "/generate_204"},
		},
		clk,
	)
	mon := NewMonitor(DefaultMonitorConfig(), clk)

	for i := 0; i < 3; i++ {
		mon.Observe("A", prober.Probe(context.Background(), "A"))
	}

	if got := mon.Get("A").State; got != Alive {
		t.Fatalf("узел с одним заблокированным пробе-URL получил состояние %q (%s)",
			got, mon.Get("A").LastError)
	}
	if !mon.HasAlive() {
		t.Fatal("живых узлов нет: один мёртвый URL увёл всю подписку в fail-close")
	}
}

// fakeHTTP — пробе-таргеты §8.1 поверх net.Pipe: без сокетов и без сети.
// Код ответа задаёт тест: 204 — норма, 403 — «домен заблокирован».
func fakeHTTP(codes map[netip.AddrPort]int) DialFunc {
	return func(_ context.Context, _ string, dst netip.AddrPort) (net.Conn, error) {
		code, ok := codes[dst]
		if !ok {
			return nil, fmt.Errorf("таргета %s нет", dst)
		}
		cli, srv := net.Pipe()
		go func() {
			defer srv.Close()
			br := bufio.NewReader(srv)
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
			if code == 204 {
				fmt.Fprint(srv, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
				return
			}
			fmt.Fprintf(srv, "HTTP/1.1 %d Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code)
		}()
		return cli, nil
	}
}

// newScheduler — расписание с фейковым пробером; узлы: активный A, пул B,
// редкий ярус r0..rN.
func newScheduler(t *testing.T, rest int) (*Scheduler, *fakeProber, *clock.Fake, *Monitor, *Selector) {
	t.Helper()
	clk := clock.NewFake(epoch)
	mon := NewMonitor(DefaultMonitorConfig(), clk)
	sel := NewSelector(mon, DefaultSelectorConfig(), clk)
	t.Cleanup(sel.Close)

	ids := make([]string, rest)
	for i := range ids {
		ids[i] = fmt.Sprintf("r%02d", i)
	}
	sel.SetCandidates(append([]string{"A", "B"}, ids...))

	prober := newFakeProber()
	prober.set("A", Result{RTT: 50 * ms})
	prober.set("B", Result{RTT: 70 * ms})
	for _, id := range ids {
		prober.set(id, Result{RTT: 200 * ms})
	}

	sch := NewScheduler(prober, mon, sel, DefaultScheduleConfig(), clk)
	sch.SetNodes("A", []string{"B"}, ids)
	return sch, prober, clk, mon, sel
}

// T6. Событие смены интерфейса — прогон проб начался немедленно, не по тикеру:
// часы не двигались вовсе, а горячий ярус уже проверен (§6.6).
func TestT6ForcedProbeOnEvent(t *testing.T) {
	sch, prober, clk, mon, _ := newScheduler(t, 4)
	prober.taken() // расписание ещё ничего не прогоняло, но список чистим явно

	sch.Force(TriggerInterface)

	if now := clk.Now(); now != epoch {
		t.Fatalf("часы ушли на %v: прогон дождался тикера вместо немедленного", now.Sub(epoch))
	}
	got := prober.taken()
	if !has(got, "A") || !has(got, "B") {
		t.Fatalf("после смены интерфейса проверены %v, ожидались активный A и пул B", got)
	}
	if st := mon.Get("A").State; st != Alive {
		t.Fatalf("исход форс-пробы не доехал до монитора: состояние A — %q", st)
	}
}

// Редкий ярус уходит вразнобой, а не залпом: 200 узлов подписки не должны бить
// по провайдеру одновременно (§6.5).
func TestScheduleRestTierIsSpreadByJitter(t *testing.T) {
	sch, prober, clk, _, _ := newScheduler(t, 50)

	sch.Sweep(context.Background())
	first := prober.taken()
	if !has(first, "A") || !has(first, "B") {
		t.Fatalf("горячий ярус не проверен на старте: %v", first)
	}
	if n := countOf(first, "r"); n > 5 {
		t.Fatalf("на старте залпом ушло %d узлов редкого яруса из 50", n)
	}

	clk.Advance(DefaultScheduleConfig().Jitter)
	sch.Sweep(context.Background())
	seen := map[string]bool{}
	for _, id := range append(first, prober.taken()...) {
		seen[id] = true
	}
	if n := len(seen) - 2; n != 50 {
		t.Fatalf("за окно джиттера проверено %d узлов редкого яруса из 50", n)
	}
}

// Ярусы §6.5: активный узел опрашивается чаще пула, пул — чаще подписки.
func TestScheduleActiveIsProbedOftenerThanPool(t *testing.T) {
	cfg := DefaultScheduleConfig()
	sch, prober, clk, _, _ := newScheduler(t, 2)

	sch.Sweep(context.Background())
	prober.taken()

	clk.Advance(cfg.Active)
	sch.Sweep(context.Background())
	if got := prober.taken(); !has(got, "A") || has(got, "B") {
		t.Fatalf("через период активного яруса проверены %v, ожидался только A", got)
	}

	clk.Advance(cfg.Active)
	sch.Sweep(context.Background())
	if got := prober.taken(); !has(got, "A") || !has(got, "B") {
		t.Fatalf("через период пула проверены %v, ожидались A и B", got)
	}
}

// Пул кандидатов ограничен PoolSize: лишние узлы опрашиваются по редкому
// ярусу, иначе расписание вырождается в полный обход подписки (§6.5).
func TestPoolSizeCapsHotTier(t *testing.T) {
	cfg := DefaultScheduleConfig()
	clk := clock.NewFake(epoch)
	mon := NewMonitor(DefaultMonitorConfig(), clk)
	sel := NewSelector(mon, DefaultSelectorConfig(), clk)
	t.Cleanup(sel.Close)

	pool := make([]string, cfg.PoolSize+3)
	for i := range pool {
		pool[i] = fmt.Sprintf("p%d", i)
	}
	prober := newFakeProber()
	sch := NewScheduler(prober, mon, sel, cfg, clk)
	sch.SetNodes("A", pool, nil)

	sch.Sweep(context.Background())
	prober.taken()

	clk.Advance(cfg.Pool)
	sch.Sweep(context.Background())
	got := prober.taken()
	for _, id := range pool[:cfg.PoolSize] {
		if !has(got, id) {
			t.Fatalf("узел пула %s не проверен через период пула: %v", id, got)
		}
	}
	for _, id := range pool[cfg.PoolSize:] {
		if has(got, id) {
			t.Fatalf("узел %s сверх PoolSize опрошен по горячему ярусу: %v", id, got)
		}
	}
}

// Run прогоняет расписание по тикеру и останавливается по контексту.
func TestRunSweepsOnTick(t *testing.T) {
	sch, prober, clk, _, _ := newScheduler(t, 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sch.Run(ctx) }()

	// Стартовый прогон: истории нет вовсе, ждать первого тика нечего.
	if got := waitProbes(t, prober, 2); !has(got, "A") || !has(got, "B") {
		t.Fatalf("на старте проверены %v, ожидались A и B", got)
	}

	clk.Advance(DefaultScheduleConfig().Active)
	if got := waitProbes(t, prober, 1); got[0] != "A" {
		t.Fatalf("через период активного яруса проверен %v, ожидался A", got)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run вернул %v, ожидалась отмена контекста", err)
	}
}

// waitProbes ждёт ровно n проб. Ожидание на канале, а не на настоящем времени:
// сломанное расписание валит тест по таймауту go test, а не по sleep.
func waitProbes(t *testing.T, p *fakeProber, n int) []string {
	t.Helper()
	got := make([]string, 0, n)
	for len(got) < n {
		got = append(got, <-p.probed)
	}
	return got
}
