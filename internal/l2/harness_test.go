// Package l2 — тесты датаплейна уровня L2 (§8.3): настоящие VLESS-соединения
// через fault injector, без прав и без TUN.
//
// Отличие от L1 (internal/health): там политика живости проверяется на фейковом
// пробере и фейковых часах, здесь — на настоящем узле, настоящем HTTP и
// настоящем времени. Моков между health и узлом нет ни одного.
//
// Расписание проб здесь сжато до сотен миллисекунд. Это не подмена бюджета из
// docs/verification-autoswitch.md §4, а его условие: бюджеты сформулированы как
// «k неудач по интервалу», и проверяется здесь механизм, а не стартовые числа
// §6.5 — их численно проверяет A25 и B2.
package l2

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/faultinject"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/probetarget"
	"github.com/shafed/hop/internal/xraytest"
)

// node — один узел стенда: инбаунд Xray за инжектором отказов.
type node struct {
	id  string
	srv *xraytest.Server
	inj *faultinject.Injector
}

// harness — «интернет», узлы, движок, пробе-таргет и менеджер живости.
type harness struct {
	t    *testing.T
	echo string
	tgt  *probetarget.Target
	eng  *engine.Engine
	mgr  *health.Manager
	node map[string]*node

	mu          sync.Mutex
	conns       []net.Conn
	interrupts  int
	switchEvent []health.SwitchEvent
}

type options struct {
	nodes []string
	// Расписание. Нули заменяются сжатыми значениями стенда.
	activeInterval, candidateInterval, probeTimeout, tolerance time.Duration
}

func newHarness(t *testing.T, opt options) *harness {
	t.Helper()
	if len(opt.nodes) == 0 {
		opt.nodes = []string{"A", "B"}
	}
	setDefault := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	setDefault(&opt.activeInterval, 150*time.Millisecond)
	setDefault(&opt.candidateInterval, 150*time.Millisecond)
	setDefault(&opt.probeTimeout, 400*time.Millisecond)
	setDefault(&opt.tolerance, 50*time.Millisecond)

	h := &harness{t: t, node: map[string]*node{}}
	h.echo = echoServer(t)
	h.tgt = probetarget.New()
	t.Cleanup(h.tgt.Close)

	var nodes []engine.Node
	for _, id := range opt.nodes {
		srv, err := xraytest.NewServer(xraytest.Options{UUID: uuidFor(id)})
		if err != nil {
			t.Fatalf("инбаунд %s: %v", id, err)
		}
		t.Cleanup(func() { srv.Close() })

		inj, err := faultinject.New(srv.Addr())
		if err != nil {
			t.Fatalf("инжектор %s: %v", id, err)
		}
		t.Cleanup(func() { inj.Close() })

		host, port := splitAddr(t, inj.Addr())
		h.node[id] = &node{id: id, srv: srv, inj: inj}
		nodes = append(nodes, engine.Node{
			ID: id, Protocol: "vless", Server: host, Port: port,
			Transport: "raw", Security: "none",
			Params: map[string]string{"uuid": srv.UUID()},
		})
	}

	// Движок сообщает вердикты §6.15 в health — через DialError.Report, то
	// есть через единственное место в продукте, где это позволено.
	eng, err := engine.NewWithConfig(engine.Config{
		Nodes: nodes,
		OnFailure: func(de *engine.DialError) {
			h.mu.Lock()
			mgr := h.mgr
			h.mu.Unlock()
			if mgr != nil {
				de.Report(mgr)
			}
		},
	})
	if err != nil {
		t.Fatalf("движок: %v", err)
	}
	h.eng = eng
	t.Cleanup(func() { eng.Close() })

	// Проба ходит тем же путём, что и трафик (§6.7): тот же движок, тот же
	// узел, тот же outbound.
	prober := &health.MultiProber{Targets: []health.Target{
		&health.HTTPTarget{URL: h.tgt.URL(), Dial: func(ctx context.Context, nodeID, network, addr string) (net.Conn, error) {
			return eng.DialTCP(ctx, nodeID, addr)
		}},
	}}

	var hnodes []health.Node
	for _, id := range opt.nodes {
		hnodes = append(hnodes, health.Node{ID: id, Supported: true})
	}
	mgr := health.New(health.Config{
		Nodes:             hnodes,
		Clock:             clock.System{},
		Prober:            prober,
		ActiveInterval:    opt.activeInterval,
		CandidateInterval: opt.candidateInterval,
		TailInterval:      opt.candidateInterval,
		ProbeTimeout:      opt.probeTimeout,
		StartupBudget:     2 * time.Second,
		Tolerance:         opt.tolerance,
		Interrupt:         h.interrupt,
	})
	h.mu.Lock()
	h.mgr = mgr
	h.mu.Unlock()
	t.Cleanup(mgr.Close)

	go h.collectEvents()
	mgr.Start()
	return h
}

// interrupt рвёт активные соединения (§5.5). В продукте это делает netstack;
// здесь — стенд, потому что проверяется контракт «reason=dead рвёт», а не
// реализация разрыва.
func (h *harness) interrupt() int {
	h.mu.Lock()
	conns := h.conns
	h.conns = nil
	h.interrupts++
	h.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	return len(conns)
}

func (h *harness) collectEvents() {
	for ev := range h.mgr.Events() {
		h.mu.Lock()
		h.switchEvent = append(h.switchEvent, ev)
		h.mu.Unlock()
	}
}

func (h *harness) events() []health.SwitchEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]health.SwitchEvent, len(h.switchEvent))
	copy(out, h.switchEvent)
	return out
}

// dial открывает соединение через узел и запоминает его: такие соединения
// рвутся при reason=dead.
func (h *harness) dial(nodeID string) (net.Conn, error) {
	// Контекст живёт столько же, сколько соединение: отмена рвёт поток
	// диспетчера, и соединение умирает не от отказа узла, а от нас самих.
	c, err := h.eng.DialTCP(context.Background(), nodeID, h.echo)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.conns = append(h.conns, c)
	h.mu.Unlock()
	return c, nil
}

// waitAnyActive ждёт любого выбора и возвращает выбранный узел.
//
// Какой узел выиграет холодный старт, стенд не знает: по Р4 активным
// становится первый ответивший, а на локальных инбаундах разница в латентности
// внутри погрешности. Поэтому тесты ломают тот узел, который выбран, а не тот,
// который «должен» быть выбран.
func (h *harness) waitAnyActive(budget time.Duration) string {
	h.t.Helper()
	h.waitFor("выбор так и не появился", budget, func() bool {
		return h.mgr.Snapshot().Active != ""
	})
	return h.mgr.Snapshot().Active
}

// other — любой узел стенда, кроме этого.
func (h *harness) other(id string) string {
	for k := range h.node {
		if k != id {
			return k
		}
	}
	h.t.Fatalf("на стенде нет узла, кроме %s", id)
	return ""
}

// waitActive ждёт, пока активным станет один из ожидаемых узлов.
func (h *harness) waitActive(want string, budget time.Duration) {
	h.t.Helper()
	h.waitFor("активным не стал "+want, budget, func() bool {
		return h.mgr.Snapshot().Active == want
	})
}

func (h *harness) waitFor(what string, budget time.Duration, cond func() bool) {
	h.t.Helper()
	deadline := time.After(budget)               //hop:realtime
	tick := time.NewTicker(5 * time.Millisecond) //hop:realtime
	defer tick.Stop()
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			h.t.Fatalf("не дождались за %v: %s (активен %q)", budget, what, h.mgr.Snapshot().Active)
		case <-tick.C:
		}
	}
}

// echoServer — «интернет» стенда.
func echoServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("эхо-сервер: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("адрес %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("порт %q: %v", portStr, err)
	}
	return host, port
}

// uuidFor — свой пользователь на каждый узел: инбаунды стенда обязаны
// отличаться, иначе тест «соединение ушло не туда» ничего не проверяет.
func uuidFor(id string) string {
	base := "b831381d-6324-4d53-ad4f-8cda48b3081"
	switch id {
	case "A":
		return base + "1"
	case "B":
		return base + "2"
	case "C":
		return base + "3"
	default:
		return base + "0"
	}
}

// interruptCount — сколько раз рвали соединения.
func (h *harness) interruptCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.interrupts
}

// dialFunc — диалер для health.HTTPTarget: тот же движок, тот же узел.
func (h *harness) dialFunc() health.DialFunc {
	return func(ctx context.Context, nodeID, network, addr string) (net.Conn, error) {
		return h.eng.DialTCP(ctx, nodeID, addr)
	}
}

// closedPort — адрес, на котором заведомо никто не слушает.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("порт: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
