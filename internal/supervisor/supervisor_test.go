package supervisor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time" //hop:realtime

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/fakenet"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/node"
	"github.com/shafed/hop/internal/packettest"
)

// Весь агент собирается на поддельном PacketDevice, фейковых часах, подставном
// исходящем и фейковом пробере (§8.1): ни сети, ни TUN, ни прав, ни настоящего
// времени.
var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const ms = time.Millisecond

// Адреса стенда: клиент за туннелем, «интернет» — документационная сеть
// RFC 5737, DNS — локальный роутер (он же проверка §3.4: перехват прежде
// bypass).
var (
	client   = netip.MustParseAddrPort("10.255.0.2:5000")
	web      = netip.MustParseAddrPort("203.0.113.7:80")
	udpPeer  = netip.MustParseAddrPort("203.0.113.1:9999")
	router53 = netip.MustParseAddrPort("192.168.1.1:53")
)

// fakeOutbound — исходящее без единого настоящего соединения. Ровно то, ради
// чего Outbound объявлен интерфейсом: §5.5 проверяется без Xray.
type fakeOutbound struct {
	*fakenet.Dialer

	mu     sync.Mutex
	active string
}

func newFakeOutbound() *fakeOutbound {
	return &fakeOutbound{Dialer: fakenet.NewDialer(false)}
}

func (o *fakeOutbound) Start() error { return nil }
func (o *fakeOutbound) Close() error { return nil }

func (o *fakeOutbound) SetActive(nodeID string) {
	o.mu.Lock()
	o.active = nodeID
	o.mu.Unlock()
}

func (o *fakeOutbound) Active() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.active
}

func (o *fakeOutbound) DialVia(_ context.Context, _ string, dst netip.AddrPort) (net.Conn, error) {
	return o.Dialer.DialTCP(dst)
}

func (o *fakeOutbound) DialDirect(_ context.Context, dst netip.AddrPort) (net.Conn, error) {
	return o.Dialer.DialTCP(dst)
}

// fakeProber — пробер, чей исход задаёт тест. Настоящий ходил бы наружу, и
// §8.1 запрещает это на уровне L1/L2.
type fakeProber struct {
	mu   sync.Mutex
	rtt  map[string]time.Duration
	bad  map[string]bool
	hung map[string]bool

	// started — по одной записи на начатую пробу. Тест ждёт её, прежде чем
	// крутить часы: иначе он прокрутит таймаут раньше, чем проба началась, и
	// померит не то.
	started chan string
}

func newFakeProber() *fakeProber {
	return &fakeProber{
		rtt:     map[string]time.Duration{},
		bad:     map[string]bool{},
		hung:    map[string]bool{},
		started: make(chan string, 256),
	}
}

func (p *fakeProber) alive(id string, rtt time.Duration) {
	p.mu.Lock()
	p.rtt[id] = rtt
	p.bad[id] = false
	p.hung[id] = false
	p.mu.Unlock()
}

func (p *fakeProber) dead(id string) {
	p.mu.Lock()
	p.bad[id] = true
	p.mu.Unlock()
}

// hang — узел-blackhole (§8.1): соединение принято, ответа нет, закрытия нет.
// Проба обязана сняться таймаутом, иначе ярус встанет навсегда.
func (p *fakeProber) hang(id string) {
	p.mu.Lock()
	p.hung[id] = true
	p.mu.Unlock()
}

func (p *fakeProber) Probe(ctx context.Context, nodeID string) health.Result {
	p.mu.Lock()
	bad, hung, rtt := p.bad[nodeID], p.hung[nodeID], p.rtt[nodeID]
	p.mu.Unlock()

	select {
	case p.started <- nodeID:
	default:
	}

	switch {
	case hung:
		<-ctx.Done()
		return health.Result{Err: ctx.Err()}
	case bad:
		return health.Result{Err: errors.New("проба не прошла")}
	}
	return health.Result{RTT: rtt}
}

// drain выбрасывает записи о прошлых пробах, чтобы waitStart не принял чужую
// запись за начало той пробы, которую ждёт тест.
func (p *fakeProber) drain() {
	for {
		select {
		case <-p.started:
		default:
			return
		}
	}
}

// waitStart ждёт начала пробы узла. Ожидание на настоящих часах: фейковые
// крутит сам тест, и ждать на них означало бы ждать себя.
func (p *fakeProber) waitStart(t *testing.T, id string) {
	t.Helper()
	deadline := clock.System{}.After(packettest.WaitTimeout)
	for {
		select {
		case got := <-p.started:
			if got == id {
				return
			}
		case <-deadline:
			t.Fatalf("проба узла %s не началась за %v", id, packettest.WaitTimeout)
		}
	}
}

type harness struct {
	t      *testing.T
	dev    *packettest.FakeDevice
	out    *fakeOutbound
	prober *fakeProber
	clk    *clock.Fake
	sup    *Supervisor
	events <-chan Event
}

func newHarness(t *testing.T, ids ...string) *harness {
	t.Helper()

	h := &harness{
		t:      t,
		dev:    packettest.NewFake(1500),
		out:    newFakeOutbound(),
		prober: newFakeProber(),
		clk:    clock.NewFake(epoch),
	}

	nodes := make([]node.Node, 0, len(ids))
	for _, id := range ids {
		nodes = append(nodes, node.Node{ID: id, Supported: true})
	}

	sup, err := New(Config{
		Device:   h.dev,
		Nodes:    nodes,
		Clock:    h.clk,
		Outbound: h.out,
		Prober:   h.prober,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.sup = sup
	h.events = sup.Subscribe()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		h.dev.Close() // разбудить насос: чтение устройства снимает только владелец
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	return h
}

// waitEvent ждёт следующее событие. Ожидание с заведомым концом, а не опрос:
// apply идёт в своей горутине, и «событие не пришло» обязано падать быстро.
func (h *harness) waitEvent() Event {
	h.t.Helper()
	select {
	case ev, ok := <-h.events:
		if !ok {
			h.t.Fatal("поток событий закрыт")
		}
		return ev
	case <-clock.System{}.After(packettest.WaitTimeout):
		h.t.Fatalf("события не было за %v", packettest.WaitTimeout)
	}
	return Event{}
}

// waitSwitch ждёт событие, несущее переключение.
func (h *harness) waitSwitch() health.Switch {
	h.t.Helper()
	for {
		if ev := h.waitEvent(); ev.Switch != nil {
			return *ev.Switch
		}
	}
}

// start приводит агента в рабочее состояние: узлы живы, активным стал первый.
func (h *harness) start(first, second string) {
	h.t.Helper()
	h.prober.alive(first, 10*ms)
	h.prober.alive(second, 200*ms)
	h.sup.Force(health.TriggerInterface)

	sw := h.waitSwitch()
	if sw.To != first {
		h.t.Fatalf("активным стал %q, ожидался быстрейший %q", sw.To, first)
	}
}

// udpFlow заводит живой поток UDP через активный узел и ждёт, пока датаграмма
// уйдёт наружу.
func (h *harness) udpFlow() {
	h.t.Helper()
	h.dev.Inject(packettest.UDP(client, udpPeer, []byte("q")))
	h.out.WaitConn(client).WaitSent(1)
	if n := h.sup.stack.Stats().NATSockets; n != 1 {
		h.t.Fatalf("исходящих сокетов %d, ожидался один", n)
	}
}

// Переключение по причине dead рвёт живые соединения (§5.5): через мёртвый узел
// они всё равно мертвы, и разрыв даёт приложению переподключиться за секунды
// вместо минут TCP-таймаута. Число разорванных уезжает в событие (§2).
func TestDeadSwitchInterruptsConnections(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.start("A", "B")
	h.udpFlow()

	h.prober.dead("A")
	// Две неудачи из трёх — политика смерти §6.3.
	h.sup.Force(health.TriggerInterface)
	h.sup.Force(health.TriggerInterface)

	sw := h.waitSwitch()
	if sw.To != "B" || sw.Reason != health.ReasonDead {
		t.Fatalf("переключение %+v, ожидалось на B по причине dead", sw)
	}
	if sw.InterruptedConnections != 1 {
		t.Fatalf("разорвано соединений %d, ожидалось одно", sw.InterruptedConnections)
	}
	if n := h.sup.stack.Stats().NATSockets; n != 0 {
		t.Fatalf("после разрыва осталось сокетов %d", n)
	}
	if got := h.out.Active(); got != "B" {
		t.Fatalf("движок остался на узле %q", got)
	}
}

// Переключение по причине faster соединения не трогает (§5.5): обрыв загрузки
// или звонка ради выигранных 30 мс раздражает сильнее, чем сами 30 мс.
func TestFasterSwitchKeepsConnections(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.start("A", "B")
	h.udpFlow()

	// A деградировал, B стал быстрее больше чем на tolerance (§6.4).
	h.prober.alive("A", 100*ms)
	h.prober.alive("B", 10*ms)
	h.sup.Force(health.TriggerInterface)

	sw := h.waitSwitch()
	if sw.To != "B" || sw.Reason != health.ReasonFaster {
		t.Fatalf("переключение %+v, ожидалось на B по причине faster", sw)
	}
	if sw.InterruptedConnections != 0 {
		t.Fatalf("разорвано соединений %d, ожидался ноль", sw.InterruptedConnections)
	}
	if n := h.sup.stack.Stats().NATSockets; n != 1 {
		t.Fatalf("сокетов после переключения %d, соединение обязано было выжить", n)
	}
	if got := h.out.Active(); got != "B" {
		t.Fatalf("движок остался на узле %q", got)
	}
}

// killActive гоняет узел до смерти его собственным расписанием и возвращает,
// сколько на это ушло времени по часам продукта.
//
// Часы крутит тест, а не они сами: §8.1 запрещает L1/L2 ждать по-настоящему, а
// бюджет §8.3 в пять секунд — это как раз то, что надо померить, а не выждать.
func (h *harness) killActive(id string) time.Duration {
	h.t.Helper()
	cfg := health.DefaultScheduleConfig()

	// Расписание дошло до своей пробы. Крутим на период пула, а не активного
	// яруса: срок узлу назначен стартовым прогоном, когда активного ещё не было
	// и оба узла лежали в пуле. Сюда же приходит трафик, увидевший отказ
	// (§6.15), — расписание в этом месте его не опережает.
	h.prober.drain()
	h.clk.Advance(cfg.Pool)
	h.prober.waitStart(h.t, id)
	start := h.clk.Now()

	// Дальше время идёт мелким шагом до самой смерти. Шаг фиксированной длины
	// не годится: rst отказывает сразу, blackhole ждёт таймаута, и путей до
	// смерти получается два разных. Крутим заведомо дольше бюджета — если узел
	// умирает позже, это обязан показать замер, а не зависший тест.
	const step = 100 * ms
	for i := 0; i < int(3*budget/step); i++ {
		if h.settled(id) {
			break
		}
		h.clk.Advance(step)
	}
	if !h.settled(id) {
		h.t.Fatalf("узел %s не признан мёртвым за %v", id, h.clk.Now().Sub(start))
	}
	return h.clk.Now().Sub(start)
}

// settled — узел признан мёртвым? Опрос на настоящих часах: прогон проб идёт в
// своей горутине, и решение приходит не в тот же миг, что прокрутка фейковых.
func (h *harness) settled(id string) bool {
	h.t.Helper()
	deadline := clock.System{}.After(20 * time.Millisecond)
	for {
		for _, nh := range h.sup.Nodes() {
			if nh.NodeID == id && nh.State == health.Dead {
				return true
			}
		}
		select {
		case <-deadline:
			return false
		case <-clock.System{}.After(time.Millisecond):
		}
	}
}

// budget — бюджет §8.3 на переключение: пять секунд от отказа узла.
const budget = 5 * time.Second

// T9. Живое соединение идёт через A, A становится blackhole. Узел признан
// мёртвым по таймауту проб, переключение приходит с причиной dead, и соединение
// получает ошибку — через мёртвый узел оно всё равно мертво (§5.5).
func TestT9BlackholeInterruptsConnectionWithinBudget(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.start("A", "B")
	h.udpFlow()

	h.prober.hang("A")
	elapsed := h.killActive("A")

	sw := h.waitSwitch()
	if sw.To != "B" || sw.Reason != health.ReasonDead {
		t.Fatalf("переключение %+v, ожидалось на B по причине dead", sw)
	}
	if sw.InterruptedConnections != 1 {
		t.Fatalf("разорвано соединений %d, ожидалось одно", sw.InterruptedConnections)
	}
	if elapsed > budget {
		t.Fatalf("переключение заняло %v, бюджет §8.3 — %v", elapsed, budget)
	}
}

// T11. Оба вида отказа узла — мгновенный (rst) и молчаливый (blackhole) — дают
// переключение в пределах бюджета. Blackhole проходит только при наличии
// таймаута пробы: без него ярус встаёт на зависшей пробе навсегда.
func TestT11BothFailureKindsSwitchWithinBudget(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(*harness)
	}{
		{"rst", func(h *harness) { h.prober.dead("A") }},
		{"blackhole", func(h *harness) { h.prober.hang("A") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "A", "B")
			h.start("A", "B")

			tc.fail(h)
			elapsed := h.killActive("A")

			sw := h.waitSwitch()
			if sw.To != "B" || sw.Reason != health.ReasonDead {
				t.Fatalf("переключение %+v, ожидалось на B по причине dead", sw)
			}
			if elapsed > budget {
				t.Fatalf("переключение заняло %v, бюджет §8.3 — %v", elapsed, budget)
			}
		})
	}
}

// Живых узлов не осталось — новый поток получает отказ, а не молчание (§5.6),
// и наружу не уходит ни одного соединения.
func TestNoAliveNodesRejectsNewFlows(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.start("A", "B")

	h.prober.dead("A")
	h.prober.dead("B")
	h.sup.Force(health.TriggerInterface)
	h.sup.Force(health.TriggerInterface)

	sw := h.waitSwitch()
	if sw.To != "" {
		t.Fatalf("выбран узел %q, ожидалось пусто: живых узлов нет", sw.To)
	}
	if st := h.sup.Status(); st.Phase != "failing" {
		t.Fatalf("фаза %q, ожидалась failing", st.Phase)
	}

	h.dev.Inject(packettest.TCPSyn(client, web, 42))
	got := h.dev.WaitEmitted(t, 1)
	tcp, ok := tcpOf(got[0])
	if !ok || tcp.Flags()&header.TCPFlagRst == 0 {
		t.Fatalf("ответом на SYN не был RST: % x", got[0])
	}
	if dialed := h.out.TCPDialed(); len(dialed) != 0 {
		t.Fatalf("fail-close выпустил соединения наружу: %v", dialed)
	}
}

// Смена активного узла сбрасывает кэш DNS (§5.7в): тот же домен через другой
// узел резолвится в другой адрес, и старая запись отправила бы трафик в CDN
// чужого региона.
//
// Наблюдаемая величина — походы к апстриму: попадание в кэш не порождает
// исходящего соединения вовсе.
func TestNodeSwitchFlushesDNSCache(t *testing.T) {
	h := newHarness(t, "A", "B")
	h.start("A", "B")

	query := dnsQuery(t, "example.com.")

	h.dev.Inject(packettest.UDP(client, router53, query))
	h.dev.WaitEmitted(t, 1)
	if n := len(h.out.TCPDialed()); n != 1 {
		t.Fatalf("походов к апстриму %d, ожидался один", n)
	}

	h.dev.Inject(packettest.UDP(client, router53, query))
	h.dev.WaitEmitted(t, 1)
	if n := len(h.out.TCPDialed()); n != 1 {
		t.Fatalf("походов к апстриму %d, второй запрос обязан был попасть в кэш", n)
	}

	h.prober.alive("A", 100*ms)
	h.prober.alive("B", 10*ms)
	h.sup.Force(health.TriggerInterface)
	if sw := h.waitSwitch(); sw.To != "B" {
		t.Fatalf("переключение %+v, ожидалось на B", sw)
	}

	h.dev.Inject(packettest.UDP(client, router53, query))
	h.dev.WaitEmitted(t, 1)
	if n := len(h.out.TCPDialed()); n != 2 {
		t.Fatalf("походов к апстриму %d, после смены узла кэш обязан быть пуст", n)
	}
}

// dnsQuery — запрос A-записи. Только A: §6.9 держит IPv6 заблокированным.
func dnsQuery(t *testing.T, name string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("StartQuestions: %v", err)
	}
	q := dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	if err := b.Question(q); err != nil {
		t.Fatalf("Question: %v", err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return msg
}

func tcpOf(p []byte) (header.TCP, bool) {
	ip := header.IPv4(p)
	if len(p) < header.IPv4MinimumSize || ip.Protocol() != uint8(header.TCPProtocolNumber) {
		return nil, false
	}
	payload := ip.Payload()
	if len(payload) < header.TCPMinimumSize {
		return nil, false
	}
	return header.TCP(payload), true
}
