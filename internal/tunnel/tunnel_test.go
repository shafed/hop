package tunnel

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
)

// fakeNet — Net без единого системного вызова. Записывает порядок операций:
// §6.2 — утверждение именно про порядок и про то, что в orphaned интерфейс не
// трогают.
type fakeNet struct {
	log     []string
	devices int
	upErr   error
	cur     *fakeDevice
}

type fakeDevice struct {
	ref    string
	closed bool
}

func (d *fakeDevice) Ref() string { return d.ref }
func (d *fakeDevice) Close() error {
	d.closed = true
	return nil
}

func (n *fakeNet) Up(p Params) (Device, error) {
	if n.upErr != nil {
		return nil, n.upErr
	}
	n.devices++
	n.cur = &fakeDevice{ref: fmt.Sprintf("dev-%d", n.devices)}
	n.log = append(n.log, "up")
	return n.cur, nil
}

func (n *fakeNet) Reject() error  { n.log = append(n.log, "reject"); return nil }
func (n *fakeNet) Restore() error { n.log = append(n.log, "restore"); return nil }
func (n *fakeNet) Down() error    { n.log = append(n.log, "down"); return nil }

func (n *fakeNet) ops() string { return strings.Join(n.log, ",") }

const owner = "uid:1000"

var epoch = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

func newMachine(t *testing.T) (*Machine, *clock.Fake, *fakeNet) {
	t.Helper()
	clk := clock.NewFake(epoch)
	net := &fakeNet{}
	return New(clk, net, DefaultConfig()), clk, net
}

func startUp(t *testing.T, m *Machine) Handle {
	t.Helper()
	h, err := m.Start(Params{Name: "hop0", MTU: 1400, Addr: "10.255.0.1/24", Table: 100}, owner)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return h
}

// TestEdgeInstallsReject — охраняющий тест политики orphan_reject.
//
// Ребро в orphaned обязано подменить маршруты на reject немедленно, до всякого
// таймера. Без политики окно молчаливое: интерфейс жив, читателя нет, пакеты
// дропаются вопреки §5.6.
func TestEdgeInstallsReject(t *testing.T) {
	m, clk, net := newMachine(t)
	startUp(t, m)

	m.AgentGone(ReasonClosed)

	if got := m.State().Phase; got != Orphaned {
		t.Fatalf("phase = %s, ожидалось orphaned", got)
	}
	if net.ops() != "up,reject" {
		t.Fatalf("операции = %q, ожидалось up,reject", net.ops())
	}
	// Ребро стоит 0 мс: часы не двигались ни на наносекунду.
	if !clk.Now().Equal(epoch) {
		t.Fatalf("ребро сдвинуло часы на %v — оно должно быть мгновенным", clk.Now().Sub(epoch))
	}
	// Интерфейс не трогали: это то, что делает T24 возможным.
	if net.cur.closed {
		t.Fatal("устройство закрыто на ребре — в orphaned интерфейс не трогают (§6.2)")
	}
}

// TestAttachWithinDeadline — охраняющий тест политики orphan_deadline (T24 в
// логике). Агент вернулся внутри окна: тот же дескриптор, туннельные маршруты
// на месте, интерфейс не пересоздавался.
func TestAttachWithinDeadline(t *testing.T) {
	m, clk, net := newMachine(t)
	h := startUp(t, m)

	m.AgentGone(ReasonClosed)
	clk.Advance(10 * time.Second) // внутри 15 с
	m.Poll()

	got, err := m.Attach(h.Token, owner)
	if err != nil {
		t.Fatalf("Attach внутри дедлайна: %v", err)
	}
	if got.Device.Ref() != h.Device.Ref() {
		t.Fatalf("дескриптор %s, ожидался тот же %s", got.Device.Ref(), h.Device.Ref())
	}
	if net.devices != 1 {
		t.Fatalf("интерфейс создавался %d раз, ожидался 1", net.devices)
	}
	if net.ops() != "up,reject,restore" {
		t.Fatalf("операции = %q, ожидалось up,reject,restore", net.ops())
	}
	if m.State().Phase != Up {
		t.Fatalf("phase = %s, ожидалось up", m.State().Phase)
	}
}

// Дедлайн истёк — полный teardown, реаттачиться уже некуда (T23-slow в логике).
func TestDeadlineTearsDown(t *testing.T) {
	m, clk, net := newMachine(t)
	h := startUp(t, m)

	m.AgentGone(ReasonClosed)
	clk.Advance(15 * time.Second)
	m.Poll()

	if got := m.State().Phase; got != Down {
		t.Fatalf("phase = %s, ожидалось down", got)
	}
	if net.ops() != "up,reject,down" {
		t.Fatalf("операции = %q, ожидалось up,reject,down", net.ops())
	}
	if !net.cur.closed {
		t.Fatal("дескриптор не закрыт после teardown")
	}
	if _, err := m.Attach(h.Token, owner); err == nil {
		t.Fatal("Attach прошёл после истечения дедлайна")
	}
}

// Дедлайн считается от ребра. Мусорные попытки Attach его не двигают — иначе
// непривилегированный локальный процесс держит машину в отказе бесконечно.
func TestFailedAttachDoesNotExtendDeadline(t *testing.T) {
	m, clk, _ := newMachine(t)
	startUp(t, m)
	m.AgentGone(ReasonClosed)

	// 14 попыток по секунде: если бы каждая продлевала окно, к 15-й секунде
	// машина была бы всё ещё orphaned.
	for i := 0; i < 14; i++ {
		clk.Advance(time.Second)
		if _, err := m.Attach(Token("мусор"), owner); err == nil {
			t.Fatal("Attach с чужим токеном прошёл")
		}
	}
	if got := m.FailedAttempts(); got != 14 {
		t.Fatalf("неудачных попыток %d, ожидалось 14", got)
	}
	if got := m.State().Phase; got != Orphaned {
		t.Fatalf("на 14-й секунде phase = %s, ожидалось orphaned", got)
	}

	clk.Advance(time.Second) // ровно 15 с от ребра
	m.Poll()
	if got := m.State().Phase; got != Down {
		t.Fatalf("phase = %s, ожидалось down: дедлайн считается от ребра", got)
	}
}

// Токен проверяется вместе с владельцем: сокет доступен только владельцу, но и
// внутри одного пользователя чужой дескриптор перехватывать нельзя.
func TestAttachChecksTokenAndOwner(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token func(Token) Token
		owner string
		want  error
	}{
		{"чужой токен", func(Token) Token { return NewToken() }, owner, ErrBadToken},
		{"чужой владелец", func(t Token) Token { return t }, "uid:1001", ErrWrongOwner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := newMachine(t)
			h := startUp(t, m)
			m.AgentGone(ReasonClosed)

			_, err := m.Attach(tc.token(h.Token), tc.owner)
			if err != tc.want {
				t.Fatalf("ошибка = %v, ожидалась %v", err, tc.want)
			}
			if m.State().Phase != Orphaned {
				t.Fatalf("после отказа phase = %s, ожидалось orphaned", m.State().Phase)
			}
		})
	}
}

// Heartbeat после §6.2 — не детектор смерти процесса, а детектор заклинившего
// живого агента: сокет не закрылся, ребро само не сработало.
func TestHeartbeatMissDrivesSameEdge(t *testing.T) {
	m, clk, net := newMachine(t)
	startUp(t, m)

	for i := 0; i < 10; i++ {
		clk.Advance(900 * time.Millisecond)
		m.Heartbeat()
	}
	if got := m.State().Phase; got != Up {
		t.Fatalf("при живом heartbeat phase = %s, ожидалось up", got)
	}

	clk.Advance(3 * time.Second) // heartbeat_miss × heartbeat
	m.Poll()

	st := m.State()
	if st.Phase != Orphaned {
		t.Fatalf("phase = %s, ожидалось orphaned", st.Phase)
	}
	if st.DetachReason != ReasonHeartbeat {
		t.Fatalf("причина = %s, ожидалась heartbeat", st.DetachReason)
	}
	if net.ops() != "up,reject" {
		t.Fatalf("операции = %q: оба сигнала обязаны кормить одно ребро", net.ops())
	}
}

// Detach(reason=restart) — то же ребро, но причина видна в Status.
func TestDetachRecordsReason(t *testing.T) {
	m, _, net := newMachine(t)
	h := startUp(t, m)

	m.Detach(ReasonRestart)
	st := m.State()
	if st.Phase != Orphaned || st.DetachReason != ReasonRestart {
		t.Fatalf("состояние = %+v, ожидалось orphaned/restart", st)
	}
	if net.ops() != "up,reject" {
		t.Fatalf("операции = %q: плановый уход отказывает так же, а не молчит", net.ops())
	}
	if _, err := m.Attach(h.Token, owner); err != nil {
		t.Fatalf("реаттач после планового Detach: %v", err)
	}
}

// OrphanLeft — то, что показывает status: сколько осталось до teardown.
func TestStateReportsOrphanLeft(t *testing.T) {
	m, clk, _ := newMachine(t)
	startUp(t, m)
	m.AgentGone(ReasonClosed)

	clk.Advance(4 * time.Second)
	if got := m.State().OrphanLeft; got != 11*time.Second {
		t.Fatalf("осталось %v, ожидалось 11s", got)
	}
}

// Stop из orphaned — полный teardown, а не зависание до дедлайна.
func TestStopFromOrphaned(t *testing.T) {
	m, _, net := newMachine(t)
	startUp(t, m)
	m.AgentGone(ReasonClosed)

	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if m.State().Phase != Down || net.ops() != "up,reject,down" {
		t.Fatalf("phase = %s, операции = %q", m.State().Phase, net.ops())
	}
}

// §6.14: секрет не попадает в логи ни на уровне debug. Самый частый путь туда —
// %v по структуре, случайно оказавшейся в аргументах логгера.
func TestTokenNeverFormats(t *testing.T) {
	tok := NewToken()
	secret := string(tok)

	for _, s := range []string{
		fmt.Sprintf("%v", tok),
		fmt.Sprintf("%s", tok),
		fmt.Sprintf("%q", tok),
		fmt.Sprintf("%#v", tok),
		fmt.Sprintf("%+v", Handle{Token: tok}),
		fmt.Sprintf("%v", struct{ H Handle }{Handle{Token: tok}}),
	} {
		if strings.Contains(s, secret) {
			t.Fatalf("токен утёк в форматированный вывод: %s", s)
		}
	}
	if fmt.Sprintf("%v", tok) != Redacted {
		t.Fatalf("вместо токена ожидалась заглушка %s", Redacted)
	}
	// А явное преобразование обязано работать: на нём стоит сравнение.
	if secret == Redacted || secret == "" {
		t.Fatal("string(Token) должен давать настоящее значение")
	}
}
