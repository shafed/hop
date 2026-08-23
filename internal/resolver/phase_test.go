package resolver

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dnsmsg"
	"github.com/shafed/hop/internal/dnstest"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/phase"
)

// Проверки фазы трафика: fail-close (Р15, D9–D11, D17), удержание в стартовом
// окне (Р16, D12, D13), повтор при переключении (Р20, D16), сброс кэша по
// подписке и на краях bypass (Р25, D19, D20) и отсутствие вердиктов о живости
// узла (Р20, §6.15, D18).
//
// Фаза здесь не константа, а изменяемый источник: три из семи проверок
// отличаются от остальных ровно тем, что фаза меняется посреди прогона.

// phaseRig — резолвер, у которого фазу и события можно двигать из теста.
type phaseRig struct {
	r      *Resolver
	up     *dnstest.Upstream
	clk    *clock.Fake
	ph     *dnstest.Phase
	events chan health.SwitchEvent
}

func newPhaseRig(t *testing.T, initial phase.Traffic) *phaseRig {
	t.Helper()
	clk := clock.NewFake(time.Unix(0, 0))
	dclk := dnstest.NewClock(clk)
	up := dnstest.New(dclk)
	ph := dnstest.NewPhase(initial)
	events := dnstest.NewSwitchEvents()

	r, err := New(Config{
		Upstreams:  []netip.AddrPort{cacheAddr},
		DialUDP:    up.DialUDP,
		Dial:       up.Dial,
		DialDirect: up.DialDirect,
		Phase:      ph.Get,
		Events:     events,
		Clock:      dclk,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	return &phaseRig{r: r, up: up, clk: clk, ph: ph, events: events}
}

// setPhase меняет фазу и сообщает о ней резолверу — ровно так, как это делает
// связка: она зовёт refreshPhase на каждом переходе.
func (g *phaseRig) setPhase(v phase.Traffic) {
	g.ph.Set(v)
	g.r.PhaseChanged()
}

// askRaw — запрос без t.Fatalf на ошибке: проверкам fail-close нужен код
// ответа, а не признак «Query вернул ошибку».
func (g *phaseRig) askRaw(t *testing.T, name string) dnsmsg.Msg {
	t.Helper()
	raw, err := g.r.Query(
		dnstest.BuildQuery(dnstest.QueryOpts{ID: 7, Name: name, Type: dnstest.TypeA}),
		netip.AddrPort{}, netip.AddrPort{},
	)
	if err != nil {
		t.Fatalf("Query %s: %v", name, err)
	}
	return parseTest(t, raw)
}

// D9. Фаза failing: SERVFAIL, и наверх не ушло ни одного запроса.
//
// Охраняет dns_failclose. С выключенной политикой резолвер отвечает и без
// живых узлов: приложение получает адреса и виснет на connect — то есть
// молчание, запрещённое §5.6, сдвигается на шаг дальше вместо того, чтобы
// стать отказом.
func TestD9FailingPhaseAnswersServfail(t *testing.T) {
	g := newPhaseRig(t, phase.Failing)
	g.up.Program(cacheAddr, answeringA(300))

	got := g.askRaw(t, "example.com")

	if rc := got.Header.Rcode(); rc != dnsmsg.RcodeServFail {
		t.Fatalf("rcode = %d, хотим SERVFAIL", rc)
	}
	wantUpstream(t, g.up, 0, "fail-close не должен ходить наверх")
}

// D10. То же, но имя лежит в кэше с непротухшим TTL — всё равно SERVFAIL.
//
// Кэш в fail-close не отдаётся (Р15). Причина не в чистоте, а в проверяемости:
// иначе наблюдаемое поведение fail-close зависит от того, что успело осесть в
// кэше до отказа, и проверка становится функцией истории прогона.
func TestD10FailClosePreventsCacheHit(t *testing.T) {
	g := newPhaseRig(t, phase.Proxied)
	g.up.Program(cacheAddr, answeringA(300))

	if rc := g.askRaw(t, "example.com").Header.Rcode(); rc != dnsmsg.RcodeNoError {
		t.Fatalf("подготовка: rcode = %d, хотим NOERROR — запись должна лечь в кэш", rc)
	}
	if e, _ := g.r.cache.size(); e == 0 {
		t.Fatal("подготовка: кэш пуст, проверять нечего")
	}

	g.setPhase(phase.Failing)
	got := g.askRaw(t, "example.com")

	if rc := got.Header.Rcode(); rc != dnsmsg.RcodeServFail {
		t.Fatalf("rcode = %d, хотим SERVFAIL: попадание в кэш не должно пробивать fail-close", rc)
	}
	if got.Header.ANCount != 0 {
		t.Fatalf("в ответе %d записей — кэш всё-таки отдан", got.Header.ANCount)
	}
}

// D11. Код отказа именно SERVFAIL, не NXDOMAIN и не пустой NOERROR.
//
// NXDOMAIN означает «такого имени нет»: приложение и стаб ОС кэшируют это как
// факт о мире и продолжают верить в него после того, как узлы ожили. Пустой
// NOERROR — то же самое для одного типа записи.
func TestD11FailCloseCodeIsServfail(t *testing.T) {
	g := newPhaseRig(t, phase.Failing)
	got := g.askRaw(t, "example.com")

	switch rc := got.Header.Rcode(); rc {
	case dnsmsg.RcodeServFail:
	case dnsmsg.RcodeNXDomain:
		t.Fatal("NXDOMAIN: приложение запомнит «имени нет» и не переспросит, когда узлы оживут")
	case dnsmsg.RcodeNoError:
		t.Fatal("пустой NOERROR: то же самое для этого типа записи")
	default:
		t.Fatalf("rcode = %d, хотим SERVFAIL", rc)
	}
}

// D12. Фаза waiting, живой узел появился — запрос дождался и получил
// настоящий ответ.
//
// Охраняет dns_waiting_hold. С выключенной политикой приложение, стартовавшее
// одновременно с агентом, получает SERVFAIL там, где через секунду всё
// работало.
func TestD12WaitingHoldsUntilNodeAppears(t *testing.T) {
	g := newPhaseRig(t, phase.Waiting)
	g.up.Program(cacheAddr, answeringA(300))

	done := make(chan dnsmsg.Msg, 1)
	go func() {
		raw, err := g.r.Query(
			dnstest.BuildQuery(dnstest.QueryOpts{ID: 7, Name: "example.com", Type: dnstest.TypeA}),
			netip.AddrPort{}, netip.AddrPort{},
		)
		if err != nil {
			close(done)
			return
		}
		m, err := dnsmsg.Parse(raw)
		if err != nil {
			close(done)
			return
		}
		done <- m
	}()

	// Ждём, пока запрос действительно встанет в удержание: иначе смена фазы
	// случится раньше, и проверка выродится в «фаза сразу была proxied».
	if !dnstest.WaitObserved(2*time.Second, func() bool { return g.r.Snapshot().Held == 1 }) {
		t.Fatal("запрос не встал в удержание: Held не дошёл до 1")
	}

	g.setPhase(phase.Proxied)

	select {
	case got, ok := <-done:
		if !ok {
			t.Fatal("Query вернул ошибку вместо ответа")
		}
		if rc := got.Header.Rcode(); rc != dnsmsg.RcodeNoError {
			t.Fatalf("rcode = %d, хотим NOERROR: удержанный запрос должен был дождаться", rc)
		}
		if got.Header.ANCount == 0 {
			t.Fatal("ответ пуст: дождались, но резолв не случился")
		}
	// Сторожевой срок настоящими часами: модельные здесь не годятся — если
	// удержание не отпустило, двигать их некому, и тест повис бы навсегда.
	case <-time.After(5 * time.Second): //hop:realtime
		t.Fatal("удержанный запрос не отпустило после появления живого узла")
	}
}

// D13. Фаза waiting держится дольше 4 с — SERVFAIL на четвёртой секунде, а не
// ожидание до конца стартового бюджета §5.6.
//
// Тоже охраняет dns_waiting_hold, но с другой стороны: без потолка удержание
// длилось бы все 30 с §5.6, отнимая у стаба ОС право на собственный ретрай.
func TestD13WaitingGivesUpAtFourSeconds(t *testing.T) {
	g := newPhaseRig(t, phase.Waiting)

	done := make(chan dnsmsg.Msg, 1)
	go func() {
		raw, err := g.r.Query(
			dnstest.BuildQuery(dnstest.QueryOpts{ID: 7, Name: "example.com", Type: dnstest.TypeA}),
			netip.AddrPort{}, netip.AddrPort{},
		)
		if err != nil {
			close(done)
			return
		}
		m, err := dnsmsg.Parse(raw)
		if err != nil {
			close(done)
			return
		}
		done <- m
	}()

	if !dnstest.WaitObserved(2*time.Second, func() bool { return g.r.Snapshot().Held == 1 }) {
		t.Fatal("запрос не встал в удержание: Held не дошёл до 1")
	}

	// Часы двигаются только после того, как удержание встало на свой срок:
	// иначе Advance пройдёт мимо ещё не заведённого ожидания.
	g.clk.Advance(WaitingHold)

	select {
	case got, ok := <-done:
		if !ok {
			t.Fatal("Query вернул ошибку вместо SERVFAIL")
		}
		if rc := got.Header.Rcode(); rc != dnsmsg.RcodeServFail {
			t.Fatalf("rcode = %d, хотим SERVFAIL по истечении удержания", rc)
		}
	// Сторожевой срок настоящими часами, по той же причине, что выше.
	case <-time.After(5 * time.Second): //hop:realtime
		t.Fatal("удержание не кончилось на четвёртой секунде модельного времени")
	}
	wantUpstream(t, g.up, 0, "удержание истекло, живого узла так и не было")
}

// D16. Активный узел умер посреди резолва, переключение состоялось — один
// повтор через нового активного, и ответ доехал.
//
// Охраняет dns_switch_retry. С выключенной политикой каждое переключение
// стоит SERVFAIL тем запросам, которые как раз летели.
//
// Переключение подаётся изнутри поведения апстрима: так момент события точно
// приходится на время резолва, а не «где-то рядом», и проверка перестаёт
// зависеть от того, кто кого опередил.
func TestD16SwitchMidResolveRetriesOnce(t *testing.T) {
	g := newPhaseRig(t, phase.Proxied)

	ip := netip.MustParseAddr("203.0.113.9")
	first := true
	g.up.Program(cacheAddr, dnstest.Behavior{Func: func(query []byte) []byte {
		q, err := dnsmsg.Parse(query)
		if err != nil {
			return nil
		}
		if first {
			first = false
			gen := g.r.Snapshot().Generation
			g.events <- health.SwitchEvent{To: "b", Reason: health.ReasonDead}
			if !dnstest.WaitObserved(2*time.Second, func() bool {
				return g.r.Snapshot().Generation > gen
			}) {
				return nil
			}
			// Прежний узел умер: ответа от него не будет.
			return []byte{0x00}
		}
		return dnstest.ResponseA(q.Header.ID, q.Question.Name.String(), 300, ip)
	}})

	got := g.askRaw(t, "example.com")

	if rc := got.Header.Rcode(); rc != dnsmsg.RcodeNoError {
		t.Fatalf("rcode = %d, хотим NOERROR: повтор через нового активного должен был доехать", rc)
	}
	wantUpstream(t, g.up, 2, "один повтор, а не ноль и не два")
}

// D17. То же, но живых узлов не осталось — немедленный SERVFAIL, без
// ожидания бюджета.
func TestD17NoLiveNodesAfterSwitchFailsFast(t *testing.T) {
	g := newPhaseRig(t, phase.Proxied)

	first := true
	g.up.Program(cacheAddr, dnstest.Behavior{Func: func([]byte) []byte {
		if first {
			first = false
			gen := g.r.Snapshot().Generation
			g.events <- health.SwitchEvent{To: "", Reason: health.ReasonDead}
			dnstest.WaitObserved(2*time.Second, func() bool {
				return g.r.Snapshot().Generation > gen
			})
			g.ph.Set(phase.Failing)
			return []byte{0x00}
		}
		return nil
	}})

	start := time.Now() //hop:realtime
	got := g.askRaw(t, "example.com")
	elapsed := time.Since(start) //hop:realtime

	if rc := got.Header.Rcode(); rc != dnsmsg.RcodeServFail {
		t.Fatalf("rcode = %d, хотим SERVFAIL", rc)
	}
	// Бюджет клиента считается модельными часами, которые здесь не двигались
	// вовсе. Настоящее время меряется только чтобы поймать настоящее зависание.
	if elapsed > 5*time.Second { //hop:realtime
		t.Fatalf("отказ занял %v: похоже на ожидание, а не на немедленный отказ", elapsed)
	}
	wantUpstream(t, g.up, 1, "повтора быть не должно: живых узлов не осталось")
}

// D18. Резолвер никогда не вызывает health.ReportFailure.
//
// Единственная проверка регистра, смотрящая на чужой модуль, и она
// обязательна: резолвер видит отказы чаще всех в системе, и соблазн засчитать
// их узлу возникает ровно здесь. §6.15 говорит, что отказ целевого хоста узел
// не убивает, а молчащий апстрим — это отказ целевого хоста; отказ дозвона до
// самого узла классифицирует перехваченный диалер движка сам, и второй
// источник вердиктов означал бы второй ответ на тот же вопрос.
//
// Проверяется по исходникам, а не по фейку: фейк доказал бы лишь то, что на
// одном прогоне вызова не случилось, а утверждение — про все пути кода.
func TestD18ResolverNeverReportsNodeFailure(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("разбор пакета: %v", err)
	}
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "ReportFailure" {
					t.Errorf("%s: резолвер вызывает ReportFailure — §6.15 запрещает ему судить узел",
						fset.Position(sel.Pos()))
				}
				return true
			})
		}
	}
}

// D19. Событие переключения: Generation выросла на 1, кэш пуст, и сброс
// сделал сам резолвер по подписке.
//
// Охраняет dns_cache_flush_on_switch. Отделена от T14 намеренно: T14 зелен и
// в реализации без кэша вообще, а Generation доказывает, что сброс сделал
// именно резолвер, а не связка вызовом.
func TestD19SwitchBumpsGeneration(t *testing.T) {
	g := newPhaseRig(t, phase.Proxied)
	g.up.Program(cacheAddr, answeringA(300))

	g.askRaw(t, "example.com")
	if e, _ := g.r.cache.size(); e == 0 {
		t.Fatal("подготовка: кэш пуст, сбрасывать нечего")
	}
	before := g.r.Snapshot().Generation

	g.events <- health.SwitchEvent{To: "b", Reason: health.ReasonDead}

	if !dnstest.WaitObserved(2*time.Second, func() bool {
		return g.r.Snapshot().Generation == before+1
	}) {
		t.Fatalf("Generation осталась %d: резолвер не сбросил кэш по подписке",
			g.r.Snapshot().Generation)
	}
	if s := g.r.Snapshot(); s.Entries != 0 {
		t.Fatalf("после сброса в кэше %d записей", s.Entries)
	}
}

// D20. Вход в bypass и выход из него — два сброса (Р25).
//
// §5.7(в) называет только смену узла, но адрес, полученный напрямую,
// указывает на CDN нашего настоящего региона, и после возврата в туннель
// трафик пойдёт туда же — то есть выключение bypass не вернуло бы защиту
// полностью.
func TestD20BypassEdgesFlushTwice(t *testing.T) {
	g := newPhaseRig(t, phase.Proxied)
	before := g.r.Snapshot().Generation

	g.setPhase(phase.Bypass)
	g.setPhase(phase.Proxied)

	if got := g.r.Snapshot().Generation; got != before+2 {
		t.Fatalf("Generation = %d, хотим %d: край bypass обязан сбрасывать кэш в обе стороны",
			got, before+2)
	}
}

// Смена фазы, не пересекающая край bypass, кэш не трогает: иначе «сброс на
// каждом чихе» выглядел бы как выполненный Р25, ничего не гарантируя.
func TestPhaseChangeWithoutBypassEdgeKeepsCache(t *testing.T) {
	g := newPhaseRig(t, phase.Proxied)
	before := g.r.Snapshot().Generation

	g.setPhase(phase.Waiting)
	g.setPhase(phase.Failing)
	g.setPhase(phase.Proxied)

	if got := g.r.Snapshot().Generation; got != before {
		t.Fatalf("Generation = %d, хотим %d: край bypass не пересекался", got, before)
	}
}
