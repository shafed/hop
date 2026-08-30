package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/shafed/hop/internal/agent"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/tunnel"
)

// Глаголы §5.9 поверх сокета §3.3 — W63, W64.
//
// Проверяется CLI, а не связка: связка проверена в internal/agent (W60–W62), и
// повторять её здесь значило бы поднимать Xray ради разбора аргументов.
// Поэтому по ту сторону настоящего сокета стоит заглушка связки — но сокет,
// протокол и разбор ответа настоящие.

// stubAgent — связка за границей ClientAPI.
//
// Замок не для порядка, а для гонок: глагол выполняется в горутине сервера, а
// проверяется в горутине теста, и happens-before между ними идёт через
// unix-сокет — то есть через ядро, которого детектор гонок не видит.
type stubAgent struct {
	snap agent.Snapshot
	hist []health.SwitchEvent

	mu sync.Mutex
	// calls — что глаголы дозвались. Строками, потому что проверяется факт
	// вызова и его аргумент, а не порядок обращений к полям.
	calls []string
}

func (s *stubAgent) called(what string) {
	s.mu.Lock()
	s.calls = append(s.calls, what)
	s.mu.Unlock()
}

// lastCall — последний дозвавшийся глагол; пусто, если ни одного не было.
func (s *stubAgent) lastCall() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		return ""
	}
	return s.calls[len(s.calls)-1]
}

func (s *stubAgent) Snapshot() agent.Snapshot { return s.snap }
func (s *stubAgent) History() []health.SwitchEvent {
	return s.hist
}

func (s *stubAgent) Events(int) ([]health.SwitchEvent, <-chan health.SwitchEvent) {
	return s.hist, make(chan health.SwitchEvent)
}
func (s *stubAgent) Unsubscribe(<-chan health.SwitchEvent) {}

func (s *stubAgent) Up() error            { s.called("up"); return nil }
func (s *stubAgent) Down() error          { s.called("down"); return nil }
func (s *stubAgent) Bypass(on bool) error { s.called(boolCall("bypass", on)); return nil }
func (s *stubAgent) Auto(on bool)         { s.called(boolCall("auto", on)) }
func (s *stubAgent) Pin(id string) error  { s.called("pin " + id); return nil }
func boolCall(v string, on bool) string {
	if on {
		return v + " on"
	}
	return v + " off"
}

// serveStub поднимает сокет §3.3 с заглушкой по ту сторону и отдаёт путь.
func serveStub(t *testing.T, api agent.ClientAPI) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "agent.sock")
	l, err := ipc.Listen(path, -1)
	if err != nil {
		t.Fatalf("сокет клиентов не открылся: %v", err)
	}
	srv := agent.NewClientServer(api, nil)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() {
		_ = l.Close()
		srv.Close()
	})
	return path
}

// TestW63StatusAsksTheAgentAndAnswersFailCloseWithThree — `hop status` берёт
// картину у связки, а fail-close отдаёт кодом 3 (§1/С5, §1/С6).
//
// Обе половины утверждения новые. До сокета §3.3 `status` знал только фазу
// сервиса — «фаза трафика и активный узел неизвестны» стояло у него в выводе
// прямым текстом, — а третий код возврата был наблюдаем только на `probe`,
// потому что живость знает связка. §1/С6 требует именно от `status`: «status
// показывает no healthy nodes и возвращает код 3».
func TestW63StatusAsksTheAgentAndAnswersFailCloseWithThree(t *testing.T) {
	proxied := &stubAgent{snap: agent.Snapshot{
		Tunnel:  tunnel.Up,
		Traffic: agent.PhaseProxied,
		Active:  "n1",
		Auto:    true,
		Nodes: []health.NodeHealth{
			{NodeID: "n1", State: health.Alive},
			{NodeID: "n2", State: health.Dead},
		},
	}}
	sock := serveStub(t, proxied)

	c, out, errs := testCLI(t)
	if code := c.dispatch([]string{"status", "-client-socket", sock}); code != 0 {
		t.Fatalf("`status` при живом узле дал %d, ожидался 0: %s", code, errs.String())
	}
	human := out.String()
	for _, want := range []string{"proxied", "n1", "1 из 2"} {
		if !strings.Contains(human, want) {
			t.Errorf("в выводе нет %q — картину §1/С5 связка отдала, а команда не показала:\n%s", want, human)
		}
	}

	// Машинная половина той же картины: половина сервиса пуста, половина
	// связки заполнена. Это и есть «кто ответил», а не «что показать».
	c, out, _ = testCLI(t)
	if code := c.dispatch([]string{"status", "-client-socket", sock, "--json"}); code != 0 {
		t.Fatalf("`status --json` дал %d", code)
	}
	var v struct {
		Tunnel *json.RawMessage `json:"tunnel"`
		Agent  *struct {
			Traffic string `json:"traffic"`
			Active  string `json:"active"`
			Alive   int    `json:"alive"`
		} `json:"agent"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("`status --json` выдал не JSON (%v):\n%s", err, out.String())
	}
	if v.Tunnel != nil {
		t.Error("ответила связка, а половина сервиса непуста: клиент сходил к привилегированной границе зря (§3.3)")
	}
	if v.Agent == nil || v.Agent.Traffic != "proxied" || v.Agent.Active != "n1" || v.Agent.Alive != 1 {
		t.Errorf("половина связки не та: %+v", v.Agent)
	}

	// Fail-close — код 3, и вывод при этом печатается: мониторинг читает код,
	// человек читает строки.
	failing := &stubAgent{snap: agent.Snapshot{
		Tunnel:  tunnel.Up,
		Traffic: agent.PhaseFailing,
		Auto:    true,
		Nodes:   []health.NodeHealth{{NodeID: "n1", State: health.Dead}},
	}}
	c, out, _ = testCLI(t)
	if code := c.dispatch([]string{"status", "-client-socket", serveStub(t, failing)}); code != 3 {
		t.Errorf("`status` без живых узлов дал %d, ожидалась 3 (§1/С6)", code)
	}
	if out.Len() == 0 {
		t.Error("код 3 пришёл без вывода: человеку нечего прочитать")
	}

	// Ни связки, ни сервиса — код 2, и отказ называет обоих: «фоновой половины
	// нет» с одним путём в тексте не говорит, какой именно половины.
	c, _, errs = testCLI(t)
	none := filepath.Join(t.TempDir(), "нет.sock")
	if code := c.dispatch([]string{"status", "-client-socket", none, "-socket", none}); code != 2 {
		t.Errorf("`status` без связки и сервиса дал %d, ожидалась 2", code)
	}
	if !strings.Contains(errs.String(), "связка") || !strings.Contains(errs.String(), "сервис") {
		t.Errorf("отказ не назвал обоих адресатов:\n%s", errs.String())
	}
}

// TestW63ControlVerbsGoThroughTheSocket — управляющие глаголы §5.9 доходят до
// связки, а не выполняются в клиенте.
//
// «CLI — тонкий клиент, вся логика в агенте» (§3.3) — утверждение о том, ГДЕ
// принимается решение, и проверяется оно единственным способом: тем, что по ту
// сторону сокета зов состоялся.
func TestW63ControlVerbsGoThroughTheSocket(t *testing.T) {
	st := &stubAgent{snap: agent.Snapshot{Tunnel: tunnel.Up, Traffic: agent.PhaseProxied, Auto: true}}
	sock := serveStub(t, st)

	for _, tc := range []struct {
		args []string
		want string
	}{
		{args: []string{"up"}, want: "up"},
		{args: []string{"up", "-node", "n7"}, want: "pin n7"},
		{args: []string{"down"}, want: "down"},
		{args: []string{"bypass", "on"}, want: "bypass on"},
		{args: []string{"bypass", "off"}, want: "bypass off"},
		{args: []string{"auto", "on"}, want: "auto on"},
		{args: []string{"auto", "off"}, want: "auto off"},
	} {
		c, out, errs := testCLI(t)
		// Флаги перед аргументом: `flag.FlagSet` прекращает разбор на первом
		// позиционном, и это ровно та причина, по которой checkArgs
		// подсказывает про порядок.
		args := append([]string{tc.args[0], "-client-socket", sock}, tc.args[1:]...)
		if code := c.dispatch(args); code != 0 {
			t.Fatalf("`hop %s` дал %d: %s", strings.Join(tc.args, " "), code, errs.String())
		}
		if out.Len() == 0 {
			t.Errorf("`hop %s` промолчал: сделанное действие обязано быть названо", strings.Join(tc.args, " "))
		}
		if got := st.lastCall(); got != tc.want {
			t.Errorf("`hop %s` дозвался %q, ожидалось %q", strings.Join(tc.args, " "), got, tc.want)
		}
	}

	// Без связки — код 2 у каждого: глагол, который умеет только связка, без
	// неё отказывает, а не делает вид.
	none := filepath.Join(t.TempDir(), "нет.sock")
	for _, args := range [][]string{{"up"}, {"events"}, {"bypass", "on"}, {"auto", "off"}} {
		c, _, _ := testCLI(t)
		full := append([]string{args[0], "-client-socket", none}, args[1:]...)
		if code := c.dispatch(full); code != 2 {
			t.Errorf("`hop %s` без связки дал %d, ожидалась 2", strings.Join(args, " "), code)
		}
	}
}

// TestW63EventsReadTheRingThroughTheSocket — `hop events` печатает кольцо
// связки, а `--json` разбирается.
func TestW63EventsReadTheRingThroughTheSocket(t *testing.T) {
	st := &stubAgent{hist: []health.SwitchEvent{
		{To: "n1", Reason: health.ReasonDead, Interrupted: 2},
		{From: "n1", To: "n2", Reason: health.ReasonFaster},
	}}
	sock := serveStub(t, st)

	c, out, errs := testCLI(t)
	if code := c.dispatch([]string{"events", "-client-socket", sock}); code != 0 {
		t.Fatalf("`events` дал %d: %s", code, errs.String())
	}
	if !strings.Contains(out.String(), "n2") || !strings.Contains(out.String(), "faster") {
		t.Errorf("журнал не показал событий:\n%s", out.String())
	}

	c, out, _ = testCLI(t)
	if code := c.dispatch([]string{"events", "-client-socket", sock, "--json"}); code != 0 {
		t.Fatalf("`events --json` дал %d", code)
	}
	var v struct {
		Events []struct {
			To     string `json:"to"`
			Reason string `json:"reason"`
		} `json:"events"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("`events --json` выдал не JSON (%v):\n%s", err, out.String())
	}
	if len(v.Events) != 2 || v.Events[1].To != "n2" || v.Events[1].Reason != "faster" {
		t.Errorf("схема журнала не та: %+v", v.Events)
	}
}

// TestW64ExtraArgumentIsRefused — лишний позиционный аргумент отвергается.
//
// Находка приёмки прошлого прохода, воспроизведённая живым прогоном:
// `hop nodes лишнее --json` возвращал 0 и печатал человеческую таблицу.
// Складываются две вещи, и обе тихие. Безаргументный обработчик игнорировал
// остаток `fs.Args()`, а `flag.FlagSet` прекращает разбор флагов на первом
// позиционном аргументе — то есть `--json` не просто не сработал, он даже не
// был разобран как неизвестный флаг.
//
// Проверяется централизованно: кардинальность стоит в таблице команд, поэтому
// достаточно взять по одному представителю каждого случая.
func TestW64ExtraArgumentIsRefused(t *testing.T) {
	withTestStore(t)

	// Живое воспроизведение находки приёмки целиком: лишний аргумент и флаг
	// за ним. Ноль в ответ на это и был дефектом.
	c, out, errs := testCLI(t)
	if code := c.dispatch([]string{"nodes", "лишнее", "--json"}); code == 0 {
		t.Errorf("`hop nodes лишнее --json` дал 0: кривой ввод выглядит как выполненная команда\n%s", out.String())
	}
	if out.Len() != 0 {
		t.Errorf("отвергнутая команда всё же напечатала вывод:\n%s", out.String())
	}
	// Отказ обязан назвать и то, что флаг НЕ разобран: иначе «--json тут не
	// бывает» — вывод, который пользователь сделает сам и который неверен.
	if !strings.Contains(errs.String(), "--json") || !strings.Contains(errs.String(), "флаги идут перед аргументами") {
		t.Errorf("отказ не объяснил, что стало с флагом:\n%s", errs.String())
	}

	// Тот же лишний аргумент без флага — отказ по кардинальности.
	c, out, errs = testCLI(t)
	if code := c.dispatch([]string{"nodes", "лишнее"}); code == 0 {
		t.Errorf("`hop nodes лишнее` дал 0\n%s", out.String())
	}
	if !strings.Contains(errs.String(), "не берёт аргументов") {
		t.Errorf("отказ не назвал причины:\n%s", errs.String())
	}

	// Один аргумент, дано два.
	c, _, errs = testCLI(t)
	if code := c.dispatch([]string{"node", "rm", "один", "второй"}); code == 0 {
		t.Error("`hop node rm` с двумя id дал 0")
	}
	if !strings.Contains(errs.String(), "hop node rm <id>") {
		t.Errorf("отказ не назвал формы команды:\n%s", errs.String())
	}

	// Один аргумент, не дано ни одного.
	c, _, _ = testCLI(t)
	if code := c.dispatch([]string{"bypass"}); code == 0 {
		t.Error("`hop bypass` без on|off дал 0")
	}

	// Аргумент есть, но не тот: on|off — замкнутое перечисление.
	c, _, errs = testCLI(t)
	if code := c.dispatch([]string{"bypass", "включи"}); code == 0 {
		t.Error("`hop bypass включи` дал 0")
	}
	if !strings.Contains(errs.String(), "on") {
		t.Errorf("отказ не назвал допустимых значений:\n%s", errs.String())
	}

	// Положительный контроль: правильная форма по-прежнему проходит. Без него
	// проверка была бы зелёной и у команды, которая отвергает всё подряд.
	c, _, errs = testCLI(t)
	if code := c.dispatch([]string{"nodes", "--json"}); code != 0 {
		t.Fatalf("`hop nodes --json` дал %d: %s", code, errs.String())
	}
	var buf bytes.Buffer
	_ = buf
}
