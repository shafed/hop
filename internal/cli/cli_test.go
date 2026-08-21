package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/events"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/tunnel"
)

// stubAgent — агент без датаплейна: команды §5.9 проверяются без TUN, без сети
// и без root (§8.1).
type stubAgent struct {
	status events.Status
	nodes  []events.NodeInfo
	auto   bool
	bypass bool
	pinned string

	groups      []events.GroupInfo
	subURL      string
	subName     string
	subUpdated  string
	subRemoved  string
	nodeLink    string
	nodeDropped string
	fromGroup   string
	fail        error
}

func (a *stubAgent) Status() events.Status    { return a.status }
func (a *stubAgent) Nodes() []events.NodeInfo { return a.nodes }
func (a *stubAgent) Pin(id string) error      { a.pinned = id; return nil }
func (a *stubAgent) Auto(on bool)             { a.auto = on }
func (a *stubAgent) Bypass(on bool)           { a.bypass = on }
func (a *stubAgent) Ping(id string) (events.NodeInfo, error) {
	return events.NodeInfo{ID: id, Name: "Токио", State: health.Alive, RTTms: 42}, nil
}

// Состав узлов (§С2) правит агент, а не клиент: под системным пользователем
// `hop` до стора агента клиент не достаёт (§3.3, §6.8). Двойник запоминает,
// что до него доехало, и отдаёт заранее заготовленный ответ.
func (a *stubAgent) SubAdd(url, name string) (events.SubResult, error) {
	a.subURL, a.subName = url, name
	if a.fail != nil {
		return events.SubResult{}, a.fail
	}
	return events.SubResult{
		GroupID: "ee8e3a30", GroupName: "sub.example", Added: 2, Unsupported: 1,
	}, nil
}

func (a *stubAgent) SubUpdate(id string) ([]events.SubResult, error) {
	a.subUpdated = id
	if a.fail != nil {
		return nil, a.fail
	}
	return []events.SubResult{{GroupID: "ee8e3a30", GroupName: "sub.example", Kept: 2}}, nil
}

func (a *stubAgent) SubRemove(id string) error   { a.subRemoved = id; return a.fail }
func (a *stubAgent) SubList() []events.GroupInfo { return a.groups }

func (a *stubAgent) NodeAdd(link string) (events.NodeInfo, error) {
	a.nodeLink = link
	if a.fail != nil {
		return events.NodeInfo{}, a.fail
	}
	return events.NodeInfo{ID: "n9", Name: "Прага", Group: "manual", Supported: true}, nil
}

func (a *stubAgent) NodeRemove(id string) (string, error) {
	a.nodeDropped = id
	return a.fromGroup, a.fail
}

// env собирает окружение команды. Сокет агента заведомо не существует, пока
// тест не позвал serveAgent: команды обязаны это переживать.
func env(t *testing.T) (Env, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	return Env{
		Out:     &out,
		Err:     &errOut,
		Socket:  filepath.Join(dir, "agent.sock"),
		Service: filepath.Join(dir, "service.sock"),
	}, &out, &errOut
}

func serveAgent(t *testing.T, e Env, a events.Agent) *events.Server {
	t.Helper()
	srv, err := events.Serve(e.Socket, a, -1)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

func run(t *testing.T, e Env, args ...string) error {
	t.Helper()
	return Run(context.Background(), e, args)
}

func TestStatusShowsNodeAndSwitch(t *testing.T) {
	e, out, _ := env(t)
	serveAgent(t, e, &stubAgent{status: events.Status{
		Phase:      tunnel.Up,
		Device:     "hop0",
		ActiveNode: "n2",
		ActiveName: "Токио",
		RTTms:      42,
		Auto:       true,
		LastSwitch: &events.Switch{
			FromNode: "n1", ToNode: "n2", Reason: health.ReasonDead, InterruptedConnections: 3,
		},
	}})

	if err := run(t, e, "status"); err != nil {
		t.Fatalf("status: %v", err)
	}
	want := `фаза: up
устройство: hop0
активный узел: n2 (Токио)
латентность: 42 мс
автопереключение: включено
последнее переключение: n1 → n2, причина dead, порвано соединений: 3
`
	if out.String() != want {
		t.Fatalf("status напечатал:\n%s\nожидалось:\n%s", out, want)
	}
}

// §2: фазу orphaned status обязан показывать — снаружи она выглядит как
// «интернета нет», и пользователь должен видеть причину.
func TestStatusShowsOrphaned(t *testing.T) {
	e, out, _ := env(t)
	serveAgent(t, e, &stubAgent{status: events.Status{
		Phase:        tunnel.Orphaned,
		Device:       "hop0",
		OrphanLeftMS: 12000,
		DetachReason: tunnel.ReasonClosed,
	}})

	if err := run(t, e, "status"); err != nil {
		t.Fatalf("status: %v", err)
	}
	want := `фаза: orphaned
устройство: hop0
предупреждение: агента нет, туннель отвечает отказом; осталось 12 с, причина: closed
`
	if out.String() != want {
		t.Fatalf("status напечатал:\n%s\nожидалось:\n%s", out, want)
	}
}

// §С6: обход виден как предупреждение, а не как обычная фаза.
func TestStatusWarnsOnBypass(t *testing.T) {
	e, out, _ := env(t)
	serveAgent(t, e, &stubAgent{status: events.Status{Phase: tunnel.Bypass}})

	if err := run(t, e, "status"); err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out.String(), "предупреждение: обход включён") {
		t.Fatalf("status без предупреждения об обходе:\n%s", out)
	}
}

// Машинам — стабильный формат, людям — таблица.
func TestStatusJSON(t *testing.T) {
	e, out, _ := env(t)
	serveAgent(t, e, &stubAgent{status: events.Status{Phase: tunnel.Failing, Auto: true}})

	if err := run(t, e, "status", "--json"); err != nil {
		t.Fatalf("status --json: %v", err)
	}
	want := `{
  "phase": "failing",
  "auto": true
}
`
	if out.String() != want {
		t.Fatalf("status --json напечатал:\n%s\nожидалось:\n%s", out, want)
	}
}

func TestNodesTable(t *testing.T) {
	e, out, _ := env(t)
	serveAgent(t, e, &stubAgent{nodes: []events.NodeInfo{
		{ID: "n1", Name: "Токио", Group: "g1", State: health.Alive, RTTms: 42, Supported: true, Active: true},
		{ID: "n2", Name: "Осака", Group: "g1", State: health.Dead, Supported: true},
		{ID: "n3", Name: "Париж", Group: "manual", State: health.Untested},
	}})

	if err := run(t, e, "nodes"); err != nil {
		t.Fatalf("nodes: %v", err)
	}
	want := `   ID  УЗЕЛ                  СОСТОЯНИЕ  RTT    ГРУППА
*  n1  Токио                 alive      42 мс  g1
   n2  Осака                 dead       —      g1
   n3  Париж (не поддержан)  untested   —      manual
`
	if out.String() != want {
		t.Fatalf("nodes напечатал:\n%s\nожидалось:\n%s", out, want)
	}
}

// §С2: подписка добавляется и показывается через агента. Клиент своего стора
// не открывает — ни на запись, ни на чтение (§3.3): под системным пользователем
// `hop` он до каталога агента не достаёт (§6.8).
func TestSubCommandsReachAgent(t *testing.T) {
	e, out, _ := env(t)
	a := &stubAgent{groups: []events.GroupInfo{{
		ID:        "ee8e3a30",
		Name:      "sub.example",
		Nodes:     2,
		UpdatedAt: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		SourceURL: "https://sub.example/list",
	}}}
	serveAgent(t, e, a)

	if err := run(t, e, "sub", "add", "https://sub.example/list"); err != nil {
		t.Fatalf("sub add: %v", err)
	}
	if a.subURL != "https://sub.example/list" {
		t.Fatalf("до агента доехал адрес %q", a.subURL)
	}
	// Вторая строка — предупреждение C12: живой агент состав не перечитывает.
	want := "подписка sub.example (ee8e3a30): добавлено 2, сохранено 0, удалено 0, не поддержано 1\n" +
		"агент уже работает: новый состав узлов вступит в силу после hop down и hop up\n"
	if out.String() != want {
		t.Fatalf("sub add напечатал:\n%s\nожидалось:\n%s", out, want)
	}

	// --name доезжает до агента: имя группы выбирает пользователь (§5.8).
	out.Reset()
	if err := run(t, e, "sub", "add", "https://sub.example/list", "--name", "мои"); err != nil {
		t.Fatalf("sub add --name: %v", err)
	}
	if a.subName != "мои" {
		t.Fatalf("имя группы не доехало: %q", a.subName)
	}

	out.Reset()
	if err := run(t, e, "sub", "list"); err != nil {
		t.Fatalf("sub list: %v", err)
	}
	want = `ID        ИМЯ          УЗЛОВ  ОБНОВЛЕНА         ИСТОЧНИК
ee8e3a30  sub.example  2      2026-08-10 12:00  https://sub.example/list
`
	if out.String() != want {
		t.Fatalf("sub list напечатал:\n%s\nожидалось:\n%s", out, want)
	}

	out.Reset()
	if err := run(t, e, "sub", "update"); err != nil {
		t.Fatalf("sub update: %v", err)
	}
	if !strings.Contains(out.String(), "сохранено 2") {
		t.Fatalf("sub update напечатал: %s", out)
	}

	out.Reset()
	if err := run(t, e, "sub", "rm", "ee8e3a30"); err != nil {
		t.Fatalf("sub rm: %v", err)
	}
	if a.subRemoved != "ee8e3a30" || !strings.HasPrefix(out.String(), "подписка ee8e3a30 удалена\n") {
		t.Fatalf("sub rm: агент получил %q, напечатано %q", a.subRemoved, out)
	}
}

// Пустой `sub list` — не пустой вывод: пользователю надо сказать, чем его
// наполнить.
func TestSubListEmpty(t *testing.T) {
	e, out, _ := env(t)
	serveAgent(t, e, &stubAgent{})
	if err := run(t, e, "sub", "list"); err != nil {
		t.Fatalf("sub list: %v", err)
	}
	if out.String() != "подписок нет: hop sub add <url>\n" {
		t.Fatalf("sub list напечатал: %q", out)
	}
}

// Отказ агента доезжает до пользователя отказом, а не пустым успехом.
func TestSubAddReportsAgentError(t *testing.T) {
	e, _, _ := env(t)
	serveAgent(t, e, &stubAgent{fail: errors.New("сеть недоступна")})
	err := run(t, e, "sub", "add", "https://sub.example/list")
	if err == nil || !strings.Contains(err.Error(), "сеть недоступна") {
		t.Fatalf("sub add с недоступным адресом вернул %v", err)
	}
}

// §С2: ссылка на отдельный узел уезжает агенту, а тот кладёт её в manual.
func TestNodeAddAndRemoveReachAgent(t *testing.T) {
	e, out, _ := env(t)
	a := &stubAgent{fromGroup: "ee8e3a30"}
	serveAgent(t, e, a)

	link := "vless://33333333-3333-3333-3333-333333333333@c.example:443?security=tls#Прага"
	if err := run(t, e, "node", "add", link); err != nil {
		t.Fatalf("node add: %v", err)
	}
	if a.nodeLink != link {
		t.Fatalf("ссылка до агента не доехала: %q", a.nodeLink)
	}
	if got := out.String(); !strings.Contains(got, "узел добавлен: n9 (Прага), группа manual") {
		t.Fatalf("node add напечатал: %s", got)
	}

	out.Reset()
	if err := run(t, e, "node", "rm", "n9"); err != nil {
		t.Fatalf("node rm: %v", err)
	}
	if a.nodeDropped != "n9" {
		t.Fatalf("id на удаление не доехал: %q", a.nodeDropped)
	}
	got := out.String()
	if !strings.Contains(got, "узел n9 удалён") {
		t.Fatalf("node rm напечатал: %s", got)
	}
	// Узел из подписки вернётся при следующем обновлении — молчать об этом
	// нельзя, иначе удаление выглядит несработавшим.
	if !strings.Contains(got, "hop sub update") {
		t.Fatalf("про возврат узла из подписки не сказано: %s", got)
	}
}

// Неподдержанный узел (§6.11) сохраняется, но об этом говорится сразу: иначе
// пользователь ждёт от него подключения.
func TestNodeAddWarnsOnUnsupported(t *testing.T) {
	e, out, _ := env(t)
	serveAgent(t, e, &unsupportedAgent{})
	if err := run(t, e, "node", "add", "tuic://x@c.example:443#Осака"); err != nil {
		t.Fatalf("node add: %v", err)
	}
	if !strings.Contains(out.String(), "в выборе не участвует") {
		t.Fatalf("node add напечатал: %s", out)
	}
}

type unsupportedAgent struct{ stubAgent }

func (a *unsupportedAgent) NodeAdd(string) (events.NodeInfo, error) {
	return events.NodeInfo{ID: "n9", Name: "Осака", Group: "manual", Supported: false}, nil
}

func TestBypassAndAutoReachAgent(t *testing.T) {
	e, out, errOut := env(t)
	a := &stubAgent{}
	serveAgent(t, e, a)

	if err := run(t, e, "bypass", "--on"); err != nil {
		t.Fatalf("bypass --on: %v", err)
	}
	if !a.bypass || !strings.HasPrefix(out.String(), "обход включён") {
		t.Fatalf("bypass --on: агент=%v, вывод %q", a.bypass, out)
	}

	out.Reset()
	if err := run(t, e, "auto", "off"); err != nil {
		t.Fatalf("auto off: %v", err)
	}
	if a.auto || out.String() != "автопереключение выключено\n" {
		t.Fatalf("auto off: агент=%v, вывод %q", a.auto, out)
	}

	// §С3: up --node у живого агента фиксирует узел, а не поднимает второй
	// туннель.
	out.Reset()
	if err := run(t, e, "up", "--node", "n7"); err != nil {
		t.Fatalf("up --node: %v", err)
	}
	if a.pinned != "n7" {
		t.Fatalf("узел не зафиксирован: %q", a.pinned)
	}

	out.Reset()
	if err := run(t, e, "node", "ping", "n7"); err != nil {
		t.Fatalf("node ping: %v", err)
	}
	if out.String() != "узел n7 (Токио): alive, 42 мс\n" {
		t.Fatalf("node ping напечатал: %s", out)
	}
	if errOut.Len() != 0 {
		t.Fatalf("лишний вывод в stderr: %s", errOut)
	}
}

// §С7: down снимает туннель через сервис — он владеет интерфейсом и
// маршрутами.
func TestDownStopsTunnel(t *testing.T) {
	e, out, _ := env(t)
	var called bool
	e.Down = func() error { called = true; return nil }

	if err := run(t, e, "down"); err != nil {
		t.Fatalf("down: %v", err)
	}
	if !called || out.String() != "туннель снят\n" {
		t.Fatalf("down: сервис позван=%v, вывод %q", called, out)
	}
}

// §С3: без живого агента up поднимает туннель сам.
func TestUpStartsAgent(t *testing.T) {
	e, _, _ := env(t)
	var pin string
	started := false
	e.Up = func(_ context.Context, p string) error { started, pin = true, p; return nil }

	if err := run(t, e, "up", "--node", "n1"); err != nil {
		t.Fatalf("up: %v", err)
	}
	if !started || pin != "n1" {
		t.Fatalf("агент не запущен: started=%v pin=%q", started, pin)
	}
}

// TestEventsFollowGetsSwitch — §С5: поток событий переключения.
func TestEventsFollowGetsSwitch(t *testing.T) {
	e, _, _ := env(t)
	srv := serveAgent(t, e, &stubAgent{})

	lines := make(chan string, 8)
	e.Out = writerChan(lines)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, e, []string{"events", "--follow"}) }()

	ev := events.Event{
		At:    time.Date(2026, 8, 10, 12, 0, 5, 0, time.UTC),
		Phase: tunnel.Up,
		Switch: &events.Switch{
			FromNode: "n1", ToNode: "n2", Reason: health.ReasonDead, InterruptedConnections: 3,
		},
	}
	// Подписка доезжает до агента асинхронно: событие шлётся, пока клиент его
	// не увидит.
	var got string
	clk := clock.System{}
	for i := 0; i < 400 && got == ""; i++ {
		srv.Publish(ev)
		select {
		case got = <-lines:
		case <-clk.After(5 * time.Millisecond):
		}
	}
	want := "12:00:05 up: n1 → n2, причина dead, порвано соединений: 3\n"
	if got != want {
		t.Fatalf("events --follow напечатал %q, ожидалось %q", got, want)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("events --follow вернул %v", err)
	}
}

// Разбор аргументов: неверное употребление обязано быть ошибкой, а не тихим
// «ничего не сделал».
func TestArgumentErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"без команды", nil, "команды:"},
		{"неизвестная команда", []string{"upp"}, `неизвестная команда "upp"`},
		{"bypass без флага", []string{"bypass"}, "нужен ровно один флаг"},
		{"bypass с обоими", []string{"bypass", "--on", "--off"}, "нужен ровно один флаг"},
		{"auto без аргумента", []string{"auto"}, "нужен аргумент on или off"},
		{"sub без подкоманды", []string{"sub"}, "нужна подкоманда"},
		{"sub add без адреса", []string{"sub", "add"}, "нужен адрес подписки"},
		{"node без подкоманды", []string{"node"}, "нужна подкоманда"},
		{"node ping без id", []string{"node", "ping"}, "нужен id узла"},
		{"неизвестный флаг", []string{"status", "--verbose"}, "flag provided but not defined"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, _, errOut := env(t)
			err := run(t, e, c.args...)
			if !IsUsage(err) {
				t.Fatalf("получена ошибка %v, ожидалась ошибка употребления", err)
			}
			if !strings.Contains(errOut.String(), c.want) {
				t.Fatalf("в stderr нет %q:\n%s", c.want, errOut)
			}
		})
	}
}

// Команды, которым без агента делать нечего, обязаны говорить об этом прямо.
func TestCommandsNeedAgent(t *testing.T) {
	for _, args := range [][]string{
		{"bypass", "--on"}, {"auto", "on"}, {"node", "ping", "n1"}, {"events", "--follow"},
		// Шесть команд состава §С2 — тоже: стор живёт в агенте, и без агента
		// править его нечем (§3.3). Прежде их делал сам процесс CLI (C12).
		{"sub", "add", "https://sub.example/list"}, {"sub", "update"},
		{"sub", "rm", "ee8e3a30"}, {"sub", "list"},
		{"node", "add", "vless://x@c.example:443"}, {"node", "rm", "n1"},
		// `nodes` показывал состав из стора, пока агент спал. Показывать его
		// больше неоткуда, и молчаливый пустой список хуже отказа.
		{"nodes"},
	} {
		e, _, _ := env(t)
		if err := run(t, e, args...); !errors.Is(err, errNoAgent) {
			t.Fatalf("%v вернула %v, ожидалось «агент не запущен»", args, err)
		}
	}
}

// writerChan отдаёт каждую напечатанную строку в канал: команда пишет из своей
// горутины, и буфер здесь был бы гонкой.
type writerChan chan string

func (w writerChan) Write(p []byte) (int, error) {
	w <- string(p)
	return len(p), nil
}
