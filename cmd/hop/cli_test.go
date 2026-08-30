package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shafed/hop/internal/agent"
	"github.com/shafed/hop/internal/negcheck"
	"github.com/shafed/hop/internal/policy"
	"github.com/shafed/hop/internal/store"
)

// Поверхность CLI §5.9 — W55–W58.
//
// Проверяется здесь ровно то, что §5.9 обещает наружу и что до этого прохода
// держалось на шести временных флагах (Р40): грамматика подкоманд, карта кодов
// возврата и `--json` с одной точкой формирования.

// fakeOutbound — физический путь §6.8 без обращения к ядру.
//
// Шов нужен затем, чтобы проверка кодов возврата шла тем же путём, что и живой
// прогон: настоящий outbound.Selector спрашивает у netlink интерфейс по
// умолчанию, и в песочнице без маршрута команда отказала бы раньше, чем дошла
// до проверяемого — то есть код 3 был бы получен по чужой причине.
type fakeOutbound struct{}

func (fakeOutbound) Interface() (string, error) { return "lo", nil }
func (fakeOutbound) HTTPClient() *http.Client   { return &http.Client{} }
func (fakeOutbound) Close() error               { return nil }

// testCLI — клиент с подменённым физическим путём и собственными потоками.
func testCLI(t *testing.T) (*cli, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, errs bytes.Buffer
	c := newCLI(&out, &errs)
	c.newOutbound = func(string) (outboundPath, error) { return fakeOutbound{}, nil }
	return c, &out, &errs
}

// specVerbs — глаголы §5.9, прочитанные ИЗ SPEC.md, а не переписанные сюда.
//
// Список литералом здесь уже стоял, и он был вторым экземпляром правды: §5.9
// и тест разъезжаются молча, а именно от молчаливого расхождения документа и
// кода этот репозиторий защищается (см. `cmd/doclint`). Читается строка формы
// «`hop a | b | c`» из раздела §5.9; отсутствие раздела или строки — падение,
// а не пустой список, иначе переписанная спека делала бы проверку зелёной,
// ничего не проверяя.
//
// `agent` спека называет отдельным абзацем («Бинарь один»), а не в
// перечислении, поэтому он добавляется к прочитанному явно и с этим доводом.
func specVerbs(t *testing.T) []string {
	t.Helper()

	root, err := negcheck.ModuleRoot(".")
	if err != nil {
		t.Fatalf("корень модуля не найден: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "SPEC.md"))
	if err != nil {
		t.Fatalf("SPEC.md не прочитан: %v", err)
	}

	var section bool
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "### 5.9"):
			section = true
			continue
		case section && strings.HasPrefix(line, "### "):
			t.Fatal("в §5.9 нет строки перечисления глаголов вида `hop a | b | c`")
		case !section || !strings.HasPrefix(line, "`hop ") || !strings.Contains(line, "|"):
			continue
		}
		list := strings.TrimPrefix(line[:strings.LastIndex(line, "`")], "`hop ")
		verbs := []string{"agent"}
		for _, v := range strings.Split(list, "|") {
			if v = strings.TrimSpace(v); v != "" {
				verbs = append(verbs, v)
			}
		}
		if len(verbs) < 5 {
			t.Fatalf("из §5.9 разобрано %d глаголов (%v) — строка перечисления разобрана неверно", len(verbs), verbs)
		}
		return verbs
	}
	t.Fatal("раздел §5.9 в SPEC.md не найден")
	return nil
}

// TestW55EveryVerbOfTheSpecIsInTheGrammar — грамматика §5.9 названа целиком и
// не растёт молча.
//
// Обе стороны несут своё. Недостающий глагол означает, что §5.9 обещает
// пользователю команду, которой нет, и узнать это можно только чтением спеки.
// Лишний означает обратное: поверхность выросла мимо документа, и никто этого
// не заметил — ровно так шесть временных флагов Р40 дожили до шести.
func TestW55EveryVerbOfTheSpecIsInTheGrammar(t *testing.T) {
	have := map[string]bool{}
	for _, c := range commands {
		have[c.verb] = true
	}
	spec := specVerbs(t)
	for _, v := range spec {
		if !have[v] {
			t.Errorf("глагола %q нет в грамматике, а §5.9 называет его поимённо", v)
		}
	}
	for _, c := range commands {
		if !slices.Contains(spec, c.verb) {
			t.Errorf("глагол %q есть в грамматике и не назван в §5.9: поверхность выросла мимо документа", c.verb)
		}
	}
}

// TestW55UnknownCommandDoesNotSucceed — неизвестный глагол кончается отказом, а
// не молчаливым нулём.
//
// Ноль на опечатке — худший из возможных ответов: скрипт считает, что команда
// выполнена, и идёт дальше.
func TestW55UnknownCommandDoesNotSucceed(t *testing.T) {
	c, _, errs := testCLI(t)
	if code := c.dispatch([]string{"статус"}); code == 0 {
		t.Fatalf("неизвестная команда дала код 0; вывод: %s", errs.String())
	}
	if code := c.dispatch(nil); code == 0 {
		t.Fatal("вызов без команды дал код 0")
	}
	if !strings.Contains(errs.String(), "status") {
		t.Errorf("отказ не показал списка команд:\n%s", errs.String())
	}
}

// TestW55RetiredFlagNamesItsReplacement — снятый флаг Р40 называет замену.
//
// Флаги удаляются, а не остаются псевдонимами (PLAN.md, этап 9: «два
// интерфейса к одному стору разойдутся»), и цена этого решения — чужой скрипт,
// который перестанет работать. Заплатить её молчаливым «неизвестная команда»
// нельзя: пользователь узнает, что интерфейс сменился, но не узнает, на что.
func TestW55RetiredFlagNamesItsReplacement(t *testing.T) {
	for flagName, replacement := range retiredFlags {
		c, _, errs := testCLI(t)
		if code := c.dispatch([]string{"-" + flagName, "аргумент"}); code == 0 {
			t.Errorf("снятый флаг -%s дал код 0", flagName)
		}
		if !strings.Contains(errs.String(), replacement) {
			t.Errorf("отказ на -%s не назвал замены %q:\n%s", flagName, replacement, errs.String())
		}
	}
	// Список не пуст по построению: шесть флагов Р40 плюс -down и -status.
	if len(retiredFlags) < 6 {
		t.Fatalf("в таблице переезда %d флагов, а Р40 их называет шесть", len(retiredFlags))
	}
}

// storeWithDeadNode кладёт в стор теста один узел, до которого не дозвониться.
//
// 127.0.0.1:1 — адрес, который отказывает сразу и не выходит в сеть: проверка
// кодов возврата не имеет права зависеть ни от интернета, ни от таймаутов.
func storeWithDeadNode(t *testing.T) {
	t.Helper()
	withTestStore(t)
	err := withStore(func(st *store.Store) error {
		return addNode(st, "vless://"+uuidA+"@127.0.0.1:1?type=ws&security=tls#мёртвый", io.Discard)
	})
	if err != nil {
		t.Fatalf("узел не добавился: %v", err)
	}
}

// TestW56ExitCodesTellRefusalFromFailClose — коды 0/1/2/3 (§5.9).
//
// Третий код существует потому, что fail-close — штатное состояние, а не
// поломка: без него мониторинг вынужден разбирать текст, чтобы отличить «всё
// работает, живых узлов нет» от «утилита упала». Проверяются все четыре разом
// именно поэтому — ценность каждого в том, что он ОТЛИЧАЕТСЯ от соседнего.
//
// Краснеет без exit_codes: с выключенной политикой любой отказ становится
// единицей, и 2 с 3 перестают отличаться от 1.
func TestW56ExitCodesTellRefusalFromFailClose(t *testing.T) {
	// 0 — выполнено. Читающая команда на пустом сторе законна.
	withTestStore(t)
	c, _, errs := testCLI(t)
	if code := c.dispatch([]string{"nodes"}); code != 0 {
		t.Fatalf("`hop nodes` на пустом сторе дал %d, ожидался 0: %s", code, errs.String())
	}

	// 1 — ошибка выполнения.
	c, _, _ = testCLI(t)
	if code := c.dispatch([]string{"node", "rm", "такого-нет"}); code != 1 {
		t.Errorf("удаление несуществующего узла дало %d, ожидалась 1", code)
	}

	// 2 — фоновой половины нет. Сокета по этому пути не существует, и это не
	// ошибка конфигурации: агент просто не поднят.
	c, _, _ = testCLI(t)
	sock := filepath.Join(t.TempDir(), "нет.sock")
	// Оба адресата названы явно: `status` спрашивает связку, а сервис — только
	// когда она молчит, и умолчание клиентского сокета зависело бы от того,
	// запущен ли агент на машине, где идёт проверка.
	if code := c.dispatch([]string{"status", "-socket", sock, "-client-socket", sock}); code != 2 {
		t.Errorf("`hop status` без сокета дал %d, ожидалась 2", code)
	}

	// 3 — живых узлов нет. Узел в сторе есть, дозвониться до него нельзя:
	// это и есть fail-close §5.6, а не поломка.
	storeWithDeadNode(t)
	c, out, _ := testCLI(t)
	if code := c.dispatch([]string{"probe"}); code != 3 {
		t.Errorf("проба мёртвого узла дала %d, ожидалась 3 (fail-close §5.6)", code)
	}
	if out.Len() == 0 {
		t.Error("код 3 пришёл без вывода: пользователю нечего прочитать про то, какие узлы не ответили")
	}
}

// TestW57BrokenSettingsIsFailureNotFailClose — кривой `settings.json` даёт 1, а
// не 3 (§5.9 буквально).
//
// Отдельная строка регистра, а не ветка W56: она про границу между двумя
// кодами, и ошибиться в ней легко именно потому, что оба ненулевые. Поломка
// конфигурации — это работа для человека, fail-close — штатное состояние; в
// мониторинге они означают противоположное.
//
// Флага у этой строки нет намеренно: при `HOP_DISABLE=exit_codes` все коды
// схлопываются в 1, и утверждение «единица, а не тройка» становится истинным
// само собой. Краснеть ей нечем, и притворяться охраной она не должна.
func TestW57BrokenSettingsIsFailureNotFailClose(t *testing.T) {
	root := withTestStore(t)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "settings.json"), []byte("{это не json"), 0o644); err != nil {
		t.Fatal(err)
	}

	c, _, errs := testCLI(t)
	code := c.dispatch([]string{"routing"})
	if code == 3 {
		t.Fatal("кривой settings.json дал 3: поломка конфигурации выглядит как fail-close")
	}
	if code != 1 {
		t.Fatalf("кривой settings.json дал %d, ожидалась 1", code)
	}
	if errs.Len() == 0 {
		t.Error("отказ молчит: §5.6 требует названной причины")
	}
}

// goldenViews — по одному значению каждой читающей команды и то, во что оно
// обязано превратиться.
//
// Литерал, а не «то, что вышло»: схема — контракт с чужой автоматикой (§8.5), и
// переименованное поле обязано краснить проверку, а не переехать в ожидание
// вместе с кодом.
func goldenViews() []struct {
	name string
	v    view
	want string
} {
	return []struct {
		name string
		v    view
		want string
	}{
		{
			name: "nodes",
			v: nodesOut{Groups: []groupOut{{
				Group: store.GroupView{
					ID: "g1", Name: "подписка", Nodes: 1,
					LastUpdatedAt: "2024-01-01T00:00:00Z", AutoUpdate: true,
				},
				Nodes: []store.NodeView{{
					ID: "n1", GroupID: "g1", Name: "узел",
					Server: "a.example", Port: 443,
					Protocol: "vless", Transport: "ws", Security: "tls",
					Supported: true, State: "alive", RTTMs: 42,
					LastProbeAt: "2024-01-01T00:00:00Z",
				}},
			}}},
			want: `{"groups":[{"group":{"id":"g1","name":"подписка","nodes":1,` +
				`"last_updated_at":"2024-01-01T00:00:00Z","auto_update":true},` +
				`"nodes":[{"id":"n1","group_id":"g1","name":"узел","server":"a.example",` +
				`"port":443,"protocol":"vless","transport":"ws","security":"tls",` +
				`"supported":true,"state":"alive","rtt_ms":42,` +
				`"last_probe_at":"2024-01-01T00:00:00Z"}]}]}`,
		},
		{
			// Ответила связка (§3.3) — половина сервиса пуста. Это нормальный
			// случай: пока агент отвечает, клиент к привилегированному сервису
			// не ходит вовсе.
			name: "status",
			v: statusOut{Agent: &agent.ClientStatus{
				Tunnel: "up", Traffic: "proxied",
				Active: "n1", ActiveState: "alive", ActiveRTTMs: 42,
				Auto: true, Alive: 2, Nodes: 3,
				Last: &agent.ClientEvent{
					At:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
					From: "n2", To: "n1", Reason: "dead", Interrupted: 3,
				},
			}},
			want: `{"tunnel":null,"agent":{"tunnel":"up","traffic":"proxied","active":"n1",` +
				`"active_state":"alive","active_rtt_ms":42,"auto":true,"alive":2,"nodes":3,` +
				`"last_switch":{"at":"2024-01-01T00:00:00Z","from":"n2","to":"n1",` +
				`"reason":"dead","interrupted":3}}}`,
		},
		{
			// Связки нет — ответил сервис. null у второй половины значит «этот
			// не отвечал», а не «показывать нечего».
			name: "status без связки",
			v:    statusOut{Tunnel: &tunnelOut{Phase: "orphaned", Device: "fd", DetachReason: "restart", OrphanLeft: "12s"}},
			want: `{"tunnel":{"phase":"orphaned","device":"fd","detach_reason":"restart",` +
				`"orphan_left":"12s"},"agent":null}`,
		},
		{
			name: "events",
			v: eventsOut{Events: []agent.ClientEvent{{
				At: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				To: "n1", Reason: "manual",
			}}},
			want: `{"events":[{"at":"2024-01-01T00:00:00Z","to":"n1","reason":"manual",` +
				`"interrupted":0}]}`,
		},
		{
			// Одно событие потока `--follow`: та же схема без обёртки, потому
			// что у потока нет конца, в который можно было бы её закрыть.
			name: "событие потока",
			v: eventOut{agent.ClientEvent{
				At:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				From: "n1", To: "n2", Reason: "faster", Interrupted: 0,
			}},
			want: `{"at":"2024-01-01T00:00:00Z","from":"n1","to":"n2","reason":"faster",` +
				`"interrupted":0}`,
		},
		{
			name: "probe",
			v: probeOut{Alive: 1, Nodes: []probeNodeOut{
				{ID: "n1", Name: "узел", Server: "a.example", Port: 443, Alive: true, RTTMs: 12},
				{ID: "n2", Server: "b.example", Port: 443, Error: "узел недоступен"},
			}},
			want: `{"nodes":[{"id":"n1","name":"узел","server":"a.example","port":443,` +
				`"alive":true,"rtt_ms":12},{"id":"n2","server":"b.example","port":443,` +
				`"alive":false,"error":"узел недоступен"}],"alive":1}`,
		},
		{
			name: "routing",
			v: routingOut{
				File:         "/тест/settings.json",
				Defaults:     listsOut{Bypass: []ruleOut{{Prefix: "10.0.0.0/8"}}, Block: []ruleOut{}},
				Configured:   nil,
				DNSUpstreams: []string{},
			},
			want: `{"file":"/тест/settings.json","defaults":{"bypass":[{"prefix":"10.0.0.0/8"}],` +
				`"block":[]},"configured":null,"dns_upstreams":[]}`,
		},
	}
}

// TestW58JSONSchemaIsFixed — схема `--json` закреплена и не едет молча (§5.9).
//
// «Вывод, который никто не проверяет, перестаёт быть контрактом»: тесты
// установки §8.5 и любая автоматика разбирают JSON, а правка человеческой
// формулировки не имеет права его трогать — и наоборот.
//
// Краснеет без json_schema: с выключенной политикой машинного вывода нет вовсе,
// и emit отказывает вместо того, чтобы напечатать неизвестно что.
func TestW58JSONSchemaIsFixed(t *testing.T) {
	for _, g := range goldenViews() {
		var buf bytes.Buffer
		if err := emit(&buf, g.v, true); err != nil {
			t.Fatalf("%s --json отказал: %v", g.name, err)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, buf.Bytes()); err != nil {
			t.Fatalf("%s --json выдал не JSON: %v\n%s", g.name, err, buf.String())
		}
		if compact.String() != g.want {
			t.Errorf("схема %s --json разъехалась\nбыло:  %s\nстало: %s", g.name, g.want, compact.String())
		}
	}
}

// TestW58JSONHasOneFormationPoint — машинный вывод формируется в одном месте.
//
// Прямое требование HANDOFF и S33 регистра стора: проверка держится на функции
// формирования вывода, а не на команде. Пока точек несколько, схему нельзя ни
// закрепить, ни сломать целиком — она разъезжается по одной команде за раз, и
// каждый такой разъезд зелен для всех проверок, кроме той единственной, что
// смотрит на эту команду.
//
// Разбор AST, а не договорённость: договорённость держится вниманием, а новая
// читающая команда пишется через полгода.
func TestW58JSONHasOneFormationPoint(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("пакет не разобрался: %v", err)
	}

	encoders := map[string]bool{"Marshal": true, "MarshalIndent": true, "NewEncoder": true}
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				ast.Inspect(fn, func(n ast.Node) bool {
					sel, ok := n.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					id, ok := sel.X.(*ast.Ident)
					if !ok || id.Name != "json" || !encoders[sel.Sel.Name] {
						return true
					}
					if fn.Name.Name != "emit" {
						t.Errorf("%s: json.%s зовут из %s, а не из emit — точек формирования стало две",
							filepath.Base(path), sel.Sel.Name, fn.Name.Name)
					}
					return true
				})
			}
		}
	}
}

// TestW58EveryReadingCommandTakesJSON — `--json` есть у всех читающих команд.
//
// §5.9 говорит «у всех», и это не про удобство: команда без машинного вывода
// заставляет автоматику разбирать человеческий текст, после чего текст
// перестаёт быть человеческим — его правят под регэксп.
func TestW58EveryReadingCommandTakesJSON(t *testing.T) {
	reading := []string{"status", "nodes", "routing", "probe", "events"}
	for _, name := range reading {
		cmd, ok := lookupVerb(name)
		if !ok {
			t.Errorf("читающей команды %q нет в грамматике", name)
			continue
		}
		if !cmd.reads {
			t.Errorf("команда %q не помечена читающей: у неё не будет --json", name)
		}
	}
	for _, c := range commands {
		if c.reads && c.waits != "" {
			t.Errorf("команда %q помечена читающей, но не реализована: --json у неё нечем наполнить", c.name())
		}
	}
}

// TestW58MachineOutputIsAloneOnStdout — в машинном канале стоит только вывод
// команды.
//
// Замер, а не предположение: `hop probe --json` печатал в stdout строку
// «[Warning] … WebSocket transport … is deprecated» перед JSON. Пишет её Xray
// своим глобальным логом, и `loglevel: none` в конфиге инстанса её не гасит —
// предупреждение о конфигурации появляется раньше, чем инстанс. Схему при этом
// проверяли зелёные тесты: они смотрели на значение, а не на поток.
//
// Поэтому здесь подменяется настоящий os.Stdout, а не буфер команды: мусорит
// чужая библиотека мимо наших писателей, и увидеть её можно только там.
func TestW58MachineOutputIsAloneOnStdout(t *testing.T) {
	// Без json_schema машинного вывода нет вовсе, и утверждение «в канале
	// только JSON» в такой сборке невыразимо: краснеть этой проверке
	// полагалось бы по чужому флагу, а охраной она не служит ни одному. Тот же
	// приём, которым W50 пропускается без ipv6_block.
	if !policy.JSONSchema.On() {
		t.Skip("json_schema выключен: машинного вывода нет, проверять в канале нечего")
	}
	storeWithDeadNode(t)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w

	c := newCLI(w, io.Discard)
	c.newOutbound = func(string) (outboundPath, error) { return fakeOutbound{}, nil }
	code := c.dispatch([]string{"probe", "--json"})

	os.Stdout = saved
	w.Close()
	out, readErr := io.ReadAll(r)
	r.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}

	// Код здесь не проверяется намеренно: его держит W56, а эта проверка про
	// поток. Тест, краснеющий за двоих, не говорит, что именно сломано.
	_ = code
	var v any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("stdout не разбирается как JSON (%v), а --json — контракт с автоматикой:\n%s", err, out)
	}
}
