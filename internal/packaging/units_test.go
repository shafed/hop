//go:build linux

package packaging

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestUnitsRunTheProductWithoutRepeatingItsDefaults — шов «unit-файл ↔
// грамматика §5.9».
//
// Существо, которое тест чинит, уже случалось в этом репозитории один раз:
// стенд L3 звал продукт строками argv, продукт снял флаги Р40, и связь между
// строкой и грамматикой не проверял никто — internal/l3/grammar_test.go
// заведён ровно поэтому. Unit-файл — та же строка argv, только исполняет её
// systemd на чужой машине, где красного не увидит никто.
//
// Второе утверждение теста — про решение, а не про опечатку: в ExecStart нет
// НИ ОДНОГО флага. Всё, что здесь было бы естественно написать (-socket,
// -group), — умолчания самого продукта, и переписанные в unit они стали бы
// вторым источником истины, расходящимся молча. Флаг, добавленный в unit,
// красит этот тест намеренно: сначала решение, потом строка.
func TestUnitsRunTheProductWithoutRepeatingItsDefaults(t *testing.T) {
	verbs := hopVerbs(t)

	for _, u := range units {
		argv := execStart(t, u.file)
		bin := filepath.Base(argv[0])
		if !filepath.IsAbs(argv[0]) {
			t.Errorf("%s: ExecStart=%s не абсолютный путь; systemd такой unit не примет", u.file, argv[0])
		}
		switch bin {
		case "hopd":
			if len(argv) != 1 {
				t.Errorf("%s: ExecStart зовёт hopd с аргументами %q; у hopd нет глаголов (cmd/hopd/main.go — только флаги)", u.file, argv[1:])
			}
		case "hop":
			if len(argv) < 2 {
				t.Fatalf("%s: ExecStart=%s без глагола; §5.9 — грамматика подкоманд", u.file, argv[0])
			}
			if !verbs[argv[1]] {
				t.Errorf("%s: глагола %q нет в грамматике §5.9 (таблица commands, cmd/hop/cli.go). Известные: %s",
					u.file, argv[1], strings.Join(sortedKeys(verbs), ", "))
			}
		default:
			t.Errorf("%s: ExecStart зовёт %q — это не hop и не hopd", u.file, bin)
		}

		for _, a := range argv[1:] {
			if strings.HasPrefix(a, "-") {
				t.Errorf("%s: ExecStart передаёт флаг %q. Решение §6.13: unit не повторяет умолчаний продукта — "+
					"иначе путь сокета и имя группы получают второй источник истины. Если флаг всё-таки нужен, "+
					"сначала правится решение (комментарий в самом unit-файле), потом эта охрана учится проверять флаги по грамматике",
					u.file, a)
			}
		}
	}
}

// TestInstallScriptCreatesTheGroupTheServiceOpensItsSocketTo — второй молчащий
// шов той же природы.
//
// Инсталлятор заводит группу по имени, а hopd открывает ей сокет по своему
// умолчанию (§6.1). Имена лежат в разных файлах и на разных языках, и
// разъехавшись, дают не отказ, а тишину: сервис поднимется, сокет будет с
// правами чужой группы, агент упрётся в permission denied при логине — там,
// где красного никто не читает.
func TestInstallScriptCreatesTheGroupTheServiceOpensItsSocketTo(t *testing.T) {
	script := readFile(t, installScript(t))
	var group string
	for _, line := range strings.Split(script, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "GROUP="); ok {
			group = strings.Trim(v, `"'`)
			break
		}
	}
	if group == "" {
		t.Fatal("в packaging/install.sh нет строки GROUP=")
	}

	def := hopdFlagDefault(t, "group")
	if group != def {
		t.Errorf("инсталлятор заводит группу %q, а hopd открывает сокет группе %q (умолчание флага -group, cmd/hopd/main.go)", group, def)
	}
}

// TestUnitsNameThePathsTheInstallScriptCreates — третий шов: ExecStart называет
// абсолютный путь, а кладёт туда файл скрипт, и связывает их только совпадение
// строк в двух файлах.
//
// Проверяется на настоящей раскладке, а не сверкой констант: скрипт может
// положить файл куда угодно по дороге (install -D, опечатка в каталоге), и
// сверка констант этого не увидит.
//
// Отдельно проверяется системный/пользовательский каталог: пользовательский
// unit, положенный в системный каталог, не отказывает — он просто никогда не
// поднимется при логине, а `systemctl --global enable` отработает молча.
func TestUnitsNameThePathsTheInstallScriptCreates(t *testing.T) {
	dest := stagedInstall(t)

	for _, u := range units {
		want := filepath.Join(dest, filepath.FromSlash(u.destDir), u.file)
		if _, err := os.Stat(want); err != nil {
			t.Errorf("%s не разложен туда, где его ждёт systemd (%s): %v", u.file, u.destDir, err)
		}

		argv := execStart(t, u.file)
		bin := filepath.Join(dest, filepath.FromSlash(argv[0]))
		fi, err := os.Stat(bin)
		if err != nil {
			t.Errorf("%s: ExecStart называет %s, но поставка туда ничего не кладёт: %v", u.file, argv[0], err)
			continue
		}
		if fi.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s: %s поставлен без бита исполнения (%v)", u.file, argv[0], fi.Mode().Perm())
		}
	}
}

// TestSystemdAcceptsTheStagedUnits — единственная проверка, которую делает сам
// systemd, а не мы про systemd.
//
// ЗАМЕРЕНО, и без этого замера тест был бы пустым: `systemd-analyze verify`
// возвращает НОЛЬ на сломанном unit-файле. Прогон на этой машине (systemd 261):
//
//	Restart=когда-нибудь   → rc=0, в stderr «Failed to parse Restart=…»
//	Type=exek              → rc=0, в stderr «Failed to parse Type=…»
//	Frobnicate=1           → rc=0, в stderr «Unknown key 'Frobnicate'»
//	нет ExecStart          → rc=1
//	[Servise]              → rc=1 (следствием: «Service has no ExecStart»)
//
// Отсюда форма: красным считается ЛЮБОЙ вывод, а не код возврата. Тест по коду
// пропустил бы три поломки из пяти и был бы зелен на unit-файле, который
// systemd грузит с руганью и игнорированием половины директив.
//
// Второй замер — про --root: `systemd-analyze verify --root=DIR` требует, чтобы
// в этом корне лежало ВСЁ дерево юнитов (иначе «Unit sysinit.target not
// found»), поэтому корень собирается из машинного /usr/lib/systemd поверх
// раскладки. А `--user` вместе с `--root` не работает вовсе («Failed to
// initialize unit search paths for root directory … Invalid argument»), и
// пользовательский unit проверяется здесь по правилам системного менеджера:
// синтаксис и значения директив — да, семантика пользовательской сессии — нет.
//
// Третий замер: WantedBy= с несуществующей целью verify не ловит НИЧЕМ — ни
// кодом, ни выводом. Поэтому цель проверяется отдельно, ниже.
func TestSystemdAcceptsTheStagedUnits(t *testing.T) {
	analyze, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skipf("systemd-analyze не найден: проверка unit-файлов самим systemd НЕ выполнена (%v)", err)
	}

	dest := stagedInstall(t)
	root := verifyRoot(t, dest)

	for _, u := range units {
		out, err := exec.Command(analyze, "verify", "--root="+root, u.file).CombinedOutput()
		if err != nil {
			t.Errorf("systemd-analyze verify %s: %v\n%s", u.file, err, out)
			continue
		}
		if len(strings.TrimSpace(string(out))) != 0 {
			t.Errorf("systemd-analyze verify %s отдал ноль, но не смолчал — значит, часть директив игнорируется:\n%s", u.file, out)
		}
	}

	// Цель [Install]: verify её не проверяет (замер в шапке). Несуществующая
	// цель означает `systemctl enable`, который ничего не включит.
	for _, u := range units {
		for _, target := range wantedBy(t, u.file) {
			if _, err := os.Stat(filepath.Join(root, "usr", "lib", "systemd", "system", target)); err != nil {
				t.Errorf("%s: WantedBy=%s — такой цели нет; enable ничего не включит", u.file, target)
			}
		}
	}
}

// verifyRoot — корень для `systemd-analyze verify --root`: юниты машины плюс
// разложенная поставка поверх.
//
// Пользовательский unit кладётся ещё и в системный каталог — см. замер про
// --user в шапке TestSystemdAcceptsTheStagedUnits: иначе verify его не найдёт.
func verifyRoot(t *testing.T, dest string) string {
	t.Helper()
	root := t.TempDir()
	sysDir := filepath.Join(root, "usr", "lib", "systemd", "system")
	if err := os.MkdirAll(sysDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cp", "-a", "/usr/lib/systemd/system/.", sysDir).CombinedOutput(); err != nil {
		t.Skipf("не скопировать юниты машины (%v): проверка самим systemd НЕ выполнена\n%s", err, out)
	}
	if out, err := exec.Command("cp", "-a", dest+"/.", root).CombinedOutput(); err != nil {
		t.Fatalf("cp раскладки: %v\n%s", err, out)
	}
	for _, u := range units {
		if !u.user {
			continue
		}
		src := filepath.Join(dest, filepath.FromSlash(u.destDir), u.file)
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sysDir, u.file), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func wantedBy(t *testing.T, unit string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(readFile(t, filepath.Join(unitDir(t), unit)), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "WantedBy="); ok {
			out = append(out, strings.Fields(v)...)
		}
	}
	if len(out) == 0 {
		t.Errorf("%s: нет WantedBy= — unit нечем включить", unit)
	}
	return out
}

// hopVerbs — глаголы §5.9 из таблицы commands, разбором cmd/hop/cli.go.
//
// Разбор исходника, а не второй список в тесте: копия однажды уже дала ложный
// зелёный (HANDOFF.json, разбор охраны стенда L3). Пакет main вторым в процесс
// теста не собрать, поэтому AST.
func hopVerbs(t *testing.T) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(repoRoot(t), "cmd", "hop", "cli.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	verbs := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "commands" {
			return true
		}
		lit, ok := vs.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, el := range lit.Elts {
			cmd, ok := el.(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, f := range cmd.Elts {
				kv, ok := f.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if id, ok := kv.Key.(*ast.Ident); !ok || id.Name != "verb" {
					continue
				}
				if s, ok := stringLit(kv.Value); ok {
					verbs[s] = true
				}
			}
		}
		return false
	})
	if len(verbs) == 0 {
		t.Fatal("в cmd/hop/cli.go не разобралась таблица commands — охрана ослепла, а не продукт исправен")
	}
	return verbs
}

// hopdFlagDefault — умолчание флага hopd разбором cmd/hopd/main.go.
func hopdFlagDefault(t *testing.T, name string) string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(repoRoot(t), "cmd", "hopd", "main.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var def string
	var found bool
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "flag" {
			return true
		}
		if s, ok := stringLit(call.Args[0]); !ok || s != name {
			return true
		}
		if s, ok := stringLit(call.Args[1]); ok {
			def, found = s, true
		}
		return false
	})
	if !found {
		t.Fatalf("в cmd/hopd/main.go не найдено умолчание флага -%s", name)
	}
	return def
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
