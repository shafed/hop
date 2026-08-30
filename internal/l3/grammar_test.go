//go:build linux

package l3

// TestL3StandSpeaksTheGrammar — охрана инструментария, не строка регистра.
//
// Существо, которое она чинит: стенд L3 зовёт продукт через exec.Command,
// собирая argv строками, и ничто не связывало эти строки с грамматикой §5.9
// (таблица `commands` в cmd/hop/cli.go). Проход CLI (ef9027d) снял флаги Р40 —
// стенд продолжал звать `hop -socket …`, интерфейс не поднимался, весь пакет
// internal/l3 падал, а l3-linux в CI был красен целый проход, потому что L3 не
// входил в обычный гейт (implementation-notes.md, «Стенд L3 не говорил с
// продуктом с прохода CLI»; HANDOFF.json → closed_this_pass → «T25, T26 и T27
// на L3», found_first).
//
// Форма — разбор AST, а не повторный список глаголов и флагов в самом тесте:
// копия однажды уже дала ложный зелёный (CLI-проход хранил свой список
// подкоманд отдельно от cmd/hop/cli.go — см. HANDOFF.json). Здесь источник
// один — сама таблица `commands` и функции-установщики флагов в cmd/hop, а
// тест читает их разбором исходника, не исполняя пакет main (cmd/hop —
// package main, второй такой в процессе теста не собрать).
//
// Работает без HOP_L3 и без unshare: это статический анализ исходников, а не
// запуск сети или продукта, и поэтому идёт в обычном `go test ./...`, а не
// только под HOP_L3 — ровно то место, где предыдущая поломка пряталась целый
// проход (HANDOFF.json → gate.rule_learned).
//
// Устойчивость к параллельной правке таблицы: тест проверяет, что стенд не
// зовёт то, чего в грамматике нет, а не что грамматика совпадает со списком
// стенда. Новый глагол (например, проведённый через сокет `hop nodes`)
// добавляется в `commands` и не трогает этот тест вовсе, пока стенд его не
// вызовет.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/shafed/hop/internal/negcheck"
)

// grammarCmd — то, что тест знает про один глагол §5.9: полное имя
// («verb» или «verb sub») и множество флагов, которые для него зарегистрировал
// cmd.setup (плюс --json, если команда читающая — dispatch добавляет его сам,
// в стороне от setup, cmd/hop/cli.go: `if cmd.reads { fs.BoolVar(&opts.json…`).
type grammarCmd struct {
	name  string
	flags map[string]bool
}

// loadGrammar разбирает пакет cmd/hop (без _test.go) и строит грамматику §5.9
// из таблицы `commands`, а не из её пересказа.
func loadGrammar(t *testing.T, root string) map[string]grammarCmd {
	t.Helper()
	dir := filepath.Join(root, "cmd", "hop")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cmd/hop: %v", err)
	}

	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{} // top-level функции пакета — для разрешения setup-хелперов вроде clientFlags
	var files []*ast.File

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("разбор %s: %v", name, err)
		}
		files = append(files, f)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if ok && fd.Recv == nil {
				funcs[fd.Name.Name] = fd
			}
		}
	}

	// extractFlags собирает имена флагов, которые тело функции регистрирует
	// через fs.XxxVar("имя", …), включая флаги, унаследованные от вызова
	// другого top-level хелпера того же пакета (clientFlags и подобные).
	var extractFlags func(body *ast.BlockStmt, seen map[string]bool, out map[string]bool)
	extractFlags = func(body *ast.BlockStmt, seen map[string]bool, out map[string]bool) {
		if body == nil {
			return
		}
		ast.Inspect(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				if !strings.HasSuffix(fn.Sel.Name, "Var") || len(call.Args) < 2 {
					return true
				}
				lit, ok := call.Args[1].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				name, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				out[name] = true
			case *ast.Ident:
				if seen[fn.Name] {
					return true
				}
				if helper, ok := funcs[fn.Name]; ok {
					seen[fn.Name] = true
					extractFlags(helper.Body, seen, out)
				}
			}
			return true
		})
	}

	flagsOf := func(expr ast.Expr) map[string]bool {
		out := map[string]bool{}
		switch e := expr.(type) {
		case *ast.FuncLit:
			extractFlags(e.Body, map[string]bool{}, out)
		case *ast.Ident:
			if helper, ok := funcs[e.Name]; ok {
				extractFlags(helper.Body, map[string]bool{e.Name: true}, out)
			}
		}
		return out
	}

	grammar := map[string]grammarCmd{}
	multiWordVerb := map[string]bool{}

	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "commands" || len(vs.Values) != 1 {
					continue
				}
				sliceLit, ok := vs.Values[0].(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, elt := range sliceLit.Elts {
					cl, ok := elt.(*ast.CompositeLit)
					if !ok {
						continue
					}
					var verb, sub string
					var reads bool
					var setupExpr ast.Expr
					for _, kv := range cl.Elts {
						kve, ok := kv.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := kve.Key.(*ast.Ident)
						if !ok {
							continue
						}
						switch key.Name {
						case "verb":
							if lit, ok := kve.Value.(*ast.BasicLit); ok {
								verb, _ = strconv.Unquote(lit.Value)
							}
						case "sub":
							if lit, ok := kve.Value.(*ast.BasicLit); ok {
								sub, _ = strconv.Unquote(lit.Value)
							}
						case "reads":
							if id, ok := kve.Value.(*ast.Ident); ok {
								reads = id.Name == "true"
							}
						case "setup":
							setupExpr = kve.Value
						}
					}
					if verb == "" {
						continue
					}
					name := verb
					if sub != "" {
						name = verb + " " + sub
						multiWordVerb[verb] = true
					}
					flags := map[string]bool{}
					if setupExpr != nil {
						flags = flagsOf(setupExpr)
					}
					if reads {
						flags["json"] = true // добавлен в dispatch, не в setup — см. cmd/hop/cli.go
					}
					grammar[name] = grammarCmd{name: name, flags: flags}
				}
			}
		}
	}

	if len(grammar) == 0 {
		t.Fatal("таблица commands не найдена или пуста в cmd/hop/cli.go — разбор AST сломан")
	}
	return grammar
}

// hopInvocations находит в исходниках internal/l3 (кроме этого файла) все
// вызовы exec.Command(hopAgent(...), …) — то есть обращения к клиенту `hop`,
// а не к сервису hopd (у него нет грамматики §5.9, см. cmd/hopd/main.go —
// плоские флаги, отдельная поверхность §3.1) — и достаёт из них argv,
// собранный из строковых литералов.
type invocation struct {
	file string
	line int
	args []string // только строковые литералы; переменные (значения флагов) пропущены
}

func hopInvocations(t *testing.T, root string) []invocation {
	t.Helper()
	dir := filepath.Join(root, "internal", "l3")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("internal/l3: %v", err)
	}

	fset := token.NewFileSet()
	var out []invocation

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") || name == "grammar_test.go" {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("разбор %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "exec" || sel.Sel.Name != "Command" || len(call.Args) == 0 {
				return true
			}
			bin, ok := call.Args[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			binFn, ok := bin.Fun.(*ast.Ident)
			if !ok || binFn.Name != "hopAgent" {
				return true // hopd(t), "ip", "go" и т.п. — вне грамматики §5.9
			}
			var args []string
			for _, a := range call.Args[1:] {
				lit, ok := a.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue // значение флага переменной (sock, link, ifname…) — не проверяем статически
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					continue
				}
				args = append(args, s)
			}
			out = append(out, invocation{file: name, line: fset.Position(call.Pos()).Line, args: args})
			return true
		})
	}
	return out
}

// TestL3StandSpeaksTheGrammar сверяет argv, которые стенд строит для `hop`, с
// грамматикой §5.9, разобранной из cmd/hop/cli.go.
func TestL3StandSpeaksTheGrammar(t *testing.T) {
	root, err := negcheck.ModuleRoot(".")
	if err != nil {
		t.Fatalf("корень модуля: %v", err)
	}

	grammar := loadGrammar(t, root)
	invocations := hopInvocations(t, root)
	if len(invocations) == 0 {
		t.Fatal("в internal/l3 не нашлось ни одного exec.Command(hopAgent(...), …) — " +
			"тест сверяет пустоту с пустотой, это не проверка")
	}

	multiWord := map[string]bool{}
	for name := range grammar {
		if strings.Contains(name, " ") {
			multiWord[strings.SplitN(name, " ", 2)[0]] = true
		}
	}

	for _, inv := range invocations {
		if len(inv.args) == 0 {
			t.Errorf("%s:%d: вызов hop без различимого глагола (первый аргумент не строковый литерал)", inv.file, inv.line)
			continue
		}
		verb := inv.args[0]
		rest := inv.args[1:]
		name := verb
		if multiWord[verb] {
			if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
				t.Errorf("%s:%d: `%s` требует под-глагола (node add|rm, sub add), а стенд его не передал",
					inv.file, inv.line, verb)
				continue
			}
			name = verb + " " + rest[0]
			rest = rest[1:]
		}

		cmd, ok := grammar[name]
		if !ok {
			t.Errorf("%s:%d: стенд зовёт `hop %s`, а такого глагола нет в таблице commands (cmd/hop/cli.go, §5.9)",
				inv.file, inv.line, name)
			continue
		}

		for _, a := range rest {
			if !strings.HasPrefix(a, "-") {
				continue // позиционный аргумент (id, ссылка…) — не флаг, не проверяем
			}
			flag := strings.TrimLeft(a, "-")
			if i := strings.IndexByte(flag, '='); i >= 0 {
				flag = flag[:i]
			}
			if !cmd.flags[flag] {
				t.Errorf("%s:%d: `hop %s` зовётся с флагом -%s, которого нет среди флагов, "+
					"зарегистрированных для этого глагола в cmd/hop/cli.go", inv.file, inv.line, name, flag)
			}
		}
	}

	if t.Failed() {
		names := make([]string, 0, len(grammar))
		for n := range grammar {
			names = append(names, n)
		}
		sort.Strings(names)
		t.Logf("грамматика §5.9, разобранная из cmd/hop/cli.go: %s", strings.Join(names, ", "))
	}
}
