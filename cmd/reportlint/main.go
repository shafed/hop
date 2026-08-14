// Команда reportlint держит классификацию §6.15 в одном месте (D10).
//
// health.ReportFailure объявляет узел мёртвым. Если звать его можно откуда
// угодно, перечисление §6.15 перестаёт быть замкнутым не сразу и не заметно:
// сперва кто-то добавит «ну это же явно отказ узла» рядом с местом, где ошибка
// под рукой, потом такое место станет вторым, и однажды упавший сайт унесёт
// живой узел. Ровно этот сценарий §6.15 и описывает.
//
// Поэтому вызов разрешён ровно в internal/engine/classify.go — в функции
// Engine.report, куда сходятся все исходы исходящего.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const banned = "ReportFailure"

// allowed — единственный файл, которому вызов разрешён.
const allowed = "internal/engine/classify.go"

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	var found int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "refs" || name == ".git" || strings.HasPrefix(name, "_") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || isExempt(path) {
			return nil
		}
		n, err := checkFile(path)
		found += n
		return err
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if found > 0 {
		fmt.Fprintf(os.Stderr, "reportlint: %d вызовов %s вне %s\n", found, banned, allowed)
		os.Exit(1)
	}
	fmt.Println("reportlint: чисто")
}

func isExempt(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	// Тесты не входят в продукт: расползтись классификации они не дают, а
	// драйвить ими health-монитор через его же Reporter — законный способ.
	return strings.HasSuffix(clean, "_test.go") || strings.HasSuffix(clean, allowed)
}

func checkFile(path string) (int, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return 0, err
	}

	var found int
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != banned {
			return true
		}
		pos := fset.Position(sel.Pos())
		fmt.Fprintf(os.Stderr, "%s: вызов %s вне %s — классификация §6.15 живёт в одном месте\n",
			pos, banned, allowed)
		found++
		return true
	})
	return found, nil
}
