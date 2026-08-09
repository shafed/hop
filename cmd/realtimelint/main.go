// Команда realtimelint запрещает обращение к настоящему времени вне
// internal/clock (§8.1). Исключение помечается комментарием //hop:realtime
// на той же строке — иначе исключений нет.
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

var banned = map[string]bool{
	"Now": true, "Since": true, "Until": true,
	"After": true, "AfterFunc": true, "Tick": true,
	"NewTicker": true, "NewTimer": true, "Sleep": true,
}

// Каталоги, где настоящее время — суть работы, а не оплошность.
var exempt = []string{
	"internal/clock",   // сам пакет часов
	"cmd/realtimelint", // этот линтер
}

const marker = "//hop:realtime"

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
		fmt.Fprintf(os.Stderr, "realtimelint: %d обращений к настоящему времени вне internal/clock\n", found)
		os.Exit(1)
	}
	fmt.Println("realtimelint: чисто")
}

func isExempt(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	for _, e := range exempt {
		if strings.Contains(clean, e+"/") {
			return true
		}
	}
	return false
}

func checkFile(path string) (int, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return 0, err
	}

	allowed := map[int]bool{}
	for _, group := range f.Comments {
		for _, c := range group.List {
			if strings.Contains(c.Text, marker) {
				allowed[fset.Position(c.Pos()).Line] = true
			}
		}
	}

	var found int
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || !banned[sel.Sel.Name] {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "time" {
			return true
		}
		pos := fset.Position(sel.Pos())
		if allowed[pos.Line] {
			return true
		}
		fmt.Fprintf(os.Stderr, "%s: time.%s вне internal/clock (пометьте %s, если это осознанно)\n",
			pos, sel.Sel.Name, marker)
		found++
		return true
	})
	return found, nil
}
