package engine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shafed/hop/internal/negcheck"
)

// TestReportFailureHasOneCallSite — линт этапа 4 из PLAN.md: health.ReportFailure
// не вызывается ниоткуда, кроме одной функции, оборачивающей dial.
//
// Он же W29 регистра связки (docs/verification-agent.md, §5.6): «остаётся
// зелёным после появления agent». Отдельного теста этой строке не нужно —
// обход идёт от корня модуля, и новый пакет попадает под линт в тот же день,
// когда появляется.
//
// Две соседние строки §5.6 этим тестом не закрыты и стоят в
// docs/not-yet-written.md: они поведенческие, а здесь разбирается AST — ни
// дозвона, ни живости в этой проверке нет вовсе. Их номера тут не названы
// намеренно: cmd/doclint читает номер в doc-комментарии как утверждение
// «закрыто», и упоминание вскользь закрыло бы обе.
//
// §6.15 требует замкнутого перечисления не ради типа, а ради того, чтобы
// классификация жила в одном месте. Перечисление это гарантирует наполовину:
// оно мешает выдумать новый вид отказа, но не мешает раздать существующие по
// всему коду. Второй половиной служит этот тест.
//
// Разрешённые места:
//   - internal/health — там метод объявлен, и там же его зовёт тест;
//   - internal/engine/classify.go — DialError.Report, единственный вызов в продукте;
//   - любые _test.go — стенды вправе сообщать отказы напрямую.
func TestReportFailureHasOneCallSite(t *testing.T) {
	root, err := negcheck.ModuleRoot(".")
	if err != nil {
		t.Fatalf("корень модуля: %v", err)
	}

	allowed := map[string]bool{
		filepath.Join("internal", "engine", "classify.go"): true,
	}

	var offenders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "refs", ".git", "dist":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// В самом health метод объявлен — объявление не вызов, но и вызовы
		// внутри пакета допустимы: там он и живёт.
		if strings.HasPrefix(rel, filepath.Join("internal", "health")) {
			return nil
		}

		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "ReportFailure" {
				return true
			}
			if allowed[rel] {
				return true
			}
			offenders = append(offenders, rel+":"+fset.Position(call.Pos()).String())
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("обход дерева: %v", err)
	}

	for _, o := range offenders {
		t.Errorf("вызов health.ReportFailure вне классификатора: %s", o)
	}
	if len(offenders) > 0 {
		t.Log("вердикт §6.15 ставится в internal/engine/classify.go и больше нигде: " +
			"иначе классификация расползётся по коду и однажды тихо начнёт считать смертью упавший сайт")
	}
}
