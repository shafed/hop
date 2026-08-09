// Package negcheck — негативная задача §8: убедиться, что охраняющий тест
// зелен с политикой и красен без неё.
//
// Проверяются оба направления. Только «красен без политики» недостаточно:
// вечно сломанный тест удовлетворяет ему, ничего при этом не проверяя.
package negcheck

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shafed/hop/internal/policy"
)

// Problem — обнаруженный дефект оракула.
type Problem struct {
	Policy string
	Guard  policy.Guard
	Reason string
}

func (p Problem) String() string {
	return fmt.Sprintf("%s: %s %s — %s", p.Policy, p.Guard.Pkg, p.Guard.Test, p.Reason)
}

// Check прогоняет каждый охраняющий тест дважды и возвращает дефекты.
// root — корень модуля.
func Check(root string, policies []*policy.Policy) []Problem {
	var problems []Problem
	for _, p := range policies {
		for _, g := range p.Guards {
			if ok, out := runGuard(root, g, ""); !ok {
				problems = append(problems, Problem{p.Name, g,
					"красен при включённой политике:\n" + indent(out)})
				continue
			}
			if ok, _ := runGuard(root, g, p.Name); ok {
				problems = append(problems, Problem{p.Name, g,
					"зелен при выключенной политике — тест ничего не проверяет"})
			}
		}
	}
	return problems
}

// runGuard возвращает true, если тест прошёл. disable — имя политики,
// которую надо выключить, или "".
func runGuard(root string, g policy.Guard, disable string) (bool, string) {
	cmd := exec.Command("go", "test", "-count=1", "-run", g.Test, g.Pkg)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "HOP_DISABLE="+disable)
	out, err := cmd.CombinedOutput()
	return err == nil, string(out)
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = "    " + lines[i]
	}
	return strings.Join(lines, "\n")
}

// ModuleRoot ищет корень модуля вверх от dir.
func ModuleRoot(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod не найден вверх от %s", dir)
		}
		dir = parent
	}
}
