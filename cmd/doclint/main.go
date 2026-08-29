// Команда doclint — третий линтер семьи §8, нацеленный на документы. Проза
// утверждает состояние; линтер требует, чтобы за утверждением стояло что-то
// исполнимое: тест с таким номером, запись в реестре политик, файл на диске,
// ссылка git. Исключения — одной строкой в docs/not-yet-written.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/shafed/hop/internal/doclint"
	"github.com/shafed/hop/internal/policy"
)

func main() {
	useGit := flag.Bool("git", true, "проверять ветки и хеши, названные в HANDOFF.json")
	flag.Parse()

	root := "."
	if flag.NArg() > 0 {
		root = flag.Arg(0)
	}

	cfg := doclint.Config{Root: root}
	for _, p := range policy.All() {
		cfg.Policies = append(cfg.Policies, p.Name)
	}
	if *useGit {
		cfg.ResolveRef = gitResolver(root)
	}

	found, err := doclint.Check(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, f := range found {
		fmt.Fprintln(os.Stderr, f)
	}
	if len(found) > 0 {
		fmt.Fprintf(os.Stderr, "doclint: утверждений без исполнимой проверки: %d\n", len(found))
		os.Exit(1)
	}
	fmt.Println("doclint: чисто")
}

// gitResolver спрашивает у git, разрешается ли имя. Ветки проходов живут
// только на машине разработчика, поэтому в CI проверка выключается флагом
// -git=false: чекаут там ни веток проходов, ни полной истории не содержит.
func gitResolver(root string) func(string) bool {
	return func(name string) bool {
		for _, ref := range []string{name, "origin/" + name} {
			cmd := exec.Command("git", "-C", root, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
			if err := cmd.Run(); err == nil {
				return true
			}
		}
		return false
	}
}
