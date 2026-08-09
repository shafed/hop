// Команда negcheck — негативная CI-задача §8.
package main

import (
	"fmt"
	"os"

	"github.com/shafed/hop/internal/negcheck"
	"github.com/shafed/hop/internal/policy"
)

func main() {
	root, err := negcheck.ModuleRoot(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	policies := policy.All()
	fmt.Printf("negcheck: %d политик\n", len(policies))

	problems := negcheck.Check(root, policies)
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "ДЕФЕКТ ОРАКУЛА "+p.String())
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
	fmt.Println("negcheck: все политики охраняются краснеющим тестом")
}
