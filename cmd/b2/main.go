// Команда b2 — замер B2 (§8.6): стоимость проб.
//
// Считает, сколько исходящих соединений расписание §6.5 просит за час при
// подписке в 200 узлов. Порог — bench.ProbeCostBudget; рост означает, что
// расписание деградировало до полного обхода, который §6.5 и запрещает.
//
// Настоящего часа замер не занимает: часы фейковые, и весь час прокручивается
// за доли секунды. Поэтому гейт стоит на всех трёх ОС, а не только там, где
// есть время его гонять.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/shafed/hop/internal/bench"
	"github.com/shafed/hop/internal/health"
)

func main() {
	var (
		nodes  = flag.Int("nodes", bench.ProbeCostNodes, "размер подписки")
		window = flag.Duration("window", time.Hour, "окно наблюдения")
		step   = flag.Duration("step", time.Second, "шаг прокрутки фейковых часов")
		gate   = flag.Bool("gate", true, "применять порог §6.5")
		asJSON = flag.Bool("json", false, "машиночитаемый вывод")
	)
	flag.Parse()

	res, err := bench.ProbeCost(bench.ProbeCostConfig{
		Nodes:  *nodes,
		Window: *window,
		Step:   *step,
		Sched:  health.DefaultScheduleConfig(),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "b2:", err)
		os.Exit(1)
	}

	if *asJSON {
		out, _ := json.Marshal(struct {
			bench.ProbeCostResult
			PerHour float64 `json:"conns_per_hour"`
			Budget  float64 `json:"budget_per_hour"`
		}{res, res.ConnsPerHour(), bench.ProbeCostBudget})
		fmt.Println(string(out))
	} else {
		fmt.Printf("b2: %s/%s, go %s\n\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
		fmt.Printf("  подписка          %d узлов\n", res.Nodes)
		fmt.Printf("  окно              %v\n", res.Window)
		fmt.Printf("  проб              %d\n", res.Probes)
		fmt.Printf("  соединений        %d (%.0f в час)\n", res.Conns, res.ConnsPerHour())
	}

	if !*gate {
		return
	}
	// Порог назван для подписки §6.5; на другом составе печатается число, но
	// сравнивать его с этим бюджетом не с чем.
	if *nodes != bench.ProbeCostNodes {
		fmt.Printf("\nгейт: не применяется на %d узлах — бюджет назван для %d (§6.5)\n",
			*nodes, bench.ProbeCostNodes)
		return
	}
	per := res.ConnsPerHour()
	if per > bench.ProbeCostBudget {
		fmt.Fprintf(os.Stderr, "\nгейт ПРОВАЛЕН: %.0f соединений в час > бюджета %d\n",
			per, bench.ProbeCostBudget)
		os.Exit(1)
	}
	fmt.Printf("\nгейт взят: %.0f соединений в час при бюджете %d, запас %.1fx\n",
		per, bench.ProbeCostBudget, bench.ProbeCostBudget/per)
}
