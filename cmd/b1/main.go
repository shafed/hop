// Команда b1 — бенчмарк B1 (§8.6): пропускная способность границы
// «сервис → агент».
//
// B1a меряет только трубу; B1b добавляет копию из кольца Wintun, которую
// реальный путь на Windows обязан делать (ReceivePacket отдаёт срез в кольцо, и
// кольцо надо освободить до записи в трубу). Гейтом §5.3 служит B1b и только на
// Windows: на Unix границы в горячем пути нет, там числа идут базовой линией.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shafed/hop/internal/bench"
)

// windowsGateMbps — единственный порог, ломающий сборку.
const windowsGateMbps = 500

func main() {
	var (
		mode     = flag.String("mode", "boundary", "boundary | tun | all")
		pkt      = flag.Int("pkt", 1400, "размер пакета, байт")
		batches  = flag.String("batches", "1,8,32,64,128", "размеры батча")
		duration = flag.Duration("duration", 3*time.Second, "длительность одного замера")
		samples  = flag.Int("latency-samples", 20000, "число ping-pong замеров латентности")
		asJSON   = flag.Bool("json", false, "машиночитаемый вывод")
		gate     = flag.Bool("gate", true, "применять порог B1b на Windows")
	)
	flag.Parse()

	var results []bench.Result
	var err error

	switch *mode {
	case "boundary":
		results, err = runBoundary(*pkt, parseBatches(*batches), *duration, *samples)
	case "tun":
		results, err = runTUN(*pkt, *duration)
	case "all":
		results, err = runBoundary(*pkt, parseBatches(*batches), *duration, *samples)
		if err == nil {
			var more []bench.Result
			more, err = runTUN(*pkt, *duration)
			results = append(results, more...)
		}
	default:
		err = fmt.Errorf("неизвестный режим %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "b1:", err)
		os.Exit(2)
	}

	if *asJSON {
		fmt.Println(bench.JSON(results))
	} else {
		fmt.Printf("b1: %s/%s, %d CPU, go %s\n\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
		fmt.Print(bench.Table(results))
	}

	if *gate {
		os.Exit(checkGate(results))
	}
}

// checkGate применяет порог. На Linux и macOS порога нет намеренно (D4).
func checkGate(results []bench.Result) int {
	if runtime.GOOS != "windows" {
		fmt.Printf("\nгейт: не применяется на %s — числа идут базовой линией (D4)\n", runtime.GOOS)
		return 0
	}
	best := 0.0
	for _, r := range results {
		if strings.Contains(r.Name, "B1b") && r.Mbps() > best {
			best = r.Mbps()
		}
	}
	if best == 0 {
		fmt.Fprintln(os.Stderr, "\nгейт: не найдено ни одного замера B1b")
		return 1
	}
	if best < windowsGateMbps {
		fmt.Fprintf(os.Stderr, "\nгейт ПРОВАЛЕН: B1b %.1f Мбит/с < %d Мбит/с\n", best, windowsGateMbps)
		return 1
	}
	fmt.Printf("\nгейт взят: B1b %.1f Мбит/с при пороге %d, запас %.1fx\n",
		best, windowsGateMbps, best/windowsGateMbps)
	return 0
}

func runBoundary(pkt int, batches []int, dur time.Duration, samples int) ([]bench.Result, error) {
	var out []bench.Result

	for _, batch := range batches {
		for _, ring := range []bool{false, true} {
			cfg := bench.Config{
				PktSize: pkt, Batch: batch, Duration: dur,
				ReadBuf: 256 << 10, RingCopy: ring,
			}
			name := "B1a " + boundaryName() + " одностор."
			if ring {
				name = "B1b " + boundaryName() + " кольцо+труба"
			}
			b, err := bench.NewBoundary()
			if err != nil {
				return nil, err
			}
			r, err := bench.Throughput(name, b.ServiceToAgent, cfg)
			b.Close()
			if err != nil {
				return nil, err
			}
			out = append(out, progress(r))
		}
	}

	// Двунаправленно на крупном батче: полудуплекс не должен душить встречный
	// поток — ради этого труб две.
	big := batches[len(batches)-1]
	cfg := bench.Config{PktSize: pkt, Batch: big, Duration: dur, ReadBuf: 256 << 10, RingCopy: true}
	b, err := bench.NewBoundary()
	if err != nil {
		return nil, err
	}
	type res struct {
		r   bench.Result
		err error
	}
	ch := make(chan res, 2)
	go func() {
		r, err := bench.Throughput("B1b "+boundaryName()+" двустор. с→а", b.ServiceToAgent, cfg)
		ch <- res{r, err}
	}()
	go func() {
		r, err := bench.Throughput("B1b "+boundaryName()+" двустор. а→с", b.AgentToService, cfg)
		ch <- res{r, err}
	}()
	for i := 0; i < 2; i++ {
		got := <-ch
		if got.err != nil {
			b.Close()
			return nil, got.err
		}
		out = append(out, progress(got.r))
	}
	b.Close()

	// Латентность и джиттер: реальный риск не в пропускной способности.
	lb, err := bench.NewBoundary()
	if err != nil {
		return nil, err
	}
	lat, err := bench.Latency("L "+boundaryName()+" ping-pong",
		lb.ServiceToAgent, lb.AgentToService,
		bench.Config{PktSize: pkt, Batch: 1, Duration: dur, ReadBuf: 256 << 10}, samples)
	lb.Close()
	if err != nil {
		return nil, err
	}
	return append(out, progress(lat)), nil
}

func parseBatches(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n <= 0 {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		out = []int{32}
	}
	return out
}

// progress печатает каждый готовый замер в stderr сразу. Без этого падение
// посреди прогона уносит с собой всё, что уже было измерено: таблица идёт в
// stdout только в самом конце.
func progress(r bench.Result) bench.Result {
	fmt.Fprintf(os.Stderr, "  %-34s батч %3d  %9.1f Мбит/с\n", r.Name, r.Batch, r.Mbps())
	return r
}
