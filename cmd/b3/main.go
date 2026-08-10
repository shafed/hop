// Команда b3 — замеры этапа 3, поверх netstack.
//
//	-mode rtt       RTT коротких TCP-обменов через стек. Долг этапа 1: B1
//	                показал, что стоимость границы тонет в пропускной
//	                способности на 1400 байтах и батче 128, и что всплыть она
//	                должна на интерактивном трафике мелкими пакетами. Порога
//	                нет — базовая линия, как B1 на Unix.
//	-mode fullcone  B3 (§8.6): 500 исходящих UDP-портов, каждый на несколько
//	                адресов. Проверяет, что NAT-таблица не деградирует и не
//	                течёт. Порог не в скорости: потерянный ответ — провал.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/shafed/hop/internal/bench"
)

func main() {
	var (
		mode      = flag.String("mode", "all", "rtt | fullcone | all")
		connects  = flag.Int("connects", 200, "сколько соединений мерить на рукопожатие")
		exchanges = flag.Int("exchanges", 2000, "сколько запрос-ответов мерить")
		payload   = flag.Int("payload", 64, "размер запроса, байт")
		ports     = flag.Int("ports", 500, "одновременных исходящих UDP-портов")
		fanout    = flag.Int("fanout", 3, "адресов на порт")
		rounds    = flag.Int("rounds", 20, "обходов всех пар")
		asJSON    = flag.Bool("json", false, "машиночитаемый вывод")
	)
	flag.Parse()

	cfg := bench.NetstackConfig{
		Connects: *connects, Exchanges: *exchanges, Payload: *payload,
		Ports: *ports, Fanout: *fanout, Rounds: *rounds,
	}

	var results []bench.Result
	var err error
	switch *mode {
	case "rtt":
		results, err = bench.NetstackRTT(cfg)
	case "fullcone":
		results, err = bench.FullCone(cfg)
	case "all":
		results, err = bench.NetstackRTT(cfg)
		if err == nil {
			var more []bench.Result
			more, err = bench.FullCone(cfg)
			results = append(results, more...)
		}
	default:
		err = fmt.Errorf("неизвестный режим %q", *mode)
	}

	// Результаты печатаются и при ошибке: замер, дошедший до половины, всё
	// равно рассказывает больше, чем одна строка «упало».
	if len(results) > 0 {
		if *asJSON {
			fmt.Println(bench.JSON(results))
		} else {
			fmt.Printf("b3: %s/%s, %d CPU, go %s\n\n",
				runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
			fmt.Print(bench.Table(results))
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "b3:", err)
		os.Exit(1)
	}
}
