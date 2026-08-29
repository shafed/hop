package main

import (
	"fmt"
	"io"

	"github.com/shafed/hop/internal/agent"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/store"
)

// Настройки маршрутизации (§6.10) и апстримов (§5.7) с диска.
//
// Это временный интерфейс ровно в том же смысле, что и остальные флаги
// cmd/hop: подкомандами §5.9 он станет тогда же, когда ими станут `-sub` и
// `-nodes`, и наденется поверх этих же вызовов — вся работа здесь делается
// пакетом store, а не разбором аргументов.

// applySettings переносит настройки стора в конфигурацию связки.
//
// Отдельная функция, а не две строки в литерале agent.Config: это единственный
// шов между диском и продуктом, и он молчалив — оба поля необязательны, nil у
// каждого означает умолчания, поэтому забытый перенос не ломает ни сборку, ни
// модульные тесты. Функция существует затем, чтобы W52 и W53 могли на него
// смотреть, не поднимая ни туннеля, ни сервиса.
func applySettings(cfg *agent.Config, st *store.Store) {
	set := st.Settings()
	cfg.Routing = set.Routing
	cfg.DNSUpstreams = set.DNSUpstreams
}

// showSettings печатает не файл, а то, что из файла следует.
//
// Два раздела вместо одного «действующего списка» — не лень, а граница
// пакетов: слияние конфигурации с исключениями §5.6 делает netstack
// (resolveRouting), и оно не вынесено наружу. Вывод поэтому показывает обе
// половины и словами объясняет, что стек с ними сделает. Умолчания §6.10 при
// этом настоящие — netstack.DefaultRouting, а не список, переписанный сюда
// руками: переписанный разошёлся бы с кодом молча.
func showSettings(st *store.Store, path string, out io.Writer) error {
	fmt.Fprintf(out, "файл настроек: %s\n", path)

	set := st.Settings()
	def := netstack.DefaultRouting()

	fmt.Fprintln(out, "\nумолчания §6.10 — то, что действует, когда раздела routing в файле нет:")
	printRules(out, "bypass", def.Bypass)
	printRules(out, "block", def.Block)

	fmt.Fprintln(out)
	if set.Routing == nil {
		fmt.Fprintln(out, "раздела routing в файле нет: действуют умолчания выше.")
	} else {
		fmt.Fprintln(out, "раздел routing в файле есть, в нём:")
		printRules(out, "bypass", set.Routing.Bypass)
		printRules(out, "block", set.Routing.Block)
		fmt.Fprintln(out, "\nчто стек сделает с этим списком:")
		fmt.Fprintln(out, "  исключения §5.6 — локальные сети, DHCP, NTP — подмешиваются к bypass всегда")
		fmt.Fprintln(out, "  и конфигурацией не убираются: «разрешены всегда» относится и к неудачному конфигу;")
		fmt.Fprintln(out, "  обнаружение служб (mDNS 224.0.0.251:5353, SSDP 239.255.255.250:1900) — наоборот,")
		fmt.Fprintln(out, "  умолчание, а не пол: раз раздел routing задан, оно действует только если выписано")
		fmt.Fprintln(out, "  в bypass явно.")
	}

	fmt.Fprintln(out)
	if len(set.DNSUpstreams) == 0 {
		fmt.Fprintln(out, "раздела dns_upstreams в файле нет: действуют стартовые апстримы §5.7.")
	} else {
		fmt.Fprintln(out, "апстримы §5.7 из файла:")
		for _, up := range set.DNSUpstreams {
			fmt.Fprintf(out, "  %s\n", up)
		}
	}
	return nil
}

func printRules(out io.Writer, list string, rules []netstack.Rule) {
	if len(rules) == 0 {
		fmt.Fprintf(out, "  %s: пусто\n", list)
		return
	}
	fmt.Fprintf(out, "  %s:\n", list)
	for _, r := range rules {
		fmt.Fprintf(out, "    %s\n", ruleLine(r))
	}
}

// ruleLine — правило одной строкой. Ноль печатается звёздочкой, а не
// опускается: «любой порт» и «порт забыли» обязаны выглядеть по-разному.
func ruleLine(r netstack.Rule) string {
	prefix := "*"
	if r.Prefix.IsValid() {
		prefix = r.Prefix.String()
	}
	proto := "*"
	switch r.Proto {
	case netstack.ProtoTCP:
		proto = "tcp"
	case netstack.ProtoUDP:
		proto = "udp"
	}
	port := "*"
	if r.Port != 0 {
		port = fmt.Sprint(r.Port)
	}
	return fmt.Sprintf("%-18s %-4s порт %s", prefix, proto, port)
}
