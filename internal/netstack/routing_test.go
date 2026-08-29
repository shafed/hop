package netstack

import (
	"net/netip"
	"testing"

	"github.com/shafed/hop/internal/packettest"
)

// Принтер в CGNAT-диапазоне (RFC 6598) — адрес, которого нет ни в одном
// умолчании §6.10: не loopback, не RFC1918, не link-local. При жёстком наборе
// verdict.go он уходил в туннель, и другого способа выпустить его в локальную
// сеть, кроме правки кода, не было.
var printer = netip.MustParseAddrPort("100.64.7.7:9100")

func printerRule() Rule {
	return Rule{Prefix: netip.MustParsePrefix("100.64.0.0/10")}
}

// Список bypass §6.10 приходит из конфигурации: адрес становится bypass только
// потому, что о нём сказали в конфиге.
//
// Охраняет routing_lists. При выключенной политике конфигурация не читается
// вовсе, и вердикт остаётся тем же proxy, что в первом утверждении, — тест
// краснеет на втором.
func TestRoutingBypassListComesFromConfig(t *testing.T) {
	f := tcpTo(printer.String())

	if got := classify(f, true, DefaultRouting()); got != Proxy {
		t.Fatalf("умолчания §6.10 уже выпускают %v: вердикт %v, ожидался proxy", printer, got)
	}

	rt := DefaultRouting()
	rt.Bypass = append(rt.Bypass, printerRule())

	if got := classify(f, true, resolveRouting(rt)); got != Bypass {
		t.Fatalf("правило из конфигурации не сработало: вердикт %v, ожидался bypass", got)
	}
}

// Обратное направление: конфигурация умеет и сузить список. Обнаружение служб
// §6.10 — не исключение §5.6, поэтому убранный из конфигурации mDNS перестаёт
// быть bypass и попадает под «прочий multicast» из того же §6.10.
//
// Тоже охраняет routing_lists: с выключенной политикой mDNS остаётся bypass по
// умолчанию.
func TestRoutingConfigCanDropServiceDiscovery(t *testing.T) {
	f := udpTo("224.0.0.251:5353")

	if got := classify(f, true, DefaultRouting()); got != Bypass {
		t.Fatalf("умолчание §6.10 сломано: mDNS получил %v, ожидался bypass", got)
	}

	narrow := resolveRouting(&Routing{Block: DefaultRouting().Block})
	if got := classify(f, true, narrow); got != Block {
		t.Fatalf("mDNS, убранный из конфигурации, получил %v, ожидался block", got)
	}

	// Тот же mDNS без списка блокировок уходит в туннель: сузив bypass,
	// конфигурация не обязана заодно блокировать.
	empty := resolveRouting(&Routing{})
	if got := classify(f, true, empty); got != Proxy {
		t.Fatalf("mDNS при пустых списках получил %v, ожидался proxy", got)
	}
}

// Пол §5.6 из конфигурации не вынимается: «локальные сети, DHCP, NTP —
// разрешены всегда». Пустая конфигурация не должна ломать саму сеть.
func TestRoutingAlwaysAllowedSurviveEmptyConfig(t *testing.T) {
	rt := resolveRouting(&Routing{})
	cases := []struct {
		name string
		f    flow
	}{
		{"локальная сеть", tcpTo("192.168.1.10:445")},
		{"loopback", tcpTo("127.0.0.1:8080")},
		{"link-local", udpTo("169.254.1.1:5000")},
		{"DHCP широковещательно", udpTo("255.255.255.255:67")},
		{"DHCP клиенту", udpTo("192.0.2.1:68")},
		{"NTP наружу", udpTo("216.239.35.0:123")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classify(c.f, true, rt); got != Bypass {
				t.Fatalf("исключение §5.6 потеряно: вердикт %v, ожидался bypass", got)
			}
		})
	}
}

// Второй список §6.10 — «Блокируем» — тоже из конфигурации.
func TestRoutingBlockListComesFromConfig(t *testing.T) {
	f := udpTo("203.0.113.7:1234")

	if got := classify(f, true, DefaultRouting()); got != Proxy {
		t.Fatalf("умолчания §6.10 уже блокируют %v: вердикт %v", f.dst, got)
	}

	rt := DefaultRouting()
	rt.Block = append(rt.Block, Rule{Proto: ProtoUDP, Port: 1234})
	if got := classify(f, true, resolveRouting(rt)); got != Block {
		t.Fatalf("правило блокировки из конфигурации не сработало: вердикт %v", got)
	}
}

// Пол §5.6 сильнее блокировки из конфигурации: bypass в §3.4 стоит раньше
// block. Иначе один неудачный конфиг оставлял бы машину без DHCP.
func TestRoutingBlockCannotOverrideAlwaysAllowed(t *testing.T) {
	rt := resolveRouting(&Routing{Block: []Rule{{Prefix: netip.MustParsePrefix("0.0.0.0/0")}}})
	if got := classify(udpTo("255.255.255.255:67"), true, rt); got != Bypass {
		t.Fatalf("DHCP заблокирован конфигурацией: вердикт %v, ожидался bypass", got)
	}
}

// Правило IPv4 не совпадает с IPv6-адресом. Проверка на будущее: сегодня IPv6
// до classify не доходит (§6.9, netstack.handle), и если он туда когда-нибудь
// дойдёт, список IPv4 не должен выпускать его мимо туннеля молча.
func TestRoutingIPv4RuleDoesNotMatchIPv6(t *testing.T) {
	f := flow{
		proto: protoUDP,
		src:   client,
		dst:   netip.MustParseAddrPort("[ff02::fb]:5353"),
	}
	if r := (Rule{Prefix: netip.MustParsePrefix("0.0.0.0/0")}); r.matches(f) {
		t.Fatal("правило 0.0.0.0/0 совпало с адресом IPv6")
	}
}

// T32 (§8.3). Тот же путь через поддельный PacketDevice, а не только через
// функцию вердикта: пакет на адрес, названный конфигурацией, физически уходит
// в приёмник bypass, а не в туннель и не в отказ.
//
// Стенд намеренно с fail-close (живых узлов нет): §5.6 закрывает всё, кроме
// исключений, и «конфигурация вывела поток в локальную сеть» проверяется тут в
// самой сильной форме — вопреки закрытому туннелю. Синхронизация без часов —
// приём TestBypassSendErrorCountsAsBlocked: насос один, ответ на второй пакет
// означает, что первый уже обработан.
func TestT32ConfiguredBypassLeavesTunnel(t *testing.T) {
	h := newHarness(t, false, func(cfg *Config) {
		rt := DefaultRouting()
		rt.Bypass = append(rt.Bypass, printerRule())
		cfg.Routing = rt
	})

	h.dev.Inject(packettest.UDP(client, printer, []byte("hello")))
	h.dev.Inject(packettest.UDP(client, udpPeerA, []byte("после")))
	h.dev.WaitEmitted(t, 1)

	pkts := h.byp.Packets()
	if len(pkts) != 1 {
		t.Fatalf("в локальную сеть ушло %d пакетов, ожидался один", len(pkts))
	}
	if src, dst := endpoints(pkts[0]); src != client || dst != printer {
		t.Fatalf("в локальную сеть ушло %v → %v", src, dst)
	}
	if st := h.st.Stats(); st.Blocked != 0 || st.Rejected != 1 {
		t.Fatalf("пакет из списка конфигурации заблокирован или отвергнут: %+v", st)
	}
	if h.dialer.Conn(client) != nil {
		t.Fatal("пакет ушёл в туннель, хотя конфигурация вывела его в локальную сеть")
	}
}
