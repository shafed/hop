//go:build linux

package platform

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/shafed/hop/internal/policy"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// W50 — §5.8 регистра: `up` не только закрывает IPv6, но и отказывает тем
// соединениям IPv6, которые были установлены до него.
//
// Проверяется список шагов, а не сеть, по той же причине, что и в W48: это
// единственная половина решения, которую видно без прав. Вторая половина —
// что ядро действительно превращает молчание в `ECONNABORTED` — живёт в
// internal/l3 и в реестре политик не названа: negcheck гоняет `go test`, а L3
// без HOP_L3 пропускается и был бы зелен при любом состоянии флага.
//
// Три утверждения, и каждое своё:
//  1. шаг зачистки в списке есть — иначе сокет висит до таймаута TCP (§5.6);
//  2. он стоит СРАЗУ за правилом IPv6 — раньше правила зачистка бессмысленна
//     (убитое переустановится), позже — окно молчания длиннее без нужды;
//  3. отката у него нет, и это утверждение, а не забывчивость: разрушенный
//     сокет обратно не собрать, а снапшот §8.4 сокетов не содержит вовсе.
func TestW50UpSweepsSilencedIPv6(t *testing.T) {
	// Без правила §6.9 зачистки в Up нет и быть не должно: разрушать было бы
	// нечего, а работающие соединения IPv6 она порвала бы. Утверждение этой
	// охраны в такой сборке невыразимо, и краснеть ей полагается по своему
	// флагу, а не по чужому. Обратную сторону держит
	// TestIPv6KillIsAbsentWithoutTheRule.
	if !policy.IPv6Block.On() {
		t.Skip("зачистка осмысленна только вместе с правилом ipv6_block")
	}
	steps := upSteps(testParams(), discardLog())

	rule, kill := -1, -1
	for i := range steps {
		if isIPv6Rule(steps[i].add) {
			rule = i
		}
		if steps[i].name == stepKillIPv6 {
			kill = i
		}
	}
	if kill < 0 {
		t.Fatalf("в шагах Up нет зачистки сокетов IPv6 — соединение, установленное до up, "+
			"молчит до собственного таймаута TCP, а §5.6 требует отказа:\n%s", dump(steps))
	}
	if rule < 0 {
		t.Fatalf("нет шага с правилом IPv6, рядом с которым зачистка имеет смысл:\n%s", dump(steps))
	}
	if kill != rule+1 {
		t.Fatalf("зачистка стоит шагом %d, правило IPv6 — шагом %d; ожидалось сразу за правилом:\n%s",
			kill, rule, dump(steps))
	}
	if steps[kill].do == nil {
		t.Fatalf("шаг %q ничего не исполняет", steps[kill].name)
	}
	if steps[kill].add != nil {
		t.Fatalf("шаг %q выражен командой %v — SOCK_DESTROY командой ip не выражается",
			steps[kill].name, steps[kill].add)
	}
	if steps[kill].del != nil {
		t.Fatalf("у шага %q объявлен откат %v — разрушенный сокет обратно не собрать",
			steps[kill].name, steps[kill].del)
	}
}

// Зависимость односторонняя: без правила §6.9 зачистка не бесполезна, а
// вредна — она рвала бы работающие соединения IPv6. Тест смысл имеет только
// при выключенном ipv6_block, то есть в прогоне negcheck по чужому флагу;
// охраной он не служит.
func TestIPv6KillIsAbsentWithoutTheRule(t *testing.T) {
	if policy.IPv6Block.On() {
		t.Skip("проверка про ipv6_block=off")
	}
	for _, s := range upSteps(testParams(), discardLog()) {
		if s.name == stepKillIPv6 {
			t.Fatal("правила IPv6 нет, а зачистка есть: она порвёт живые соединения")
		}
	}
}

func sock(state uint8, dst string) *netlink.Socket {
	return &netlink.Socket{
		Family: unix.AF_INET6,
		State:  state,
		ID: netlink.SocketID{
			Source:      net.ParseIP("fd00:9:9::1"),
			Destination: net.ParseIP(dst),
		},
	}
}

// Отбор — обратная сторона §6.9: зачищать надо ровно то, что правило обрекло
// на молчание, и ничего сверх того. Каждая строка ниже — замер, а не догадка;
// они собраны в implementation-notes.md.
func TestSilencedIPv6LeavesAloneWhatTheRuleDoesNotBlock(t *testing.T) {
	own := map[string]bool{"::1": true, "fd00:9:9::1": true}

	cases := []struct {
		s    *netlink.Socket
		want bool
		why  string
	}{
		{sock(1, "2001:db8::1"), true, "маршрутизируемый unicast — правило его закрыло"},
		{sock(1, "fd00:1::5"), true, "ULA лежит в main, ниже правила"},
		{sock(2, "fe80::1"), true, "fe80 unicast тоже в main (§6.9), и SYN_SENT переживает правило"},
		{sock(1, "::1"), false, "::1 забирает таблица local приоритетом 0, выше правила"},
		{sock(1, "fd00:9:9::1"), false, "свой адрес машины — та же таблица local (замер)"},
		{sock(10, "::"), false, "слушатель ничего не отправляет; ядро на него отвечает EINVAL"},
		{sock(1, "::ffff:10.0.0.1"), false, "соединение IPv4 у dual-stack слушателя, в дампе AF_INET6 (замер)"},
	}
	for _, c := range cases {
		got := len(silencedIPv6([]*netlink.Socket{c.s}, own)) == 1
		if got != c.want {
			t.Errorf("[%s]:%d state=%d → зачистить=%v, ожидалось %v: %s",
				c.s.ID.Destination, c.s.ID.DestinationPort, c.s.State, got, c.want, c.why)
		}
	}

	all := make([]*netlink.Socket, len(cases))
	for i, c := range cases {
		all[i] = c.s
	}
	if got := len(silencedIPv6(all, own)); got != 3 {
		t.Fatalf("из общего дампа отобрано %d сокетов, ожидалось 3", got)
	}
}

// Ядро без CONFIG_INET_DIAG_DESTROY — деградация, а не поломка, и отличить её
// от исчезнувшего сокета обязан код, а не человек в логе. Замер: разрушение
// несуществующего сокета даёт ENOENT, а не EOPNOTSUPP, — то есть EOPNOTSUPP
// свободен под «ядро не умеет».
func TestKillOutcomeTellsUnsupportedKernelFromLostSocket(t *testing.T) {
	cases := []struct {
		err  error
		want killOutcome
	}{
		{nil, killDone},
		{unix.ENOENT, killGone},
		{unix.EOPNOTSUPP, killUnsupported},
		// ExtAck оборачивает errno текстом; классификация обязана смотреть
		// сквозь обёртку, иначе деградация выглядит как неизвестная ошибка.
		{fmt.Errorf("%w: сообщение ядра", unix.EOPNOTSUPP), killUnsupported},
		{unix.EPERM, killRefused},
		{unix.EINVAL, killRefused},
	}
	for _, c := range cases {
		if got := classifyKill(c.err); got != c.want {
			t.Errorf("classifyKill(%v) = %d, ожидалось %d", c.err, got, c.want)
		}
	}
}
