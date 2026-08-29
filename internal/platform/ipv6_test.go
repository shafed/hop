//go:build linux

package platform

import (
	"fmt"
	"strings"
	"testing"

	"github.com/shafed/hop/internal/policy"
	"github.com/shafed/hop/internal/tunnel"
)

// Параметры туннеля здесь ровно те же, что у стенда L3 (internal/l3): тест
// смотрит на список шагов, а не на сеть, но совпадение параметров держит
// W48 и T28 разговором об одном и том же туннеле.
func testParams() tunnel.Params {
	return tunnel.Params{Name: "hopt0", Addr: "10.255.0.1/24", MTU: 1420, Table: 8421}
}

// W48 — §5.8 регистра: `up` закрывает IPv6, и делает это намеренно, а не
// побочным эффектом.
//
// Проверяется список шагов, а не сеть, потому что это единственная половина
// решения, которую можно проверить без прав: §6.2 тем же приёмом вынес
// респондер в чистую функцию отдельно от привилегированного ввода-вывода.
// Вторая половина — что ядро действительно перестаёт выпускать IPv6 — это
// T28 в internal/l3, и он в реестре политик не назван: negcheck гоняет
// `go test`, а L3 без HOP_L3 и netns пропускается, то есть был бы зелен при
// любом состоянии флага.
func TestW48UpBlocksIPv6(t *testing.T) {
	steps := upSteps(testParams())

	var found *step
	for i := range steps {
		if isIPv6Rule(steps[i].add) {
			found = &steps[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("в шагах Up нет ни одного правила IPv6 — IPv6 уходит мимо туннеля:\n%s", dump(steps))
	}

	// Тип правила несёт всё утверждение §5.6: unreachable даёт приложению
	// ENETUNREACH мгновенно, blackhole — молчание, ради которого §6.2
	// переписывался. Замер обоих — implementation-notes.md.
	if !contains(found.add, "unreachable") {
		t.Fatalf("правило IPv6 не unreachable: %v — §5.6 требует отказа, а не молчания", found.add)
	}
	// Приоритет тот же, что у туннельного правила: «всё остальное» — в
	// туннель для IPv4 и в отказ для IPv6. 31000 оставлен свободным на случай
	// исключений §5.6 для IPv6, которых сегодня нет.
	if !contains(found.add, fmt.Sprint(prioTunnel)) {
		t.Fatalf("правило IPv6 стоит не на приоритете туннеля %d: %v", prioTunnel, found.add)
	}
	// Без отката правило переживает down, и снапшот §8.4 после него не
	// совпадёт с исходным.
	if found.del == nil || !isIPv6Rule(found.del) || !contains(found.del, "del") {
		t.Fatalf("у шага %q нет отката правила IPv6: %v", found.name, found.del)
	}
}

// Порядок — часть механизма, а не оформление: журнал откатывает шаги в
// обратном порядке (netstate.Journal.Rollback идёт с конца), поэтому шаг,
// поставленный первым, снимается последним. Значит нет ни одного момента —
// ни при подъёме, ни при откате, ни при срыве на середине Up, — когда
// интерфейс уже (или ещё) существует, а IPv6 открыт.
func TestW48IPv6BlockIsFirstStepAndSoLastUndone(t *testing.T) {
	steps := upSteps(testParams())
	if len(steps) == 0 {
		t.Fatal("Up не раскладывает ничего")
	}
	if !isIPv6Rule(steps[0].add) {
		t.Fatalf("первый шаг Up — %q (%v), а не блокировка IPv6:\n%s",
			steps[0].name, steps[0].add, dump(steps))
	}
}

// Обратная сторона того же утверждения: блокировка не задевает IPv4. Тест
// зелен при любом состоянии флага и охраной не служит — он держит границу
// политики, чтобы «закрыть IPv6» однажды не превратилось в «закрыть всё».
func TestIPv6BlockLeavesIPv4StepsAlone(t *testing.T) {
	steps := upSteps(testParams())
	want := []string{"mtu", "addr", "up", "route", "tunnel rule"}
	for _, name := range want {
		if !hasStep(steps, name) {
			t.Fatalf("шаг %q пропал из Up:\n%s", name, dump(steps))
		}
	}
	for _, pfx := range LocalPrefixes {
		if !hasStep(steps, "exclude "+pfx) {
			t.Fatalf("исключение §5.6 %s пропало из Up:\n%s", pfx, dump(steps))
		}
	}
	if !policy.IPv6Block.On() {
		return
	}
	// Правило IPv6 ровно одно: два правила с одним приоритетом ядро примет
	// оба, а откат снимет одно.
	n := 0
	for _, s := range steps {
		if isIPv6Rule(s.add) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("правил IPv6 в Up %d, ожидалось ровно одно:\n%s", n, dump(steps))
	}
}

func isIPv6Rule(args []string) bool {
	return len(args) >= 3 && args[0] == "ip" && args[1] == "-6" && args[2] == "rule"
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func hasStep(steps []step, name string) bool {
	for _, s := range steps {
		if s.name == name {
			return true
		}
	}
	return false
}

func dump(steps []step) string {
	var b strings.Builder
	for _, s := range steps {
		fmt.Fprintf(&b, "  %-24s %s\n", s.name, strings.Join(s.add, " "))
	}
	return b.String()
}
