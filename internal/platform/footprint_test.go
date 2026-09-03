//go:build linux

package platform

import (
	"strings"
	"testing"

	"github.com/shafed/hop/internal/netstate"
	"github.com/shafed/hop/internal/tunnel"
)

// standParams — параметры, с которыми снят замер ниже. Те же, что у стенда L3
// и у умолчаний CLI (cmd/hop/cli.go, defaultOptions).
var standParams = tunnel.Params{Name: "hop0", MTU: 1400, Addr: "10.255.0.1/24", Table: 8420}

// measuredFootprint — ЗАМЕР, а не список из upSteps.
//
// В netns (`unshare -Urn`) разложены все шаги Up и снята разница снапшотов до
// и после. Это её полный вывод, дословно. Три строки из четырнадцати upSteps
// не добавлял: connected-, local- и broadcast-маршруты завело ядро вслед за
// адресом, — и именно они пропали бы, сравнивай мы «что мы делали» по журналу
// вместо «что от нас видно» по снапшоту.
var measuredFootprint = []string{
	`10.255.0.0/24 dev hop0 proto kernel scope link src 10.255.0.1 linkdown`,
	`2: hop0    inet 10.255.0.1/24 scope global hop0\       valid_lft forever preferred_lft forever`,
	`2: hop0: <NO-CARRIER,POINTOPOINT,MULTICAST,NOARP,UP> mtu 1400 qdisc fq_codel state DOWN mode DEFAULT group default qlen 500\    link/none`,
	"31000:\tfrom all ipproto udp dport 123 lookup main",
	"31000:\tfrom all ipproto udp dport 67-68 lookup main",
	"31000:\tfrom all to 10.0.0.0/8 lookup main",
	"31000:\tfrom all to 169.254.0.0/16 lookup main",
	"31000:\tfrom all to 172.16.0.0/12 lookup main",
	"31000:\tfrom all to 192.168.0.0/16 lookup main",
	"31000:\tfrom all to 224.0.0.0/4 lookup main",
	"31000:\tfrom all to 255.255.255.255 lookup main",
	"32000:\tfrom all lookup 8420",
	"32000:\tfrom all unreachable",
	`broadcast 10.255.0.255 dev hop0 table local proto kernel scope link src 10.255.0.1 linkdown`,
	`default dev hop0 table 8420 scope link linkdown`,
	`local 10.255.0.1 dev hop0 table local proto kernel scope host src 10.255.0.1`,
}

// measuredForeign — тоже замер: расхождения, которые давали чужие изменения
// сети вокруг живого hopd. Ряд 2 — посторонний добавил адрес; ряд 3 —
// обновление аренды DHCP, снявшее один адрес и выдавшее другой. Ни одна из
// этих строк не наша, и ряд 3 показывает заодно, почему разделять по знаку
// строки нельзя: «-» бывает и чужим.
var measuredForeign = []string{
	`addrs: +1: lo    inet 10.99.0.1/32 scope global lo\       valid_lft forever preferred_lft forever`,
	`routes: +local 10.99.0.1 dev lo table local proto kernel scope host src 10.99.0.1`,
	`addrs: -1: lo    inet 10.98.0.1/32 scope global lo\       valid_lft forever preferred_lft forever`,
	`addrs: +1: lo    inet 10.98.0.2/32 scope global lo\       valid_lft forever preferred_lft forever`,
	`routes: -local 10.98.0.1 dev lo table local proto kernel scope host src 10.98.0.1`,
	`routes: +local 10.98.0.2 dev lo table local proto kernel scope host src 10.98.0.2`,
}

// W72: каждая строка замеренного следа обязана опознаваться как наша.
//
// Утверждение построчное, а не «сколько всего»: пропущенная строка — это
// пропущенная течь, и знать надо, какая именно.
func TestW72MarksCoverTheMeasuredFootprint(t *testing.T) {
	m := marks(standParams)
	mine, foreign := netstate.Classify(measuredFootprint, m)
	if len(foreign) > 0 {
		t.Errorf("след hop не опознан как свой (%d строк из %d):", len(foreign), len(measuredFootprint))
		for _, l := range foreign {
			t.Errorf("  %s", l)
		}
	}
	if len(mine) != len(measuredFootprint) {
		t.Errorf("своими сочтено %d строк, замерено %d", len(mine), len(measuredFootprint))
	}
}

// W72: ни одна замеренная чужая строка не должна засчитаться нам — иначе
// штатная остановка снова падает за чужую работу.
func TestW72MarksDoNotClaimForeignChanges(t *testing.T) {
	m := marks(standParams)
	mine, _ := netstate.Classify(measuredForeign, m)
	if len(mine) > 0 {
		t.Errorf("чужое изменение сети засчитано нам (%d строк):", len(mine))
		for _, l := range mine {
			t.Errorf("  %s", l)
		}
	}
}

// W72: пока туннель не поднимался, следа нет — и чужое тогда всё.
//
// Это не мелочь: сервис, простоявший без единого `up`, сети не касался, а
// именно так он и стоит между стартом машины и первым входом пользователя.
func TestW72FootprintIsEmptyUntilUp(t *testing.T) {
	l := New(nil)
	if got := l.Footprint(); len(got) != 0 {
		t.Fatalf("след без единого Up: %v", got)
	}
	mine, foreign := netstate.Classify(measuredForeign, l.Footprint())
	if len(mine) != 0 {
		t.Fatalf("без Up что-то сочтено нашим: %v", mine)
	}
	if len(foreign) != len(measuredForeign) {
		t.Fatalf("чужих строк %d, ожидалось %d", len(foreign), len(measuredForeign))
	}
}

// W72: след копится по всем Up, а не описывает последний.
//
// Агент вправе перезапуститься с другим именем интерфейса; течь прошлого
// воплощения назовёт прошлое имя, и оно обязано остаться нашим.
func TestW72FootprintAccumulatesAcrossParams(t *testing.T) {
	l := New(nil)
	l.addMarks(marks(standParams))
	l.addMarks(marks(tunnel.Params{Name: "hop1", MTU: 1400, Addr: "10.254.0.1/24", Table: 8421}))

	for _, want := range []string{"hop0", "hop1", "lookup 8420", "lookup 8421"} {
		found := false
		for _, m := range l.Footprint() {
			if strings.Contains(m, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("в следе нет %q: %v", want, l.Footprint())
		}
	}
}
