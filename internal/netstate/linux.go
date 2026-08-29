//go:build linux

package netstate

import (
	"fmt"
	"os/exec"
	"strings"
)

// linuxSource читает состояние сети утилитой ip.
//
// Утилита, а не netlink напрямую: снапшот сравнивается с самим собой до и
// после, поэтому важна не форма представления, а её воспроизводимость, а
// текстовый вывод ещё и читается человеком в сообщении упавшего теста. Цена —
// зависимость от iproute2, которая на Linux и так есть в любом окружении, где
// имеет смысл поднимать TUN.
type linuxSource struct{}

// System — источник состояния сети текущей ОС.
func System() Source { return linuxSource{} }

var sections = []struct {
	name string
	args []string
}{
	{"links", []string{"-o", "link", "show"}},
	{"addrs", []string{"-o", "addr", "show"}},
	{"routes", []string{"-o", "route", "show", "table", "all"}},
	{"rules", []string{"-o", "rule", "show"}},
	// Правила IPv6 живут в отдельной базе, и `ip rule show` их не показывает.
	// Без этого раздела правило блокировки IPv6 (§6.9), пережившее down,
	// оставило бы §8.4 зелёным: замер — снапшот вокруг `ip -6 rule add`
	// не менялся вовсе. Маршруты IPv6 добирать не пришлось: `route show
	// table all` печатает оба семейства сразу.
	{"rules6", []string{"-o", "-6", "rule", "show"}},
}

func (linuxSource) Capture() (Snapshot, error) {
	var secs []Section
	for _, s := range sections {
		out, err := exec.Command("ip", s.args...).Output()
		if err != nil {
			return Snapshot{}, fmt.Errorf("ip %s: %w", strings.Join(s.args, " "), err)
		}
		secs = append(secs, Section{Name: s.name, Lines: nonEmpty(string(out))})
	}
	return NewSnapshot(secs...), nil
}

func nonEmpty(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}
