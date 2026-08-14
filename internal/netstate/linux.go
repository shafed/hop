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

// Обе семьи адресов: `ip route show` и `ip rule show` без `-6` показывают
// только IPv4, а блокировка IPv6 (§6.9) выражена правилом в -6. Снапшот без
// него не заметил бы ни утечки блокировки после down, ни правила, пережившего
// смерть сервиса (T22, T29).
var sections = []struct {
	name string
	args []string
}{
	{"links", []string{"-o", "link", "show"}},
	{"addrs", []string{"-o", "addr", "show"}},
	{"routes", []string{"-o", "route", "show", "table", "all"}},
	{"routes6", []string{"-6", "-o", "route", "show", "table", "all"}},
	{"rules", []string{"-o", "rule", "show"}},
	{"rules6", []string{"-6", "-o", "rule", "show"}},
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
