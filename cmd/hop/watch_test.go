package main

import (
	"strings"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/health"
)

// TestNodesLineRendersWords — срез живости печатается словами, а не байтами.
//
// Первая редакция приводила health.State через string(), то есть uint8 → руна:
// в логе вместо «alive» появлялся «\x01». Поймано живым прогоном, а не тестом,
// потому что наблюдаемость никто не проверял — она сама была средством проверки.
func TestNodesLineRendersWords(t *testing.T) {
	line := nodesLine([]health.NodeHealth{
		{NodeID: "d45e4844072cea86", State: health.Alive, RTT: 383 * time.Millisecond}, //hop:realtime
		{NodeID: "0000000011112222", State: health.Dead, LastError: "проба не дошла"},
		{NodeID: "3333333344445555", State: health.Untested},
	})

	for _, want := range []string{"alive", "dead", "383ms", "проба не дошла"} {
		if !strings.Contains(line, want) {
			t.Errorf("в строке живости нет %q: %s", want, line)
		}
	}
	for _, r := range line {
		if r < 0x20 && r != '\t' {
			t.Errorf("в строке живости управляющий байт %#x — состояние напечатано числом, а не словом: %q", r, line)
			break
		}
	}
}

// TestNodesLineWithoutNodes — пустой срез не превращается в пустую строку:
// «узлов нет» и «строка не собралась» в логе должны различаться.
func TestNodesLineWithoutNodes(t *testing.T) {
	if got := nodesLine(nil); got == "" {
		t.Error("пустой срез дал пустую строку")
	}
}
