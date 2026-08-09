// Package policy — реестр политик, которые можно выключить.
//
// §8 требует: у каждой проверяемой политики есть флаг отключения, и отдельная
// CI-задача убеждается, что с выключенной политикой охраняющий её тест
// краснеет. Реестр — единственное место, где политики перечислены, поэтому он
// полон по построению: negcheck читает этот список напрямую, а не собирает его
// из графа импортов.
//
// Флаг снимается из переменной окружения XRAYVPN_DISABLE (список имён через
// запятую) один раз при инициализации пакета. Call-site видит только
// p.On() — конфиг никуда не протаскивается.
package policy

import (
	"os"
	"strings"
)

// Policy — одна выключаемая политика.
type Policy struct {
	Name string
	Doc  string
	// Guards — тесты, которые обязаны быть зелёными с политикой и красными
	// без неё. Пустой список запрещён: политика без охраняющего теста — это
	// политика, отключение которой ничего не ломает.
	Guards []Guard
}

// Guard — адрес теста для `go test -run`.
type Guard struct {
	Pkg  string // пакет относительно корня модуля, например "./internal/framing"
	Test string // regexp для -run, например "^TestBatchRoundTrip$"
}

// On сообщает, включена ли политика.
func (p *Policy) On() bool { return !disabled[p.Name] }

var disabled = parseDisabled(os.Getenv("XRAYVPN_DISABLE"))

func parseDisabled(v string) map[string]bool {
	m := make(map[string]bool)
	for _, name := range strings.Split(v, ",") {
		if name = strings.TrimSpace(name); name != "" {
			m[name] = true
		}
	}
	return m
}
