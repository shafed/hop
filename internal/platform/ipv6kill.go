//go:build linux

package platform

import (
	"log/slog"

	"github.com/vishvananda/netlink"
)

// stepKillIPv6 — имя шага Up, разрушающего соединения IPv6, установленные до
// подъёма туннеля.
const stepKillIPv6 = "ipv6 kill established"

// killOutcome — как трактовать ответ ядра на одно разрушение.
type killOutcome int

const (
	killDone        killOutcome = iota // сокет разрушен
	killGone                           // сокета уже нет: закрылся между дампом и разрушением
	killUnsupported                    // ядро не умеет SOCK_DESTROY вовсе
	killRefused                        // всё остальное
)

// classifyKill — заглушка до реализации.
func classifyKill(err error) killOutcome { return killRefused }

// silencedIPv6 — заглушка до реализации.
func silencedIPv6(socks []*netlink.Socket, own map[string]bool) []*netlink.Socket { return nil }

// sweepSilencedIPv6 — заглушка до реализации.
func sweepSilencedIPv6(log *slog.Logger) {}
