package netstack

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/shafed/hop/internal/policy"
)

// Verdict — решение по первому пакету потока (§3.4).
type Verdict uint8

const (
	// HijackDNS — dst-порт 53, UDP или TCP. Всегда и до всякой маршрутизации.
	HijackDNS Verdict = iota + 1
	// Bypass — мимо туннеля, в локальную сеть (§6.10).
	Bypass
	// Block — то, что §6.10 велит блокировать, плюс всё, для чего у нас нет
	// исходящего: IPv6 (§6.9) и протоколы кроме TCP и UDP. Пятого вердикта в
	// §3.4 нет — см. «Deviations» в implementation-notes.md.
	Block
	// Reject — fail-close: живых узлов нет (§5.6). Ответ строит internal/reject.
	Reject
	// Proxy — всё остальное: core.Dial / core.DialUDP.
	Proxy
)

func (v Verdict) String() string {
	switch v {
	case HijackDNS:
		return "hijack-dns"
	case Bypass:
		return "bypass"
	case Block:
		return "block"
	case Reject:
		return "reject"
	case Proxy:
		return "proxy"
	}
	return "?"
}

// flow — 5-кортеж, по которому принимается вердикт.
type flow struct {
	proto uint8
	src   netip.AddrPort
	dst   netip.AddrPort
}

// Порты §6.10 и §5.6.
const (
	portDNS    = 53
	portDHCPSv = 67
	portDHCPCl = 68
	portNTP    = 123
	portMDNS   = 5353
	portSSDP   = 1900
)

var (
	addrMDNS  = netip.AddrFrom4([4]byte{224, 0, 0, 251})
	addrSSDP  = netip.AddrFrom4([4]byte{239, 255, 255, 250})
	addrBcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})
)

// classify — вердикт по §3.4. Чистая функция от потока, одного факта «есть ли
// живой узел» и списков §6.10: всё, что она знает, видно в сигнатуре, поэтому
// она проверяется таблицей без единого пакета. Списки пришли из конфигурации
// и уже разрешены (resolveRouting), поэтому rt здесь никогда не nil.
//
// Порядок — часть контракта, а не деталь реализации. Системный DNS обычно и
// есть локальный роутер: при обратном порядке запрос на 192.168.1.1:53 уходит
// в локальную сеть как bypass при формально работающем перехвате. Ровно это и
// краснит T16 при verdict_order=bypass_first.
func classify(f flow, healthy bool, rt *Routing) Verdict {
	if f.proto != uint8(header.TCPProtocolNumber) && f.proto != uint8(header.UDPProtocolNumber) {
		return Block
	}

	dns := isDNS(f)
	bypass := isBypass(f, rt)

	if policy.VerdictOrder.On() {
		if dns {
			return HijackDNS
		}
		if bypass {
			return Bypass
		}
	} else {
		if bypass {
			return Bypass
		}
		if dns {
			return HijackDNS
		}
	}

	if isBlocked(f, rt) {
		return Block
	}
	if !healthy {
		return Reject
	}
	return Proxy
}

// isDNS — пункт 1 §3.4: dst-порт 53, UDP или TCP.
func isDNS(f flow) bool { return f.dst.Port() == portDNS }

// isBypass — пункт 2 §3.4 в объёме §6.10 «мимо туннеля, в локальную сеть»,
// плюс исключения §5.6, разрешённые всегда (DHCP, NTP).
//
// Сам список живёт в Routing и приходит из конфигурации (routing.go); здесь
// остаётся только «совпало ли». Это не reject.Excluded, хотя списки похожи:
// там вопрос «на что респондер не имеет права отвечать» и любой multicast
// консервативно попадает в «не наше дело», здесь — «что выпустить в локальную
// сеть», и multicast §6.10 делит на разрешённое обнаружение служб и
// блокируемое остальное.
func isBypass(f flow, rt *Routing) bool { return matchAny(rt.Bypass, f) }

// isBlocked — «Блокируем» из §6.10: широковещательный NetBIOS и прочий
// multicast и broadcast за пределами разрешённого выше. Список — оттуда же,
// из конфигурации.
func isBlocked(f flow, rt *Routing) bool { return matchAny(rt.Block, f) }
