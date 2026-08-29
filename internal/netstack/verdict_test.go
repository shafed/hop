package netstack

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/shafed/hop/internal/packettest"
	"github.com/shafed/hop/internal/reject"
)

const (
	protoTCP  = uint8(header.TCPProtocolNumber)
	protoUDP  = uint8(header.UDPProtocolNumber)
	protoICMP = uint8(header.ICMPv4ProtocolNumber)
)

func udpTo(dst string) flow {
	return flow{proto: protoUDP, src: client, dst: netip.MustParseAddrPort(dst)}
}

func tcpTo(dst string) flow {
	return flow{proto: protoTCP, src: client, dst: netip.MustParseAddrPort(dst)}
}

// Таблица §3.4 плюс списки §6.10 и исключения §5.6.
func TestClassify(t *testing.T) {
	cases := []struct {
		name    string
		f       flow
		healthy bool
		want    Verdict
	}{
		{"DNS на локальный роутер", udpTo("192.168.1.1:53"), true, HijackDNS},
		{"DNS наружу", udpTo("8.8.8.8:53"), true, HijackDNS},
		{"DNS поверх TCP", tcpTo("8.8.8.8:53"), true, HijackDNS},
		{"DNS без живых узлов всё равно перехвачен", udpTo("8.8.8.8:53"), false, HijackDNS},

		{"локальная сеть", tcpTo("192.168.1.10:445"), true, Bypass},
		{"loopback", tcpTo("127.0.0.1:8080"), true, Bypass},
		{"link-local", udpTo("169.254.1.1:5000"), true, Bypass},
		{"DHCP широковещательно", udpTo("255.255.255.255:67"), true, Bypass},
		{"NTP наружу", udpTo("216.239.35.0:123"), true, Bypass},
		{"mDNS", udpTo("224.0.0.251:5353"), true, Bypass},
		{"SSDP", udpTo("239.255.255.250:1900"), true, Bypass},

		{"NetBIOS широковещательно", udpTo("255.255.255.255:137"), true, Block},
		{"прочий multicast", udpTo("239.1.2.3:1234"), true, Block},
		{"не TCP и не UDP", flow{proto: protoICMP, src: client, dst: web}, true, Block},

		{"наружу при живом узле", tcpTo("203.0.113.7:443"), true, Proxy},
		{"наружу без живых узлов", tcpTo("203.0.113.7:443"), false, Reject},
		{"UDP наружу без живых узлов", udpTo("203.0.113.7:443"), false, Reject},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classify(c.f, c.healthy, DefaultRouting()); got != c.want {
				t.Fatalf("вердикт %v, ожидался %v", got, c.want)
			}
		})
	}
}

// Всё, что попадает в reject, обязано получить ответ. Если вердикт reject
// достаётся тому, что internal/reject считает исключением §5.6, Reply вернёт
// nil — и fail-close станет молчаливым дропом, ровно тем, что запрещает §5.6.
// Два списка живут в разных пакетах и отвечают на разные вопросы; этот тест —
// шов между ними.
func TestRejectVerdictNeverEndsInSilence(t *testing.T) {
	dsts := []string{
		"203.0.113.7:443", "8.8.8.8:443", "1.1.1.1:853",
		"216.239.35.0:1234", "203.0.113.7:123", "192.0.2.1:80",
	}
	for _, d := range dsts {
		dst := netip.MustParseAddrPort(d)
		for _, proto := range []uint8{protoTCP, protoUDP} {
			f := flow{proto: proto, src: client, dst: dst}
			if classify(f, false, DefaultRouting()) != Reject {
				continue
			}
			var pkt []byte
			if proto == protoTCP {
				pkt = packettest.TCPSyn(client, dst, 1)
			} else {
				pkt = packettest.UDP(client, dst, []byte("x"))
			}
			if reject.Reply(pkt) == nil {
				t.Fatalf("вердикт reject для %v/%d, а ответа нет — молчание вместо отказа", dst, proto)
			}
		}
	}
}
