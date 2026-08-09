// Package reject — отказ вместо молчания (§5.6) для состояния orphaned (§6.2).
//
// На Linux и macOS отказ делает ядро подменённым маршрутом, и этого пакета там
// не нужно. Он существует ради Windows, где route-level reject отсутствует:
// сервис дренирует кольцо Wintun и синтезирует ответ сам.
//
// Reply — **чистая функция**: входящий пакет → ответный пакет или nil. Она не
// знает ни про кольцо, ни про права, ни про ОС, поэтому проверяется на
// FakePacketDevice без прав на всех трёх ОС (половина T23b). Привилегированная
// поверхность §5.2 остаётся ровно дренажом кольца — Serve, десяток строк.
//
// Заголовки строятся через gvisor.dev/gvisor/pkg/tcpip/header (Apache-2.0).
// sing-tun/flow_reject.go под GPL-3.0 — образец формы, не источник кода.
package reject

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Порты исключений §5.6: без них машина теряет DHCP-аренду ровно в окне
// продления, а часы уезжают.
const (
	portDHCPServer = 67
	portDHCPClient = 68
	portNTP        = 123
)

// Reply строит ответ на пакет, которому отказано, или возвращает nil, если
// ответа не положено.
//
//	TCP  → RST
//	UDP  → ICMP destination unreachable, code 3 (port unreachable)
//	иначе → nil
//
// nil возвращается и для того, что §5.6 выпускает всегда (Excluded): такой
// пакет не отвергается, он просто не наше дело.
//
// IPv6 сюда не доходит: §6.9 блокирует его на уровне маршрутов TUN. Отвечать
// на него означало бы сделать вид, что он поддержан.
func Reply(pkt []byte) []byte {
	ip, ok := parseIPv4(pkt)
	if !ok || Excluded(pkt) {
		return nil
	}
	payload := ip.Payload()
	switch ip.Protocol() {
	case uint8(header.TCPProtocolNumber):
		return tcpRST(ip, payload)
	case uint8(header.UDPProtocolNumber):
		return icmpUnreachable(ip, header.ICMPv4PortUnreachable)
	default:
		return nil
	}
}

// Excluded — то, что §5.6 выпускает всегда, включая состояние orphaned:
// локальные сети (RFC1918 и аналоги), DHCP, NTP.
func Excluded(pkt []byte) bool {
	ip, ok := parseIPv4(pkt)
	if !ok {
		return false
	}
	dst, _ := netip.AddrFromSlice(ip.DestinationAddressSlice())
	if isLocal(dst) {
		return true
	}
	if ip.Protocol() == uint8(header.UDPProtocolNumber) {
		udp := ip.Payload()
		if len(udp) < header.UDPMinimumSize {
			return false
		}
		switch header.UDP(udp).DestinationPort() {
		case portDHCPServer, portDHCPClient, portNTP:
			return true
		}
	}
	return false
}

// isLocal — «локальные сети (RFC1918 и аналоги)» из §5.6, вместе с
// broadcast-адресом, на который уходит DHCP DISCOVER.
func isLocal(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsMulticast() {
		return true
	}
	return a == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func parseIPv4(pkt []byte) (header.IPv4, bool) {
	if len(pkt) < header.IPv4MinimumSize {
		return nil, false
	}
	ip := header.IPv4(pkt)
	if ip.IsValid(len(pkt)) && ip.HeaderLength() >= header.IPv4MinimumSize &&
		ip.FragmentOffset() == 0 {
		return ip, true
	}
	return nil, false
}

// tcpRST строит RST по RFC 793: на сегмент с ACK отвечаем чистым RST с
// seq = ack входящего, иначе RST|ACK с ack = seq + длина занятого места в
// последовательности. Сам RST не отвергается — иначе получится петля.
func tcpRST(ip header.IPv4, payload []byte) []byte {
	if len(payload) < header.TCPMinimumSize {
		return nil
	}
	in := header.TCP(payload)
	if in.Flags()&header.TCPFlagRst != 0 {
		return nil
	}

	var seq, ack uint32
	flags := header.TCPFlagRst
	if in.Flags()&header.TCPFlagAck != 0 {
		seq = in.AckNumber()
	} else {
		dataOff := int(in.DataOffset())
		if dataOff < header.TCPMinimumSize || dataOff > len(payload) {
			return nil
		}
		segLen := uint32(len(payload) - dataOff)
		if in.Flags()&(header.TCPFlagSyn|header.TCPFlagFin) != 0 {
			segLen++
		}
		ack = in.SequenceNumber() + segLen
		flags |= header.TCPFlagAck
	}

	src, dst := ip.SourceAddress(), ip.DestinationAddress()
	out := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	tcp := header.TCP(out[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    in.DestinationPort(),
		DstPort:    in.SourcePort(),
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
	})
	tcp.SetChecksum(^checksum.Checksum(tcp, header.PseudoHeaderChecksum(
		header.TCPProtocolNumber, dst, src, header.TCPMinimumSize)))

	encodeIPv4(out, dst, src, uint8(header.TCPProtocolNumber))
	return out
}

// icmpUnreachable строит ICMP destination unreachable. Тело — заголовок
// исходного пакета плюс первые 8 байт его полезной нагрузки (RFC 792): ровно
// столько, чтобы отправитель сопоставил ответ со своим сокетом.
func icmpUnreachable(ip header.IPv4, code header.ICMPv4Code) []byte {
	quote := []byte(ip)
	if max := int(ip.HeaderLength()) + 8; len(quote) > max {
		quote = quote[:max]
	}

	out := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(quote))
	icmp := header.ICMPv4(out[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4DstUnreachable)
	icmp.SetCode(code)
	copy(out[header.IPv4MinimumSize+header.ICMPv4MinimumSize:], quote)
	icmp.SetChecksum(0)
	icmp.SetChecksum(^checksum.Checksum(out[header.IPv4MinimumSize:], 0))

	encodeIPv4(out, ip.DestinationAddress(), ip.SourceAddress(), uint8(header.ICMPv4ProtocolNumber))
	return out
}

func encodeIPv4(out []byte, src, dst tcpip.Address, proto uint8) {
	ip := header.IPv4(out)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(out)),
		TTL:         64,
		Protocol:    proto,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
}
