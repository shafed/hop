package packet

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// BuildUDP собирает IPv4/UDP-датаграмму.
//
// Живёт здесь, а не в трёх местах: датаграммы строит и netstack (ответ NAT и
// ответ резолвера), и оракул, и бенчмарк B3. Три копии одной арифметики
// контрольных сумм разошлись бы молча.
//
// Заголовки — gvisor.dev/gvisor/pkg/tcpip/header (Apache-2.0), как в
// internal/reject.
func BuildUDP(src, dst netip.AddrPort, payload []byte) []byte {
	total := header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)
	out := make([]byte, total)

	udp := header.UDP(out[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(out[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)

	a := tcpip.AddrFrom4(src.Addr().As4())
	b := tcpip.AddrFrom4(dst.Addr().As4())
	udp.SetChecksum(^checksum.Checksum(out[header.IPv4MinimumSize:], header.PseudoHeaderChecksum(
		header.UDPProtocolNumber, a, b, uint16(header.UDPMinimumSize+len(payload)))))

	encodeIPv4(out, a, b, uint8(header.UDPProtocolNumber))
	return out
}

// BuildTCPSyn собирает SYN — первый пакет потока, тот самый, по которому
// принимается вердикт (§3.4).
func BuildTCPSyn(src, dst netip.AddrPort, seq uint32) []byte {
	out := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)

	tcp := header.TCP(out[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    src.Port(),
		DstPort:    dst.Port(),
		SeqNum:     seq,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})

	a := tcpip.AddrFrom4(src.Addr().As4())
	b := tcpip.AddrFrom4(dst.Addr().As4())
	tcp.SetChecksum(^checksum.Checksum(tcp, header.PseudoHeaderChecksum(
		header.TCPProtocolNumber, a, b, header.TCPMinimumSize)))

	encodeIPv4(out, a, b, uint8(header.TCPProtocolNumber))
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
