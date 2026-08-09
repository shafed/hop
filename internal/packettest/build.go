package packettest

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TCPSyn — SYN, каким его увидит устройство от приложения, открывающего
// соединение.
func TCPSyn(src, dst netip.AddrPort, seq uint32) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	tcp := header.TCP(pkt[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    src.Port(),
		DstPort:    dst.Port(),
		SeqNum:     seq,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	a, b := addr(src), addr(dst)
	tcp.SetChecksum(^checksum.Checksum(tcp, header.PseudoHeaderChecksum(
		header.TCPProtocolNumber, a, b, header.TCPMinimumSize)))
	ipv4(pkt, a, b, uint8(header.TCPProtocolNumber))
	return pkt
}

// UDP — датаграмма с полезной нагрузкой.
func UDP(src, dst netip.AddrPort, payload []byte) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	udp := header.UDP(pkt[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(pkt[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	a, b := addr(src), addr(dst)
	udp.SetChecksum(^checksum.Checksum(pkt[header.IPv4MinimumSize:], header.PseudoHeaderChecksum(
		header.UDPProtocolNumber, a, b, uint16(header.UDPMinimumSize+len(payload)))))
	ipv4(pkt, a, b, uint8(header.UDPProtocolNumber))
	return pkt
}

func addr(a netip.AddrPort) tcpip.Address {
	v4 := a.Addr().As4()
	return tcpip.AddrFrom4(v4)
}

func ipv4(pkt []byte, src, dst tcpip.Address, proto uint8) {
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    proto,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
}
