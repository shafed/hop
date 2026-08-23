package packet

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// ParseUDP4 разбирает IPv4-датаграмму UDP: адреса, порты и нагрузку.
// ok == false для не-IPv4, не-UDP, фрагментов и коротких пакетов.
//
// Симметрична BuildUDP. netstack.parse не переиспользуется: та разбирает ещё
// и TCP ради вердикта, а тут нужен только путь UDP, отдельно от netstack,
// чтобы internal/bypass не зависел от internal/netstack.
func ParseUDP4(pkt []byte) (src, dst netip.AddrPort, payload []byte, ok bool) {
	if len(pkt) < header.IPv4MinimumSize {
		return netip.AddrPort{}, netip.AddrPort{}, nil, false
	}
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) || ip.HeaderLength() < header.IPv4MinimumSize || ip.FragmentOffset() != 0 {
		return netip.AddrPort{}, netip.AddrPort{}, nil, false
	}
	if ip.Protocol() != uint8(header.UDPProtocolNumber) {
		return netip.AddrPort{}, netip.AddrPort{}, nil, false
	}

	srcAddr, ok1 := netip.AddrFromSlice(ip.SourceAddressSlice())
	dstAddr, ok2 := netip.AddrFromSlice(ip.DestinationAddressSlice())
	if !ok1 || !ok2 {
		return netip.AddrPort{}, netip.AddrPort{}, nil, false
	}

	body := ip.Payload()
	if len(body) < header.UDPMinimumSize {
		return netip.AddrPort{}, netip.AddrPort{}, nil, false
	}
	u := header.UDP(body)

	src = netip.AddrPortFrom(srcAddr, u.SourcePort())
	dst = netip.AddrPortFrom(dstAddr, u.DestinationPort())
	return src, dst, u.Payload(), true
}
