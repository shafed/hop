package packettest

import (
	"net/netip"

	"github.com/shafed/hop/internal/packet"
)

// TCPSyn — SYN, каким его увидит устройство от приложения, открывающего
// соединение.
func TCPSyn(src, dst netip.AddrPort, seq uint32) []byte {
	return packet.BuildTCPSyn(src, dst, seq)
}

// UDP — датаграмма с полезной нагрузкой.
func UDP(src, dst netip.AddrPort, payload []byte) []byte {
	return packet.BuildUDP(src, dst, payload)
}
