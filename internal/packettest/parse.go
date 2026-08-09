package packettest

const (
	protoICMP = 1
	protoTCP  = 6

	tcpRST = 0x04

	icmpDestUnreach = 3
)

// ipv4Payload возвращает протокол и полезную нагрузку IPv4-пакета.
func ipv4Payload(p []byte) (proto byte, payload []byte, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return 0, nil, false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl {
		return 0, nil, false
	}
	return p[9], p[ihl:], true
}

func tcpFlags(p []byte) (byte, bool) {
	proto, payload, ok := ipv4Payload(p)
	if !ok || proto != protoTCP || len(payload) < 20 {
		return 0, false
	}
	return payload[13], true
}

func icmpTypeCode(p []byte) (typ, code byte, ok bool) {
	proto, payload, ok := ipv4Payload(p)
	if !ok || proto != protoICMP || len(payload) < 4 {
		return 0, 0, false
	}
	return payload[0], payload[1], true
}
