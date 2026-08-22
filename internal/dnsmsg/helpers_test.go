package dnsmsg

import (
	"encoding/binary"
	"strings"
	"testing"
)

// Сообщения в тестах собираются здесь, по байтам, а не функциями пакета:
// иначе разбор проверялся бы собственной сборкой и совпадал бы с ней даже
// тогда, когда оба неверны.

func wireName(s string) []byte {
	out := []byte{}
	s = strings.TrimSuffix(s, ".")
	if s != "" {
		for _, l := range strings.Split(s, ".") {
			out = append(out, byte(len(l)))
			out = append(out, l...)
		}
	}
	return append(out, 0)
}

func question(name string, qtype uint16) []byte {
	out := wireName(name)
	out = binary.BigEndian.AppendUint16(out, qtype)
	return binary.BigEndian.AppendUint16(out, ClassIN)
}

func record(name string, rtype, class uint16, ttl uint32, rdata []byte) []byte {
	out := wireName(name)
	out = binary.BigEndian.AppendUint16(out, rtype)
	out = binary.BigEndian.AppendUint16(out, class)
	out = binary.BigEndian.AppendUint32(out, ttl)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
	return append(out, rdata...)
}

// optRecord — псевдозапись EDNS0: имя корневое, тип 41, размер буфера в поле
// класса, DO в старшем бите поля TTL (RFC 6891 §6.1.2, §6.1.3).
func optRecord(udpSize uint16, do bool, opts ...[]byte) []byte {
	var ttl uint32
	if do {
		ttl |= optDOBit
	}
	var rdata []byte
	for _, o := range opts {
		rdata = append(rdata, o...)
	}
	return record("", TypeOPT, udpSize, ttl, rdata)
}

func option(code uint16, value []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, code)
	out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
	return append(out, value...)
}

// ecsOption — ECS для 203.0.113.0/24 (RFC 7871 §6): семейство, длины префикса,
// значимые байты адреса.
func ecsOption() []byte {
	v := []byte{0, 1, 24, 0, 203, 0, 113}
	return option(OptionECS, v)
}

// soaRDATA — MNAME, RNAME и пять чисел; MINIMUM последнее.
func soaRDATA(serial, minimum uint32) []byte {
	out := append(wireName("ns.example.com"), wireName("hostmaster.example.com")...)
	out = binary.BigEndian.AppendUint32(out, serial)
	out = binary.BigEndian.AppendUint32(out, 7200)  // REFRESH
	out = binary.BigEndian.AppendUint32(out, 3600)  // RETRY
	out = binary.BigEndian.AppendUint32(out, 86400) // EXPIRE
	return binary.BigEndian.AppendUint32(out, minimum)
}

func assemble(id, flags uint16, q []byte, an, ns, ar [][]byte) []byte {
	out := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], uint16(len(an)))
	binary.BigEndian.PutUint16(out[8:10], uint16(len(ns)))
	binary.BigEndian.PutUint16(out[10:12], uint16(len(ar)))
	out = append(out, q...)
	for _, sec := range [][][]byte{an, ns, ar} {
		for _, r := range sec {
			out = append(out, r...)
		}
	}
	return out
}

// aQuery — типовой запрос клиента: A example.com, RD.
func aQuery(id uint16) []byte {
	return assemble(id, FlagRecursionDesired, question("example.com", TypeA), nil, nil, nil)
}

// aResponse — типовой ответ апстрима на aQuery.
func aResponse(id uint16, ttl uint32) []byte {
	return assemble(id, FlagResponse|FlagRecursionDesired|FlagRecursionAvailable,
		question("example.com", TypeA),
		[][]byte{record("example.com", TypeA, ClassIN, ttl, []byte{203, 0, 113, 7})},
		nil, nil)
}

// mustParse — разбор фикстуры, которая обязана разбираться. Ошибка здесь —
// сломанная фикстура, а не проверяемое поведение.
func mustParse(t *testing.T, raw []byte) Msg {
	t.Helper()
	m, err := Parse(raw)
	if err != nil {
		t.Fatalf("фикстура не разбирается: %v", err)
	}
	return m
}
