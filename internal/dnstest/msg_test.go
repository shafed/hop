package dnstest

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestNameEncodesLabels(t *testing.T) {
	got := Name("example.com")
	want := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if string(got) != string(want) {
		t.Fatalf("Name() = %v, хочу %v", got, want)
	}
	if string(Name("")) != string([]byte{0}) {
		t.Fatal("Name(\"\") должно кодировать корневое имя")
	}
}

func TestBuildQueryHeaderAndEDNS0(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.9")
	q := BuildQuery(QueryOpts{
		ID: 0x1234, Name: "example.com", Type: TypeAAAA,
		EDNS0: true, DO: true,
		ECS: &ECS{Family: 1, SourcePrefix: 24, Address: ip},
	})

	if id := binary.BigEndian.Uint16(q[:2]); id != 0x1234 {
		t.Fatalf("ID = %#x, хочу 0x1234", id)
	}
	if arcount := binary.BigEndian.Uint16(q[10:12]); arcount != 1 {
		t.Fatalf("ARCOUNT = %d, хочу 1 (запись OPT)", arcount)
	}

	// Проматываем секцию QUESTION до OPT — по метке имени, а не по
	// зашитому смещению: тест не должен знать длину "example.com" наизусть.
	qnameEnd := 12
	for q[qnameEnd] != 0 {
		qnameEnd += int(q[qnameEnd]) + 1
	}
	qnameEnd++               // нулевой байт-терминатор
	optStart := qnameEnd + 4 // QTYPE + QCLASS

	if q[optStart] != 0 {
		t.Fatal("имя записи OPT не корневое")
	}
	typ := binary.BigEndian.Uint16(q[optStart+1 : optStart+3])
	if typ != TypeOPT {
		t.Fatalf("TYPE OPT = %d, хочу %d", typ, TypeOPT)
	}
	bufSize := binary.BigEndian.Uint16(q[optStart+3 : optStart+5])
	if bufSize != DefaultEDNS0BufSize {
		t.Fatalf("буфер = %d, хочу %d", bufSize, DefaultEDNS0BufSize)
	}
	ttl := binary.BigEndian.Uint32(q[optStart+5 : optStart+9])
	if ttl&(1<<15) == 0 {
		t.Fatal("DO-бит не поднят")
	}
	rdlen := binary.BigEndian.Uint16(q[optStart+9 : optStart+11])
	rdata := q[optStart+11 : optStart+11+int(rdlen)]
	code := binary.BigEndian.Uint16(rdata[:2])
	if code != optECS {
		t.Fatalf("код опции = %d, хочу %d (ECS)", code, optECS)
	}
}

func TestBuildQueryWithoutEDNS0HasNoAdditional(t *testing.T) {
	q := BuildQuery(QueryOpts{ID: 1, Name: "example.com", Type: TypeA})
	if arcount := binary.BigEndian.Uint16(q[10:12]); arcount != 0 {
		t.Fatalf("ARCOUNT = %d, хочу 0 без EDNS0", arcount)
	}
}

func TestResponseOversizedCrossesThreshold(t *testing.T) {
	for _, size := range []int{512, 4096} {
		msg := ResponseOversized(1, "example.com", size)
		if len(msg) < size {
			t.Fatalf("ResponseOversized(%d) вернул %d байт", size, len(msg))
		}
	}
}

func TestWithTCSetsBitWithoutMutatingInput(t *testing.T) {
	msg := ResponseA(1, "example.com", 300, netip.MustParseAddr("203.0.113.1"))
	tc := WithTC(msg)
	if tc[2]&(1<<1) == 0 {
		t.Fatal("TC-бит не поднят")
	}
	if msg[2]&(1<<1) != 0 {
		t.Fatal("WithTC изменил исходный срез")
	}
}

func TestResponseNXDOMAINWithSOAHasAuthoritySection(t *testing.T) {
	msg := ResponseNXDOMAINWithSOA(1, "nope.example.com", TypeA, "example.com", 60,
		SOA{MName: "ns1.example.com", RName: "hostmaster.example.com", Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 60})

	if rcode := msg[3] & 0xF; rcode != RCodeNXDOMAIN {
		t.Fatalf("RCODE = %d, хочу %d", rcode, RCodeNXDOMAIN)
	}
	if nscount := binary.BigEndian.Uint16(msg[8:10]); nscount != 1 {
		t.Fatalf("NSCOUNT = %d, хочу 1 (SOA)", nscount)
	}
}

func TestResponseNoDataHasEmptyAnswer(t *testing.T) {
	msg := ResponseNoData(1, "example.com", TypeA)
	if rcode := msg[3] & 0xF; rcode != RCodeNOERROR {
		t.Fatalf("RCODE = %d, хочу %d", rcode, RCodeNOERROR)
	}
	if ancount := binary.BigEndian.Uint16(msg[6:8]); ancount != 0 {
		t.Fatalf("ANCOUNT = %d, хочу 0 (NODATA)", ancount)
	}
}

func TestResponseCNAMEAHasTwoAnswers(t *testing.T) {
	msg := ResponseCNAMEA(1, "example.com", "target.example.com", 30, 300, netip.MustParseAddr("203.0.113.1"))
	if ancount := binary.BigEndian.Uint16(msg[6:8]); ancount != 2 {
		t.Fatalf("ANCOUNT = %d, хочу 2 (CNAME + A)", ancount)
	}
}

func TestQueryID(t *testing.T) {
	q := BuildQuery(QueryOpts{ID: 0xBEEF, Name: "x", Type: TypeA})
	if got := QueryID(q); got != 0xBEEF {
		t.Fatalf("QueryID() = %#x, хочу 0xBEEF", got)
	}
	if got := QueryID(nil); got != 0 {
		t.Fatalf("QueryID(nil) = %#x, хочу 0", got)
	}
}

func TestFillerIsDeterministic(t *testing.T) {
	a := Filler(16)
	b := Filler(16)
	if string(a) != string(b) {
		t.Fatal("Filler недетерминирован при одинаковой длине")
	}
	if len(Filler(9)) != 9 {
		t.Fatal("Filler вернул не ту длину")
	}
}

func TestBrokenHeaderIsShorterThanHeader(t *testing.T) {
	if len(BrokenHeader()) >= 12 {
		t.Fatal("BrokenHeader обязан быть короче 12-байтового заголовка")
	}
}

func TestTrailingGarbageAppendsWithoutMutating(t *testing.T) {
	msg := ResponseNoData(1, "example.com", TypeA)
	garbage := TrailingGarbage(msg)
	if len(garbage) != len(msg)+4 {
		t.Fatalf("длина с мусором = %d, хочу %d", len(garbage), len(msg)+4)
	}
	if len(msg) == len(garbage) {
		t.Fatal("TrailingGarbage не должен менять исходный срез")
	}
}
