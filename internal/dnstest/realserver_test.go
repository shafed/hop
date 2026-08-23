package dnstest

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRealServerAnswersUDP(t *testing.T) {
	s, err := NewRealServer()
	if err != nil {
		t.Fatalf("NewRealServer: %v", err)
	}
	defer s.Close()

	const name = "real.example"
	ip := netip.MustParseAddr("203.0.113.9")
	s.Program(Behavior{Func: func(q []byte) []byte {
		return ResponseA(QueryID(q), name, 300, ip)
	}})

	query := BuildQuery(QueryOpts{ID: 0xAAAA, Name: name, Type: TypeA})
	conn, err := net.Dial("udp4", s.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n < 12 {
		t.Fatalf("ответ %d байт короче заголовка", n)
	}
	if qs := s.Queries(); len(qs) != 1 || qs[0].Via != ViaDialUDP {
		t.Fatalf("Queries() = %+v, хотим один запрос через UDP", qs)
	}
}

func TestRealServerAnswersTCP(t *testing.T) {
	s, err := NewRealServer()
	if err != nil {
		t.Fatalf("NewRealServer: %v", err)
	}
	defer s.Close()

	const name = "real-tcp.example"
	ip := netip.MustParseAddr("203.0.113.10")
	s.Program(Behavior{Func: func(q []byte) []byte {
		return ResponseA(QueryID(q), name, 300, ip)
	}})

	query := BuildQuery(QueryOpts{ID: 0xBBBB, Name: name, Type: TypeA})
	conn, err := net.Dial("tcp4", s.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	var hdr [2]byte
	hdr[0] = byte(len(query) >> 8)
	hdr[1] = byte(len(query))
	conn.Write(hdr[:])
	conn.Write(query)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	respHdr := make([]byte, 2)
	if _, err := readFull(conn, respHdr); err != nil {
		t.Fatalf("читаем префикс: %v", err)
	}
	n := int(respHdr[0])<<8 | int(respHdr[1])
	body := make([]byte, n)
	if _, err := readFull(conn, body); err != nil {
		t.Fatalf("читаем тело: %v", err)
	}
	if len(body) < 12 {
		t.Fatal("ответ короче заголовка")
	}
	if qs := s.Queries(); len(qs) != 1 || qs[0].Via != ViaDial {
		t.Fatalf("Queries() = %+v, хотим один запрос через TCP", qs)
	}
}

func TestRealServerSilentBehaviorDoesNotAnswer(t *testing.T) {
	s, err := NewRealServer()
	if err != nil {
		t.Fatalf("NewRealServer: %v", err)
	}
	defer s.Close()
	// Behavior{} нулевого значения — Silent (та же семантика, что у Upstream).

	conn, err := net.Dial("udp4", s.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	conn.Write(BuildQuery(QueryOpts{ID: 1, Name: "silent.example", Type: TypeA}))
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("незапрограммированный сервер ответил — ожидалось молчание")
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
