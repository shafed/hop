// Тесты настоящего сервера dnstest: настоящие сокеты, настоящее ядро.
//
// Три `SetReadDeadline(time.Now()…)` ниже помечены `//hop:realtime`
// намеренно. Дедлайн ставится ядру на настоящем сокете, и подменять здесь
// время нечем: `internal/clock` управляет ожиданиями продукта, а не тем,
// когда ядро отпустит `read`. Тест, который вместо этого ждал бы фейковых
// часов, повис бы — фейковые часы никто не двигает, а сокет настоящий.
//
// Пометка, а не исключение в линтере: `realtimelint` сам предлагает её своим
// сообщением, и она стоит в строке, которую объясняет. Пока эти три строки
// были непомечены, `realtimelint` в CI падал на каждом пуше, и весь прогон
// был красным — то есть «известный шум» съедал сигнал всего пайплайна.

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
	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //hop:realtime
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

	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //hop:realtime
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
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)) //hop:realtime
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
