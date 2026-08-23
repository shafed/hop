package dnstest

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
)

// RealServer — настоящий UDP+TCP DNS-апстрим на 127.0.0.1: та же
// программируемость (Behavior), что у Upstream, но настоящие сокеты — для L2
// (docs/verification-dns.md §7, п. 10), где трафик до апстрима идёт через
// freedom outbound настоящего узла, а не в памяти процесса.
//
// В отличие от Upstream, адрес один: L2-проверки этого этапа не нуждаются в
// выборе между несколькими апстримами (это уже покрыто L1: D41-D43), а
// продукт свой единственный настроенный апстрим и так спрашивает по одному
// адресу за раз. Behavior.Delay не поддерживается: ни один из L2-сценариев,
// ради которых заведён RealServer, не проверяет фору по времени.
type RealServer struct {
	udp *net.UDPConn
	tcp net.Listener

	mu       sync.Mutex
	behavior Behavior
	queries  []Query

	wg sync.WaitGroup
}

// NewRealServer поднимает UDP- и TCP-слушатели на одном порте 127.0.0.1:0:
// настоящий DNS-апстрим слушает оба протокола на одном порту (RFC 1035
// §4.2.2), и стенд обязан быть его двойником, а не парой независимых портов.
func NewRealServer() (*RealServer, error) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, fmt.Errorf("dnstest: udp: %w", err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	tcp, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		udp.Close()
		return nil, fmt.Errorf("dnstest: tcp: %w", err)
	}

	s := &RealServer{udp: udp, tcp: tcp}
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	return s, nil
}

// Addr — адрес сервера, годный и для Config.Upstreams резолвера, и для
// прямого net.Dial в тесте.
func (s *RealServer) Addr() netip.AddrPort {
	return netip.MustParseAddrPort(s.udp.LocalAddr().String())
}

// Program задаёт поведение сервера. Действует немедленно на все дальнейшие
// запросы; уже принятые до вызова — по прежнему поведению.
func (s *RealServer) Program(b Behavior) {
	s.mu.Lock()
	s.behavior = b
	s.mu.Unlock()
}

func (s *RealServer) behaviorNow() Behavior {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.behavior
}

func (s *RealServer) recordQuery(q Query) {
	s.mu.Lock()
	s.queries = append(s.queries, q)
	s.mu.Unlock()
}

// Queries — все запросы, дошедшие до сервера, в порядке прихода.
func (s *RealServer) Queries() []Query {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Query(nil), s.queries...)
}

func (s *RealServer) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		s.recordQuery(Query{Payload: q, Via: ViaDialUDP})
		go s.answerUDP(addr, q)
	}
}

func (s *RealServer) answerUDP(addr *net.UDPAddr, query []byte) {
	b := s.behaviorNow()
	if b.Silent {
		return
	}
	answer := b.build(query)
	if answer == nil {
		return
	}
	s.udp.WriteToUDP(answer, addr)
}

func (s *RealServer) serveTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.serveTCPConn(conn)
	}
}

func (s *RealServer) serveTCPConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		s.recordQuery(Query{Payload: msg, Via: ViaDial})

		b := s.behaviorNow()
		if b.Silent {
			continue
		}
		if b.BadLengthPrefix {
			var bad [2]byte
			binary.BigEndian.PutUint16(bad[:], 0xFFFF)
			conn.Write(bad[:])
			conn.Write([]byte{0x00, 0x01, 0x02})
			return
		}
		answer := b.build(msg)
		if answer == nil {
			continue
		}
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(len(answer)))
		conn.Write(out[:])
		conn.Write(answer)
	}
}

// Close останавливает оба слушателя и ждёт обслуживающие горутины.
func (s *RealServer) Close() error {
	s.udp.Close()
	s.tcp.Close()
	s.wg.Wait()
	return nil
}
