// Package dnstest — настоящий DNS-сервер внутри процесса теста (§8.1).
//
// Пакет намеренно **не импортирует testing**: им пользуются и L1-тесты
// резолвера, и L2-стенд, где запрос идёт через настоящий узел, — по той же
// причине, по которой xraytest и probetarget живут отдельно от тестов.
//
// Сервер слушает и UDP, и TCP: §3.4 хайджекает :53 на обоих, а §5.7 обязан
// уметь дослать усечённый ответ по TCP. Зона программируется, ответы считаются
// по транспортам — иначе «второй запрос ушёл в апстрим» и «второй запрос взят
// из кэша» неразличимы.
package dnstest

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Server — запущенный авторитетный сервер на 127.0.0.1 со свободным портом.
type Server struct {
	udp *net.UDPConn
	tcp net.Listener

	mu        sync.Mutex
	zone      map[key][]netip.Addr
	ttl       map[key]time.Duration
	nx        map[string]bool
	truncate  bool
	udpCount  int
	tcpCount  int
	perName   map[string]int
	closeOnce sync.Once
	wg        sync.WaitGroup
}

type key struct {
	name string
	typ  dnsmessage.Type
}

// DefaultTTL — TTL записи, если он не задан явно.
const DefaultTTL = 60 * time.Second

// New поднимает сервер на 127.0.0.1 со свободным портом. UDP и TCP слушают
// один и тот же порт: клиент, дославший запрос по TCP после TC=1, идёт на тот
// же адрес (RFC 1035 §4.2.2).
func New() (*Server, error) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, fmt.Errorf("dnstest: не слушается UDP: %w", err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	tcp, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("dnstest: не слушается TCP: %w", err)
	}

	s := &Server{
		udp:     udp,
		tcp:     tcp,
		zone:    make(map[key][]netip.Addr),
		ttl:     make(map[key]time.Duration),
		nx:      make(map[string]bool),
		perName: make(map[string]int),
	}
	s.wg.Add(2)
	go func() { defer s.wg.Done(); s.serveUDP() }()
	go func() { defer s.wg.Done(); s.serveTCP() }()
	return s, nil
}

// Addr — адрес сервера, он же «апстрим» для резолвера.
func (s *Server) Addr() netip.AddrPort {
	a := s.udp.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(a.Port))
}

// Set задаёт ответ на A-запрос по имени. ttl <= 0 означает DefaultTTL.
func (s *Server) Set(name string, ttl time.Duration, addrs ...netip.Addr) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	k := key{name: fqdn(name), typ: dnsmessage.TypeA}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zone[k] = addrs
	s.ttl[k] = ttl
	delete(s.nx, k.name)
}

// SetNXDOMAIN заставляет сервер отвечать «имени нет».
func (s *Server) SetNXDOMAIN(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nx[fqdn(name)] = true
}

// SetTruncate включает ответ с TC=1 по UDP: клиент обязан переспросить по TCP.
func (s *Server) SetTruncate(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.truncate = on
}

// Queries — сколько запросов пришло по каждому транспорту.
func (s *Server) Queries() (udp, tcp int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udpCount, s.tcpCount
}

// QueriesFor — сколько запросов пришло по конкретному имени, обоими
// транспортами.
func (s *Server) QueriesFor(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.perName[fqdn(name)]
}

// Close останавливает сервер.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		_ = s.udp.Close()
		_ = s.tcp.Close()
	})
	s.wg.Wait()
}

func (s *Server) serveUDP() {
	buf := make([]byte, 4096)
	for {
		n, from, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		answer, ok := s.answer(buf[:n], false)
		if !ok {
			continue
		}
		_, _ = s.udp.WriteToUDP(answer, from)
	}
}

func (s *Server) serveTCP() {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			var hdr [2]byte
			for {
				if _, err := io.ReadFull(conn, hdr[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(hdr[:]))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				answer, ok := s.answer(query, true)
				if !ok {
					return
				}
				binary.BigEndian.PutUint16(hdr[:], uint16(len(answer)))
				if _, err := conn.Write(append(hdr[:], answer...)); err != nil {
					return
				}
			}
		}()
	}
}

// answer строит ответ на запрос. Второй результат — false, если отвечать не на
// что: битый запрос сервер молча роняет, как и настоящий.
func (s *Server) answer(query []byte, overTCP bool) ([]byte, bool) {
	var m dnsmessage.Message
	if err := m.Unpack(query); err != nil || len(m.Questions) != 1 {
		return nil, false
	}
	q := m.Questions[0]

	s.mu.Lock()
	if overTCP {
		s.tcpCount++
	} else {
		s.udpCount++
	}
	name := q.Name.String()
	s.perName[name]++
	addrs := s.zone[key{name: name, typ: q.Type}]
	ttl := s.ttl[key{name: name, typ: q.Type}]
	nx := s.nx[name]
	truncate := s.truncate && !overTCP
	s.mu.Unlock()

	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 m.Header.ID,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   m.Header.RecursionDesired,
			RecursionAvailable: true,
			Truncated:          truncate,
		},
		Questions: m.Questions,
	}
	switch {
	case nx:
		resp.Header.RCode = dnsmessage.RCodeNameError
	case truncate:
		// TC=1 без тела: клиент обязан переспросить по TCP, а не разбирать
		// обрезок. Так же ведёт себя настоящий сервер при переполнении.
	default:
		for _, a := range addrs {
			a4 := a.As4()
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   uint32(ttl / time.Second),
				},
				Body: &dnsmessage.AResource{A: a4},
			})
		}
	}

	out, err := resp.Pack()
	if err != nil {
		return nil, false
	}
	return out, true
}

// fqdn приводит имя к виду с точкой на конце — в таком виде его отдаёт
// dnsmessage.Name.String().
func fqdn(name string) string {
	if name == "" {
		return "."
	}
	if name[len(name)-1] == '.' {
		return name
	}
	return name + "."
}
