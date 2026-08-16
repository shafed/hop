package netstack

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/packet"
	"github.com/shafed/hop/internal/policy"
)

// natKey — ключ NAT-записи. При full-cone (§5.3) dst нулевой: запись одна на
// исходный порт клиента, и ответ принимается **с любого** адреса. При
// nat_key=src+dst ключ становится парой, и ответ с адреса, на который клиент не
// слал, не находит записи и теряется — это и краснит T15.
type natKey struct {
	src netip.AddrPort
	dst netip.AddrPort
}

func keyFor(src, dst netip.AddrPort) natKey {
	if policy.NATKey.On() {
		return natKey{src: src}
	}
	return natKey{src: src, dst: dst}
}

// natSocket — исходящий сокет. Один на исходный порт клиента, потому что
// core.DialUDP отдаёт ровно это (§5.3). Ключей NAT на него может приходиться
// сколько угодно; при full-cone — ровно один.
type natSocket struct {
	conn net.PacketConn
	src  netip.AddrPort
}

// natTable — NAT §5.3: full-cone, по source addr:port.
type natTable struct {
	s    *Stack
	clk  clock.Clock
	idle time.Duration

	mu       sync.Mutex
	socks    map[netip.AddrPort]*natSocket
	ents     map[natKey]time.Time
	orphaned int64
	closed   bool
	swept    time.Time
}

func newNATTable(s *Stack, clk clock.Clock, idle time.Duration) *natTable {
	return &natTable{
		s: s, clk: clk, idle: idle,
		socks: make(map[netip.AddrPort]*natSocket),
		ents:  make(map[natKey]time.Time),
		swept: clk.Now(),
	}
}

// send выпускает датаграмму наружу, заводя сокет и запись NAT при первой
// встрече исходного порта.
func (t *natTable) send(f flow, payload []byte) {
	sock, ok := t.mapping(f)
	if !ok {
		return
	}
	_, _ = sock.conn.WriteTo(payload, net.UDPAddrFromAddrPort(f.dst))
}

func (t *natTable) mapping(f flow) (*natSocket, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, false
	}

	now := t.clk.Now()
	t.sweepLocked(now)

	sock, ok := t.socks[f.src]
	if !ok {
		if t.s.cfg.Dialer == nil {
			return nil, false
		}
		conn, err := t.s.cfg.Dialer.DialUDP(f.src)
		if err != nil {
			return nil, false
		}
		sock = &natSocket{conn: conn, src: f.src}
		t.socks[f.src] = sock
		t.s.wg.Add(1)
		go func() {
			defer t.s.wg.Done()
			t.receive(sock)
		}()
	}
	t.ents[keyFor(f.src, f.dst)] = now
	return sock, true
}

// receive — обратный путь. Ответ приходит с какого-то адреса; запись NAT
// решает, дойдёт ли он до клиента.
func (t *natTable) receive(sock *natSocket) {
	buf := make([]byte, 65535)
	for {
		n, from, err := sock.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		peer, ok := addrPort(from)
		if !ok {
			continue
		}
		if !t.allow(sock.src, peer) {
			t.mu.Lock()
			t.orphaned++
			t.mu.Unlock()
			continue
		}
		t.s.write(packet.BuildUDP(peer, sock.src, buf[:n]))
	}
}

// allow — поиск записи NAT для ответа. Единственное место, где full-cone
// отличается от NAT по паре: при full-cone dst в ключе нулевой, и адрес
// отвечающего в поиск не входит вовсе.
func (t *natTable) allow(src, peer netip.AddrPort) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := keyFor(src, peer)
	if _, ok := t.ents[k]; !ok {
		return false
	}
	t.ents[k] = t.clk.Now()
	return true
}

func (t *natTable) stats() (entries, sockets int, orphaned int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.ents), len(t.socks), t.orphaned
}

// Sweep прокручивает уборку принудительно — это нужно замеру B3, который
// смотрит, что таблица не только не растёт, но и убывает.
func (t *natTable) Sweep() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.swept = time.Time{}
	t.sweepLocked(t.clk.Now())
}

// sweepLocked выкидывает просроченные записи и закрывает сокеты, за которыми
// не осталось ни одной. Без второго шага таблица записей убывала бы, а сокеты
// копились — течь та же, только незаметнее.
func (t *natTable) sweepLocked(now time.Time) {
	if now.Sub(t.swept) < t.idle/2 {
		return
	}
	t.swept = now

	live := make(map[netip.AddrPort]struct{}, len(t.socks))
	for k, seen := range t.ents {
		if now.Sub(seen) >= t.idle {
			delete(t.ents, k)
			continue
		}
		live[k.src] = struct{}{}
	}
	for src, sock := range t.socks {
		if _, ok := live[src]; !ok {
			delete(t.socks, src)
			_ = sock.conn.Close()
		}
	}
}

func (t *natTable) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	for src, sock := range t.socks {
		delete(t.socks, src)
		_ = sock.conn.Close()
	}
	t.ents = make(map[natKey]time.Time)
}

// hijackUDP — пункт 1 §3.4 для UDP: запрос уходит в резолвер, а не наружу.
//
// Резолв идёт **не на насосе**. С заглушкой этапа 3 разницы не было, с
// настоящим резолвером этапа 6 это поход через узел длиной до секунд, и на
// время этого похода стояло бы всё устройство целиком: один DNS-запрос
// останавливал бы весь трафик машины. Полезная нагрузка живёт только до
// следующего чтения, поэтому копируется.
//
// Число одновременных резолвов ограничено: клиент по UDP переспрашивает сам,
// и без потолка поток запросов превращался бы в поток горутин. Одинаковые
// вопросы при этом склеивает сам резолвер, так что потолок задевает только
// по-настоящему разные имена.
func (s *Stack) hijackUDP(f flow, query []byte) {
	if s.cfg.Resolver == nil {
		return
	}
	select {
	case s.dnsSlots <- struct{}{}:
	default:
		// Потолок выбран: запрос дропается, клиент переспросит. Отказать
		// внятно здесь нечем — это стоило бы разбора запроса на насосе.
		s.count(&s.dnsDropped)
		return
	}

	q := append([]byte(nil), query...)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { <-s.dnsSlots }()

		answer, err := s.cfg.Resolver.Query(q, f.src, f.dst)
		if err != nil || len(answer) == 0 {
			return
		}
		// Источник ответа — тот адрес, на который слал клиент: с чужого адреса
		// резолвер клиента ответ не примет.
		s.write(packet.BuildUDP(f.dst, f.src, answer))
	}()
}

// addrPort — адрес отвечающего в том виде, в каком его знает NAT. IPv6 сюда не
// попадает: §6.9 его блокирует, и отвечать на него нечем.
func addrPort(a net.Addr) (netip.AddrPort, bool) {
	var ap netip.AddrPort
	switch v := a.(type) {
	case *net.UDPAddr:
		ap = v.AddrPort()
	default:
		var err error
		if ap, err = netip.ParseAddrPort(a.String()); err != nil {
			return netip.AddrPort{}, false
		}
	}
	addr := ap.Addr().Unmap()
	if !addr.Is4() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, ap.Port()), true
}
