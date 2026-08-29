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

	// sweepWG — своя группа, а не s.wg. s.wg считает горутины, чья жизнь
	// кончается сама по себе (чтение сокета NAT, поток DNS): TestD7IdleStreamIsClosed
	// ждёт её опустошения БЕЗ Stack.Close(), проверяя, что простой освобождает
	// горутину сам. Фоновый уборщик простоя живёт до самого close() natTable —
	// он не «освобождается простоем», это его штатное состояние между тиками
	// — и попади он в s.wg, тот же тест ждал бы вечно.
	sweepWG sync.WaitGroup
}

func newNATTable(s *Stack, clk clock.Clock, idle time.Duration) *natTable {
	t := &natTable{
		s: s, clk: clk, idle: idle,
		socks: make(map[netip.AddrPort]*natSocket),
		ents:  make(map[natKey]time.Time),
		swept: clk.Now(),
	}
	t.startIdleSweeper()
	return t
}

// startIdleSweeper заводит фоновую уборку простоя (политика nat_idle_sweep,
// W59). Тот же приём, что у bypass.NAT.startIdleSweeper
// (internal/bypass/bypass.go): выключенная политика не оставляет ни
// горутины, ни тикера — механизма нет целиком, а не «есть, но бездействует».
func (t *natTable) startIdleSweeper() {
	if !policy.NATIdleSweep.On() {
		return
	}
	// Тикер заводится здесь, в конструкторе, а не внутри sweepLoop. Часы
	// могут быть инъектируемыми (clock.Fake): тикер, заведённый внутри
	// горутины, отсчитывал бы первый срок не от New, а от того момента, когда
	// планировщик до горутины дойдёт, — и Advance, обогнавший этот момент, не
	// доставил бы ни одного тика вовсе. На bypass.NAT это стоило красного
	// `go test -count=20 -race`; здесь тикер заводится до возврата из New,
	// пока никакая горутина ещё не читает t.clk.
	period := t.idle / 2
	if period <= 0 {
		// Idle меньше двух наносекунд — величина не из продукта, но тикер с
		// неположительным периодом паникует.
		period = t.idle
	}
	ticker := t.clk.NewTicker(period)
	t.sweepWG.Add(1)
	go t.sweepLoop(ticker)
}

// sweepLoop прокручивает уборку по часам, не дожидаясь ни очередного пакета
// (mapping), ни внешнего Sweep(). Останавливается закрытием стека (t.s.done)
// — natTable отдельного done не заводит, чужой механизм закрытия ему уже
// подчинён: close() зовётся из Stack.Close() ПОСЛЕ close(s.done), и к тому
// моменту, как close() дождётся t.sweepWG, уборщик уже увидел done и вышел.
func (t *natTable) sweepLoop(ticker clock.Ticker) {
	defer t.sweepWG.Done()
	defer ticker.Stop()

	for {
		select {
		case <-t.s.done:
			return
		case <-ticker.C():
			t.sweepNow()
		}
	}
}

// sweepNow — принудительная прокрутка тикером: собственное ограничение
// sweepLocked (не чаще раза на Idle/2) снимается, потому что тикер уже
// ограничил частоту снаружи, а совпасть с недавним mapping() тик может в
// любой момент.
func (t *natTable) sweepNow() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.swept = time.Time{}
	t.sweepLocked(t.clk.Now())
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

// stats — чистый снимок: читает и ничего не меняет. Уборку простоя двигают
// mapping(), внешний Sweep() и (с nat_idle_sweep) фоновый тикер, но не
// наблюдатель — тот же довод, что у bypass.NAT.Stats() (internal/bypass/bypass.go):
// время жизни записи не должно зависеть от того, открыт ли у пользователя
// экран состояния.
func (t *natTable) stats() (entries, sockets int, orphaned int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.ents), len(t.socks), t.orphaned
}

// Sweep прокручивает уборку принудительно — это нужно замеру B3, который
// смотрит, что таблица не только не растёт, но и убывает. Остаётся вне
// nat_idle_sweep: замер двигает часы и шлёт ещё один пакет сам, а выключенная
// политика гасит только фоновую половину (см. startIdleSweeper).
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
	t.closed = true
	for src, sock := range t.socks {
		delete(t.socks, src)
		_ = sock.conn.Close()
	}
	t.ents = make(map[natKey]time.Time)
	t.mu.Unlock()

	// t.s.done уже закрыт (Stack.Close закрывает его до вызова close()), так
	// что уборщик, если он был заведён, вот-вот вернётся сам; ждём вне мьютекса,
	// чтобы не держать его на время выхода чужой горутины.
	t.sweepWG.Wait()
}

// hijackUDP — пункт 1 §3.4 для UDP: запрос уходит в резолвер, а не наружу.
// Этап 3 доводит его до заглушки; настоящий резолвер — этап 6.
func (s *Stack) hijackUDP(f flow, query []byte) {
	if s.cfg.Resolver == nil {
		return
	}
	answer, err := s.cfg.Resolver.Query(query, f.src, f.dst)
	if err != nil || len(answer) == 0 {
		return
	}
	// Источник ответа — тот адрес, на который слал клиент: с чужого адреса
	// резолвер клиента ответ не примет.
	s.write(packet.BuildUDP(f.dst, f.src, answer))
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
