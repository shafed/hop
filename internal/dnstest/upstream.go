// Package dnstest — L1-стенд для перехваченного DNS-резолвера этапа 6
// (docs/verification-dns.md, §2, конец): поддельный апстрим с
// программируемыми ответами, задержками, флагом TC и молчанием, часы без
// гонки на Advance (Clock), фейковая фаза трафика (Phase) и байтовые
// писатели DNS-сообщений (msg.go). На этом стенде гоняется весь регистр
// уровня L1 из docs/verification-dns.md — без сети, TUN, Xray и прав.
//
// Сообщения стенд строит своими писателями, а не через internal/dnsmsg:
// фикстуры, собранные тем же кодом, который они проверяют, прячут его
// ошибки (.superpowers/sdd/handoff-md-wondrous-boole/task-2-brief.md).
//
// Пакет намеренно не импортирует testing — по той же причине, по которой
// internal/fakenet и internal/xraytest его не импортируют: тестовые флаги в
// бинаре, который свяжет этот пакет напрямую (например, бенчмарк резолвера),
// не нужны.
package dnstest

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/shafed/hop/internal/clock"
)

// Via — каким из трёх диалеров ушёл запрос. Три числа, а не два (через
// узел/мимо), потому что через узел ходят двумя разными диалерами — UDP и
// TCP, — и D5/D33 обязаны отличать их друг от друга не меньше, чем от
// DialDirect.
type Via int

const (
	ViaDialUDP Via = iota
	ViaDial
	ViaDialDirect
)

func (v Via) String() string {
	switch v {
	case ViaDialUDP:
		return "DialUDP"
	case ViaDial:
		return "Dial"
	case ViaDialDirect:
		return "DialDirect"
	default:
		return "?"
	}
}

// Behavior — запрограммированный ответ одного адреса апстрима.
//
// Поля комбинируются в фиксированном порядке: Silent обрывает обработку до
// всего остального (молчание не ждёт — оно и не начинает), затем Delay,
// затем BadLengthPrefix (только TCP), затем Answer/Func.
type Behavior struct {
	// Silent — не отвечать вовсе. Соединение виснет так же, как молчащий
	// настоящий апстрим: клиентская сторона узнаёт об этом только по
	// собственному таймауту (D14, D40). Нулевое значение Behavior — это
	// Silent: см. behaviorFor.
	Silent bool

	// Delay — фора перед ответом. Считается инъектированными часами
	// (Upstream.clk.After), а не настоящим временем: без этого проверка
	// форы 150 мс (D41–D43) либо ждёт вживую 150 реальных миллисекунд на
	// каждый прогон, либо не ждёт вовсе и превращается в тавтологию.
	Delay time.Duration

	// Answer — готовые байты ответа.
	Answer []byte

	// Func строит ответ по байтам дошедшего запроса — нужен, когда ответ
	// обязан нести идентификатор именно этого запроса: он не клиентский
	// (Р23 регистра), и фиксированный Answer его не подберёт. Имеет
	// приоритет над Answer, если задан.
	Func func(query []byte) []byte

	// BadLengthPrefix — только для TCP-соединений (Dial, DialDirect по
	// "tcp"): сервер шлёт заведомо неверный двухбайтовый префикс длины и
	// обрывок тела вместо настоящего ответа, затем закрывает поток (D37).
	// Answer и Func в этом случае игнорируются.
	BadLengthPrefix bool
}

func (b Behavior) build(query []byte) []byte {
	if b.Func != nil {
		return b.Func(query)
	}
	return b.Answer
}

// Query — один запрос, дошедший до стенда.
type Query struct {
	Payload []byte
	Via     Via
	Dst     netip.AddrPort
}

// Calls — сколько раз позвали каждый из трёх диалеров. D51/D52 отличают путь
// через узел от пути мимо туннеля именно этими числами, а не договорённостью
// об аргументе — тот же принцип, на котором держатся пробы §6.7 (A34).
type Calls struct {
	DialUDP    uint64
	Dial       uint64
	DialDirect uint64
}

// Upstream — поддельный DNS-апстрим: набор адресов, каждому из которых
// программируется своё поведение. Ни одного настоящего сокета не открывает —
// соединения живут в памяти (net.Pipe для TCP, каналы для UDP), как и
// датаплейн-стенд этапа 3 (internal/fakenet).
type Upstream struct {
	clk clock.Clock

	mu       sync.Mutex
	cond     *sync.Cond
	behavior map[netip.AddrPort]Behavior
	queries  []Query
	calls    Calls
}

// New создаёт апстрим на часах clk. Часы должны быть общими с теми, что
// получит резолвер (Config.Clock) — иначе Behavior.Delay и таймауты
// резолвера считают время по-разному, и фору 150 мс или таймаут попытки
// нечем свести к одному Advance. Обычно clk — это *Clock из этого пакета:
// тогда WaitAfterCalls видит обращения к After и от стенда, и от резолвера.
func New(clk clock.Clock) *Upstream {
	u := &Upstream{clk: clk, behavior: make(map[netip.AddrPort]Behavior)}
	u.cond = sync.NewCond(&u.mu)
	return u
}

// Program задаёт поведение адреса addr.
func (u *Upstream) Program(addr netip.AddrPort, b Behavior) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.behavior[addr] = b
}

// behaviorFor — незапрограммированный адрес молчит: нулевое значение
// Behavior эквивалентно Silent. Молчание — безопасное умолчание подставного
// сервера; отвечать чем попало адресу, который тест не настраивал, опаснее.
func (u *Upstream) behaviorFor(addr netip.AddrPort) Behavior {
	u.mu.Lock()
	defer u.mu.Unlock()
	b, ok := u.behavior[addr]
	if !ok {
		return Behavior{Silent: true}
	}
	return b
}

func (u *Upstream) recordQuery(q Query) {
	u.mu.Lock()
	u.queries = append(u.queries, q)
	switch q.Via {
	case ViaDialUDP:
		u.calls.DialUDP++
	case ViaDial:
		u.calls.Dial++
	case ViaDialDirect:
		u.calls.DialDirect++
	}
	u.cond.Broadcast()
	u.mu.Unlock()
}

// Queries — все запросы, дошедшие до стенда, в порядке прихода.
func (u *Upstream) Queries() []Query {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]Query(nil), u.queries...)
}

// WaitQueries блокируется, пока до стенда не дойдёт n запросов. Ожидание, а
// не опрос со сном — по той же причине, что и у internal/fakenet.WaitConn:
// настоящее время в продукте и тестах живёт только в internal/clock, а
// зависший тест по этой примете и находят.
func (u *Upstream) WaitQueries(n int) []Query {
	u.mu.Lock()
	defer u.mu.Unlock()
	for len(u.queries) < n {
		u.cond.Wait()
	}
	return append([]Query(nil), u.queries...)
}

// Calls — счётчики по диалерам, раздельно.
func (u *Upstream) Calls() Calls {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

// DialUDP — путь наверх через активный узел (Config.DialUDP).
func (u *Upstream) DialUDP(ctx context.Context, dst netip.AddrPort) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &udpPacketConn{u.newUDPCore(dst, ViaDialUDP)}, nil
}

// Dial — путь наверх через активный узел, TCP (Config.Dial): им резолвер
// повторяет запрос после TC (§5.7).
func (u *Upstream) Dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return u.newTCPConn(dst, ViaDial), nil
}

// DialDirect — путь мимо туннеля (Config.DialDirect, §6.8): им ходят
// bootstrap и фаза bypass. network — как в net.Dial: "udp" или "tcp" (с
// суффиксами 4/6).
func (u *Upstream) DialDirect(ctx context.Context, network string, dst netip.AddrPort) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch network {
	case "udp", "udp4", "udp6":
		return &udpStreamConn{u.newUDPCore(dst, ViaDialDirect)}, nil
	case "tcp", "tcp4", "tcp6":
		return u.newTCPConn(dst, ViaDialDirect), nil
	default:
		return nil, fmt.Errorf("dnstest: неизвестная сеть %q", network)
	}
}

// udpCore — общая часть поддельного UDP-сокета: PacketConn (DialUDP) и Conn
// (DialDirect по udp) — два разных интерфейса над одной логикой, отличаются
// только тем, что от них требует net.PacketConn против net.Conn.
type udpCore struct {
	up  *Upstream
	dst netip.AddrPort
	via Via

	in   chan []byte
	done chan struct{}
	once sync.Once
}

// udpInboxSize — сколько неприкрытых ответов держит сокет. Один запрос —
// один ответ, поэтому запас нужен только на случай, если тест не читает Read
// сразу; большего в стенде не бывает.
const udpInboxSize = 8

func (u *Upstream) newUDPCore(dst netip.AddrPort, via Via) *udpCore {
	return &udpCore{
		up:   u,
		dst:  dst,
		via:  via,
		in:   make(chan []byte, udpInboxSize),
		done: make(chan struct{}),
	}
}

func (c *udpCore) send(p []byte) {
	q := Query{Payload: append([]byte(nil), p...), Via: c.via, Dst: c.dst}
	c.up.recordQuery(q)
	go c.up.answerUDP(c, q.Payload)
}

func (c *udpCore) recv(p []byte) (int, error) {
	select {
	case d := <-c.in:
		return copy(p, d), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}

func (c *udpCore) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}

// answerUDP — вся программируемость апстрима для UDP в одном месте. Молчание
// возвращается немедленно и горутины не заводит: D40/D44 требуют, чтобы у
// молчащего апстрима не копились ресурсы, и стенду проще всего сдержать это
// обещание за резолвер, а не полагаться на то, что он сам не будет ждать.
func (u *Upstream) answerUDP(c *udpCore, query []byte) {
	b := u.behaviorFor(c.dst)
	if b.Silent {
		return
	}
	if b.Delay > 0 {
		select {
		case <-u.clk.After(b.Delay):
		case <-c.done:
			return
		}
	}
	answer := b.build(query)
	if answer == nil {
		return
	}
	select {
	case c.in <- answer:
	case <-c.done:
	}
}

// udpPacketConn — net.PacketConn от DialUDP.
type udpPacketConn struct{ *udpCore }

func (c *udpPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.send(p)
	return len(p), nil
}

func (c *udpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.recv(p)
	return n, net.UDPAddrFromAddrPort(c.dst), err
}

func (c *udpPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *udpPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *udpPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *udpPacketConn) SetWriteDeadline(time.Time) error { return nil }

// udpStreamConn — net.Conn от DialDirect по "udp": та же логика, но без
// WriteTo/ReadFrom, потому что мимо туннеля резолвер ходит на один заранее
// известный адрес и явный адрес назначения ему не нужен.
type udpStreamConn struct{ *udpCore }

func (c *udpStreamConn) Write(p []byte) (int, error) { c.send(p); return len(p), nil }
func (c *udpStreamConn) Read(p []byte) (int, error)  { return c.recv(p) }

func (c *udpStreamConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *udpStreamConn) RemoteAddr() net.Addr             { return net.UDPAddrFromAddrPort(c.dst) }
func (c *udpStreamConn) SetDeadline(time.Time) error      { return nil }
func (c *udpStreamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *udpStreamConn) SetWriteDeadline(time.Time) error { return nil }

// newTCPConn возвращает клиентский конец соединения; сервер обслуживает
// другой конец в отдельной горутине — тот же приём, которым xraytest поднимает
// настоящий Xray за настоящим сокетом, только здесь без сети вообще.
func (u *Upstream) newTCPConn(dst netip.AddrPort, via Via) net.Conn {
	near, far := net.Pipe()
	go u.serveTCP(far, dst, via)
	return near
}

// serveTCP читает кадры RFC 1035 §4.2.2 (двухбайтовый префикс длины) и
// отвечает на каждый в своей горутине: D6 разрешает вернуть ответы не по
// порядку, поэтому чтение следующего запроса не должно ждать ответа на
// предыдущий — иначе Delay одного запроса блокирует конвейер целиком.
func (u *Upstream) serveTCP(conn net.Conn, dst netip.AddrPort, via Via) {
	defer conn.Close()
	var writeMu sync.Mutex
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(hdr[:])
		msg := make([]byte, n)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		u.recordQuery(Query{Payload: msg, Via: via, Dst: dst})
		go u.answerTCP(conn, &writeMu, dst, msg)
	}
}

func (u *Upstream) answerTCP(conn net.Conn, writeMu *sync.Mutex, dst netip.AddrPort, query []byte) {
	b := u.behaviorFor(dst)
	if b.Silent {
		return
	}
	if b.Delay > 0 {
		<-u.clk.After(b.Delay)
	}

	writeMu.Lock()
	defer writeMu.Unlock()

	if b.BadLengthPrefix {
		// Заявляем длину заведомо больше того, что реально шлём, и рвём
		// поток: резолвер обязан распознать сообщение как битое (D37), а не
		// заблокироваться в ожидании недостающих байт до собственного
		// таймаута — не закрыв соединение, стенд сам стал бы источником
		// зависшего теста.
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], 0xFFFF)
		conn.Write(hdr[:])
		conn.Write([]byte{0x00, 0x01, 0x02})
		conn.Close()
		return
	}

	answer := b.build(query)
	if answer == nil {
		return
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(answer)))
	conn.Write(hdr[:])
	conn.Write(answer)
}
