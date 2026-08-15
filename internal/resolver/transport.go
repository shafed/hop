package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// maxMessage — потолок ответа. 4096 хватает и EDNS0-датаграмме, и типичному
// ответу по TCP; больше приходит только от того, кто хочет, чтобы мы съели
// больше памяти.
const maxMessage = 4096

// NodeDialer — исходящее через активный узел. Это ровно то, что умеет
// internal/engine, выраженное без импорта: резолвер не знает про Xray (§3.4),
// а движок не знает про DNS.
//
// Активный узел выбирает реализация: она замыкает id узла, поэтому смена узла
// меняет путь без единого вызова сюда.
type NodeDialer interface {
	DialTCP(ctx context.Context, addr string) (net.Conn, error)
	DialUDP(ctx context.Context) (net.PacketConn, error)
}

// NodeTransport — апстрим через активный узел. Тот же путь, которым идёт
// трафик (§6.7): другого пути наружу у пакета нет.
type NodeTransport struct{ d NodeDialer }

// NewNodeTransport собирает транспорт поверх исходящего узла.
func NewNodeTransport(d NodeDialer) *NodeTransport { return &NodeTransport{d: d} }

// Exchange задаёт один вопрос одному серверу.
func (t *NodeTransport) Exchange(ctx context.Context, server netip.AddrPort, query []byte, stream bool) ([]byte, error) {
	if t.d == nil {
		return nil, errors.New("resolver: нет исходящего")
	}
	if stream {
		return t.overTCP(ctx, server, query)
	}
	return t.overUDP(ctx, server, query)
}

func (t *NodeTransport) overUDP(ctx context.Context, server netip.AddrPort, query []byte) ([]byte, error) {
	pc, err := t.d.DialUDP(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolver: не открылся UDP через узел: %w", err)
	}
	defer pc.Close()
	setDeadline(ctx, pc)

	if _, err := pc.WriteTo(query, net.UDPAddrFromAddrPort(server)); err != nil {
		return nil, fmt.Errorf("resolver: запрос не ушёл: %w", err)
	}
	buf := make([]byte, maxMessage)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("resolver: апстрим не ответил: %w", err)
	}
	// Адрес отвечающего не проверяется: соответствие ответа вопросу решается
	// в accept по идентификатору и вопросу, а адрес на выходе из узла — это
	// адрес узла, а не сервера.
	return buf[:n:n], nil
}

func (t *NodeTransport) overTCP(ctx context.Context, server netip.AddrPort, query []byte) ([]byte, error) {
	conn, err := t.d.DialTCP(ctx, server.String())
	if err != nil {
		return nil, fmt.Errorf("resolver: не открылся TCP через узел: %w", err)
	}
	defer conn.Close()
	setDeadline(ctx, conn)

	// RFC 1035 §4.2.2: двухбайтовый префикс длины.
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(query)))
	if _, err := conn.Write(append(hdr[:], query...)); err != nil {
		return nil, fmt.Errorf("resolver: запрос не ушёл: %w", err)
	}
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("resolver: апстрим не ответил: %w", err)
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > maxMessage {
		return nil, fmt.Errorf("resolver: апстрим прислал %d байт", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("resolver: ответ оборвался: %w", err)
	}
	return buf, nil
}

// deadliner — то общее, что есть у net.Conn и net.PacketConn.
type deadliner interface{ SetDeadline(time.Time) error }

// setDeadline переносит дедлайн контекста на сокет. Контекст здесь не
// сторожит ввод-вывод сам: и core.Dial, и обычный сокет отменяются только
// дедлайном.
func setDeadline(ctx context.Context, c deadliner) {
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
}

// Direct — исходящее мимо туннеля, обычными сокетами процесса.
//
// Это путь bootstrap (§5.7а) и только он. Трафик агента не попадает в туннель
// по построению (§6.8: ip rule с UID-диапазоном на Linux, sockopt.interface на
// macOS и Windows), поэтому «мимо туннеля» здесь — свойство процесса, а не
// свойство этого типа.
type Direct struct {
	// Dialer — чем открывать соединения. Нулевой годится.
	Dialer net.Dialer
}

func (d Direct) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, "tcp4", addr)
}

func (d Direct) DialUDP(ctx context.Context) (net.PacketConn, error) {
	return net.ListenPacket("udp4", "0.0.0.0:0")
}
