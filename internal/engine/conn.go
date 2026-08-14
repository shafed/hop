package engine

import (
	"errors"
	"io"
	"net"
)

// Соединение Xray устанавливается лениво: `core.Dial` отдаёт `cnc.Connection`
// поверх пайпа диспетчера и возвращается **до** того, как случится хоть один
// байт в сторону узла (`core/functions.go:49` — Dispatch уходит в горутину).
// Отказ узла — недоступный порт, сломанное рукопожатие, отвергнутый ключ —
// приезжает поэтому на первой записи или первом чтении, а не из Dial.
//
// Отсюда обёртка. Без неё §6.15 не работал бы вовсе: health.ReportFailure
// звали бы по ошибке Dial, которой в этом сценарии не бывает, и мёртвый узел
// оставался бы живым до истечения окна проб — то есть бюджет «5 секунд под
// трафиком» (docs/verification-autoswitch.md §4) не выполнялся бы никогда.
//
// Классификация при этом остаётся в одном месте: и Dial, и Read, и Write ходят
// в ту же classify.

// classifiedConn — соединение, чьи ошибки уже разобраны по §6.15.
type classifiedConn struct {
	net.Conn
	nodeID string
}

func (c *classifiedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	return n, c.wrap(err)
}

func (c *classifiedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	return n, c.wrap(err)
}

// wrap классифицирует ошибку ввода-вывода.
//
// EOF не трогаем: нормальное закрытие соединения удалённой стороной — это не
// отказ узла, а конец разговора. Ошибиться здесь значит убивать узел на каждом
// закрытом HTTP-соединении.
func (c *classifiedConn) wrap(err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return err
	}
	var de *DialError
	if errors.As(err, &de) {
		return err // уже разобрано
	}
	return classifyDial(c.nodeID, err)
}

// classifiedPacketConn — то же для UDP (§5.3).
type classifiedPacketConn struct {
	net.PacketConn
	nodeID string
}

func (c *classifiedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	return n, addr, c.wrap(err)
}

func (c *classifiedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, addr)
	return n, c.wrap(err)
}

func (c *classifiedPacketConn) wrap(err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return err
	}
	var de *DialError
	if errors.As(err, &de) {
		return err
	}
	return classifyDial(c.nodeID, err)
}
