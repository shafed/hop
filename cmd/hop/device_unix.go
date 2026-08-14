//go:build unix

package main

import (
	"io"
	"os"

	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/packet"
)

// openDevice — PacketDevice поверх дескриптора TUN, приехавшего через
// SCM_RIGHTS (§3.2). Агент непривилегирован и открыть /dev/net/tun сам не может:
// дескриптор именно получен от сервиса, это и проверяет L3.
//
// Второй возврат закрывает устройство: чтение блокирующее, и разбудить его
// может только закрытие — этим владелец снимает агента.
func openDevice(res ipc.Result, mtu int) (packet.PacketDevice, io.Closer, error) {
	if res.FD < 0 {
		return nil, nil, errNoDevice
	}
	f := os.NewFile(uintptr(res.FD), res.Device)
	return &tunDevice{f: f, mtu: mtu}, f, nil
}

// tunDevice — один пакет за одну операцию. Батча здесь нет и быть не может:
// read() на TUN без vnet_hdr возвращает ровно один пакет (D4), а GSO §4 из v1
// исключил.
type tunDevice struct {
	f   *os.File
	mtu int
}

func (d *tunDevice) MTU() int { return d.mtu }

func (d *tunDevice) ReadPackets(bufs [][]byte) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	n, err := d.f.Read(bufs[0][:cap(bufs[0])])
	if n > 0 {
		bufs[0] = bufs[0][:n]
		return 1, err
	}
	return 0, err
}

func (d *tunDevice) WritePackets(bufs [][]byte) error {
	for _, b := range bufs {
		if _, err := d.f.Write(b); err != nil {
			return err
		}
	}
	return nil
}
