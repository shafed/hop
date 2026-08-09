package reject

import (
	"errors"
	"io"

	"github.com/shafed/hop/internal/packet"
	"github.com/shafed/hop/internal/policy"
)

// batch — сколько пакетов забирается за одно чтение. В состоянии orphaned
// поток мелкий (приложения упираются в отказ и умолкают), но кольцо всё равно
// нельзя дать переполнить: переполненное кольцо — это молчание, то самое,
// против чего §5.6.
const batch = 64

// Serve — дренаж кольца: единственная часть отказа, которой нужен
// привилегированный ввод-вывод, и вся она здесь.
//
// Возвращает nil, когда устройство закрылось: в orphaned это штатный конец —
// пришёл реаттач или дедлайн.
func Serve(dev packet.PacketDevice) error {
	mtu := dev.MTU()
	if mtu <= 0 {
		mtu = 1500
	}
	bufs := make([][]byte, batch)
	store := make([]byte, batch*mtu)
	for i := range bufs {
		bufs[i] = store[i*mtu : (i+1)*mtu]
	}

	out := make([][]byte, 0, batch)
	for {
		for i := range bufs {
			bufs[i] = bufs[i][:mtu]
		}
		n, err := dev.ReadPackets(bufs)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			return err
		}

		out = out[:0]
		for _, p := range bufs[:n] {
			// Политика §8: без неё кольцо всё так же дренируется, но ответа
			// нет — приложение висит до таймаута вместо немедленного отказа.
			// Ровно это и краснит TestReplyRefusesInsteadOfSilence.
			if !policy.OrphanReject.On() {
				continue
			}
			if r := Reply(p); r != nil {
				out = append(out, r)
			}
		}
		if len(out) > 0 {
			if err := dev.WritePackets(out); err != nil {
				return err
			}
		}
	}
}
