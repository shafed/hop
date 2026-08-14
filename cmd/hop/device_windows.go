//go:build windows

package main

import (
	"io"

	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/packet"
)

// openDevice на Windows забирает пакеты трубой данных, а не дескриптором:
// Wintun — это хендл драйвера с кольцевым буфером, привязанный к
// процессу-владельцу адаптера (§3.2).
//
// Труба появится вместе с платформенным слоем: без подписанной wintun.dll рядом
// с бинарём адаптер не поднимается, а это открытый вопрос §7.2, который план
// держит блокером этапа 8.
func openDevice(_ ipc.Result, _ int) (packet.PacketDevice, io.Closer, error) {
	return nil, nil, errNoDevice
}
