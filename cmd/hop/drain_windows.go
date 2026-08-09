//go:build windows

package main

import (
	"context"
	"log/slog"

	"github.com/shafed/hop/internal/ipc"
)

// drain на Windows забирает пакеты трубой данных, а не дескриптором: Wintun —
// это хендл драйвера с кольцевым буфером, привязанный к процессу-владельцу
// адаптера (§3.2).
//
// Труба появится вместе с платформенным слоем: без подписанной wintun.dll
// рядом с бинарём адаптер не поднимается, а это открытый вопрос §7.2, который
// план держит блокером этапа 8.
func drain(_ context.Context, res ipc.Result, _ int, log *slog.Logger) {
	log.Error("труба данных на Windows появится вместе с адаптером Wintun (§7.2, этап 8)",
		"device", res.Device)
}
