//go:build unix

package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/shafed/hop/internal/ipc"
)

// drain — весь датаплейн этапа 2: агент читает дескриптор и выбрасывает
// прочитанное. Netstack приедет на этапе 3.
//
// Дескриптор именно приехал через SCM_RIGHTS, а не был открыт агентом: агент
// непривилегирован и открыть /dev/net/tun не может. Это и проверяет L3.
func drain(ctx context.Context, res ipc.Result, mtu int, log *slog.Logger) {
	if res.FD < 0 {
		log.Error("сервис не прислал дескриптор")
		return
	}
	f := os.NewFile(uintptr(res.FD), res.Device)
	defer f.Close()

	go func() {
		<-ctx.Done()
		f.Close() // разбудить read
	}()

	buf := make([]byte, mtu)
	var n uint64
	for {
		if _, err := f.Read(buf); err != nil {
			log.Debug("чтение устройства прекращено", "err", err, "пакетов", n)
			return
		}
		n++
	}
}
