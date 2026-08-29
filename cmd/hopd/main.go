// Команда hopd — привилегированный сервис (§5.2). На этапе 2 он умеет ровно
// то, что описывает §6.2: поднять туннель, отдать его агенту, пережить смерть
// агента отказом вместо молчания и убрать за собой.
//
// Ни узлов, ни ключей, ни Xray здесь нет и не будет (§3.1).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/netstate"
	"github.com/shafed/hop/internal/platform"
	"github.com/shafed/hop/internal/tunnel"
)

func main() {
	var (
		sock     = flag.String("socket", ipc.DefaultPath, "управляющий сокет или труба (§3.1)")
		deadline = flag.Duration("orphan-deadline", 15*time.Second, "окно реаттача (§6.2)")
		beat     = flag.Duration("heartbeat", time.Second, "интервал heartbeat")
		miss     = flag.Int("heartbeat-miss", 3, "пропусков heartbeat до ребра")
		ready    = flag.String("ready-file", "", "создать этот файл, когда сокет готов")
		group    = flag.String("group", "hop", "группа, которой открыт сокет; пусто — только владелец (§6.1, Unix)")
		debug    = flag.Bool("debug", false, "подробный лог")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// Группа резолвится до всякой привилегированной работы: опечатка в имени
	// должна валить старт, а не оставлять сокет, к которому агент не достучится.
	gid, err := lookupGID(*group)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hopd:", err)
		os.Exit(1)
	}

	cfg := tunnel.Config{OrphanDeadline: *deadline, Heartbeat: *beat, HeartbeatMiss: *miss}
	if err := run(log, *sock, *ready, gid, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "hopd:", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, sock, readyFile string, gid int, cfg tunnel.Config) error {
	clk := clock.System{}
	src := netstate.System()

	// Сначала уборка за предыдущим воплощением, и только потом снапшот: T29
	// показал, что смерть сервиса переживают все его правила, и снапшот,
	// снятый до уборки, закрепил бы этот мусор как «исходное состояние».
	if n, err := platform.Reclaim(); err != nil {
		return fmt.Errorf("уборка за предыдущим запуском: %w", err)
	} else if n > 0 {
		log.Warn("сняты правила, пережившие прошлый запуск", "правил", n)
	}

	// Снапшот снимается до первого изменения: восстанавливать нечего, если
	// неизвестно, к чему возвращаться (§8.4).
	before, err := src.Capture()
	if err != nil {
		return fmt.Errorf("снапшот сети: %w", err)
	}

	m := tunnel.New(clk, platform.New(log), cfg)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go tunnel.Run(ctx, clk, m, cfg.Heartbeat/5)

	l, err := ipc.Listen(sock, gid)
	if err != nil {
		return fmt.Errorf("слушать %s: %w", sock, err)
	}
	defer l.Close()

	if readyFile != "" {
		if err := os.WriteFile(readyFile, []byte(sock), 0o644); err != nil {
			return err
		}
	}
	log.Info("hopd готов", "socket", sock)

	srv := ipc.NewServer(m, log)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()

	select {
	case <-ctx.Done():
	case err := <-done:
		log.Error("слушатель остановился", "err", err)
	}

	// Штатный выход обязан вернуть сеть в исходное состояние — тот же контракт
	// §8.4, что проверяют T22 и T23-slow.
	if err := m.Stop(); err != nil {
		log.Error("teardown", "err", err)
	}
	if err := netstate.Verify(before, src); err != nil {
		return err
	}
	log.Info("hopd остановлен, снапшот сети совпал")
	return nil
}
