// Команда hop — агент. На этапе 2 он заглушка по построению: берёт у сервиса
// дескриптор или трубу, читает и выбрасывает. Netstack, Xray, DNS и health —
// следующие этапы.
//
// Смысл этой заглушки в том, что она настоящая ровно там, где §6.2 требует:
// живое соединение с сервисом, heartbeat, реаттач по токену и плановый Detach.
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
	"github.com/shafed/hop/internal/tunnel"
)

func main() {
	var (
		sock  = flag.String("socket", ipc.DefaultPath, "управляющий сокет сервиса")
		name  = flag.String("ifname", "hop0", "имя интерфейса")
		addr  = flag.String("addr", "10.255.0.1/24", "адрес туннеля")
		mtu   = flag.Int("mtu", 1400, "MTU")
		table = flag.Int("table", 8420, "таблица маршрутизации туннеля")
		beat  = flag.Duration("heartbeat", time.Second, "интервал heartbeat")
		store = flag.String("token-file", defaultTokenFile(), "где лежит attach-token")
		down  = flag.Bool("down", false, "снять туннель и выйти")
		stat  = flag.Bool("status", false, "показать состояние и выйти")
		debug = flag.Bool("debug", false, "подробный лог")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cl, err := ipc.Connect(*sock)
	if err != nil {
		fail(err)
	}
	defer cl.Close()

	switch {
	case *stat:
		st, err := cl.Status()
		if err != nil {
			fail(err)
		}
		fmt.Printf("phase=%s device=%s reason=%s orphan_left=%v\n",
			st.Phase, st.Device, st.DetachReason, st.OrphanLeft)
		return
	case *down:
		if err := cl.Stop(); err != nil {
			fail(err)
		}
		_ = removeToken(*store)
		return
	}

	res, err := acquire(cl, *store, tunnel.Params{
		Name: *name, MTU: *mtu, Addr: *addr, Table: *table,
	}, log)
	if err != nil {
		fail(err)
	}
	// §6.14: токен не попадает в лог ни на debug. В аргументах его нет и быть
	// не может — тип Token форматируется заглушкой.
	log.Info("туннель получен", "device", res.Device, "fd", res.FD)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go drain(ctx, res, *mtu, log)
	heartbeat(ctx, cl, *beat, log)

	// Плановый уход: сервис узнаёт причину и показывает её в status. Окно
	// отказа схлопывается до времени respawn (§6.2).
	if err := cl.Detach(tunnel.ReasonRestart); err != nil {
		log.Debug("Detach", "err", err)
	}
}

// acquire сначала пробует реаттач: если сервис в orphaned и токен от прошлого
// сеанса ещё жив, туннель забирается целиком — тот же интерфейс, тот же
// дескриптор (T24).
func acquire(cl *ipc.Client, store string, p tunnel.Params, log *slog.Logger) (ipc.Result, error) {
	if tok, err := loadToken(store); err == nil {
		res, err := cl.Attach(tok)
		if err == nil {
			log.Info("реаттач по токену удался")
			return res, nil
		}
		log.Debug("реаттач не удался, поднимаем заново", "err", err)
	}

	res, err := cl.Start(p)
	if err != nil {
		return ipc.Result{}, err
	}
	if err := saveToken(store, res.Token); err != nil {
		return ipc.Result{}, err
	}
	return res, nil
}

func heartbeat(ctx context.Context, cl *ipc.Client, every time.Duration, log *slog.Logger) {
	t := clock.System{}.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			if err := cl.Heartbeat(); err != nil {
				log.Error("heartbeat", "err", err)
				return
			}
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "hop:", err)
	os.Exit(1)
}
