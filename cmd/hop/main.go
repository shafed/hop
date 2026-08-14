// Команда hop — агент и CLI в одном бинаре (§5.9). Без команды это агент: он
// берёт у сервиса дескриптор или трубу (§3.2) и гоняет поверх них весь
// датаплейн — netstack, движок Xray, резолвер и health (§3.4). Связывает их
// internal/supervisor, здесь только границы: с сервисом (§3.1) и с клиентами
// (§3.3).
//
// С командой (`hop status`, `hop nodes`, …) тот же бинарь — тонкий клиент
// живого агента: разбор аргументов и печать в internal/cli.
//
// Всё, что §6.2 требует от границы с сервисом, работает по-прежнему: живое
// соединение, heartbeat, реаттач по токену и плановый Detach.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/shafed/hop/internal/cli"
	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/events"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/supervisor"
	"github.com/shafed/hop/internal/tunnel"
)

// errNoDevice — сервис не дал устройства. Отдельная ошибка, потому что на
// Windows это штатное «ещё не сделано» (§7.2), а на Unix — авария.
var errNoDevice = errors.New("сервис не дал устройства")

// options — всё, что задаётся флагами. Одна структура на два пути (агент и
// CLI), потому что пути расходятся только в конце main.
type options struct {
	sock   string
	client string
	token  string
	store  string
	beat   time.Duration
	params tunnel.Params
	mtu    int
	log    *slog.Logger
}

func main() {
	var (
		sock   = flag.String("socket", ipc.DefaultPath, "управляющий сокет сервиса")
		client = flag.String("client-socket", events.DefaultPath, "сокет клиентов агента")
		name   = flag.String("ifname", "hop0", "имя интерфейса")
		addr   = flag.String("addr", "10.255.0.1/24", "адрес туннеля")
		mtu    = flag.Int("mtu", 1400, "MTU")
		table  = flag.Int("table", 8420, "таблица маршрутизации туннеля")
		beat   = flag.Duration("heartbeat", time.Second, "интервал heartbeat")
		token  = flag.String("token-file", defaultTokenFile(), "где лежит attach-token")
		data   = flag.String("store", defaultStoreDir(), "каталог стора агента")
		down   = flag.Bool("down", false, "снять туннель и выйти")
		stat   = flag.Bool("status", false, "сырое состояние сервиса и выйти")
		debug  = flag.Bool("debug", false, "подробный лог")
	)
	flag.Usage = func() {
		cli.Usage(os.Stderr)
		fmt.Fprintln(os.Stderr, "\nглобальные флаги:")
		flag.PrintDefaults()
	}
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	opt := options{
		sock: *sock, client: *client, token: *token, store: *data, beat: *beat, mtu: *mtu,
		params: tunnel.Params{Name: *name, MTU: *mtu, Addr: *addr, Table: *table},
		log:    slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})),
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if args := flag.Args(); len(args) > 0 {
		env := cli.Env{
			Socket:   opt.client,
			Service:  opt.sock,
			StoreDir: opt.store,
			Up:       func(ctx context.Context, pin string) error { return runAgent(ctx, opt, pin) },
			Down:     func() error { return stopTunnel(opt) },
		}
		if err := cli.Run(ctx, env, args); err != nil {
			if !cli.IsUsage(err) {
				fmt.Fprintln(os.Stderr, "hop:", err)
			}
			os.Exit(1)
		}
		return
	}

	// Короткие пути к сервису мимо CLI: ими пользуется стенд L3, которому нужен
	// сырой ответ границы §3.1, а не то, что из него собрал агент.
	switch {
	case *stat:
		cl, err := ipc.Connect(opt.sock)
		if err != nil {
			fail(err)
		}
		defer cl.Close()
		st, err := cl.Status()
		if err != nil {
			fail(err)
		}
		fmt.Printf("phase=%s device=%s reason=%s orphan_left=%v\n",
			st.Phase, st.Device, st.DetachReason, st.OrphanLeft)
		return
	case *down:
		if err := stopTunnel(opt); err != nil {
			fail(err)
		}
		return
	}

	// Без команды и без флагов это агент: при логине его запускает менеджер
	// служб (§6.13), а `hop up` — руками.
	if err := runAgent(ctx, opt, ""); err != nil {
		fail(err)
	}
}

// runAgent — сам агент. Блокирует, пока туннель жив.
func runAgent(ctx context.Context, opt options, pin string) error {
	// Свой cancel: отказавший heartbeat снимает агента тем же путём, что и
	// сигнал, — закрытием устройства (§3.2).
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cl, err := ipc.Connect(opt.sock)
	if err != nil {
		return err
	}
	defer cl.Close()

	// Стор открывается до туннеля: без узлов агент поднимет интерфейс, в
	// который нечего писать, и пользователь получит fail-close вместо внятной
	// ошибки.
	st, err := store.Open(opt.store)
	if err != nil {
		return err
	}
	defer st.Close()

	res, err := acquire(cl, opt.token, opt.params, opt.log)
	if err != nil {
		return err
	}
	// §6.14: токен не попадает в лог ни на debug. В аргументах его нет и быть
	// не может — тип Token форматируется заглушкой.
	opt.log.Info("туннель получен", "device", res.Device, "fd", res.FD)

	dev, closer, err := openDevice(res, opt.mtu)
	if err != nil {
		return err
	}
	defer closer.Close()

	sup, err := supervisor.New(supervisor.Config{
		Device: dev,
		Nodes:  st.AllNodes(),
		Clock:  clock.System{},
	})
	if err != nil {
		return err
	}

	api := newAgentAPI(sup, cl, st)
	if pin != "" {
		// `hop up --node` (§С3): фиксация до старта, иначе первый же прогон проб
		// успеет выбрать не тот узел.
		if err := api.Pin(pin); err != nil {
			return err
		}
	}

	// Сокет клиентов поднимается до Run: `hop status` обязан отвечать и в фазе
	// starting, когда ни одна проба ещё не закончилась (§2).
	srv, err := events.Serve(opt.client, api)
	if err != nil {
		return err
	}
	defer srv.Close()

	// Чтение устройства снимается только его закрытием: насос сидит в read, и
	// отмена контекста до него не доходит (§3.2).
	go func() {
		<-ctx.Done()
		closer.Close()
	}()
	go heartbeat(ctx, cl, opt.beat, cancel, opt.log)
	go forceOnSignal(ctx, sup, opt.log)
	go publish(sup, srv)

	// Ошибка насоса уезжает вызывающему: агент, у которого умерло устройство,
	// обязан выйти с ненулевым кодом, иначе менеджер служб сочтёт это плановым
	// завершением и не перезапустит его (§6.13).
	runErr := sup.Run(ctx)

	// Плановый уход: сервис узнаёт причину и показывает её в status. Окно
	// отказа схлопывается до времени respawn (§6.2).
	if err := cl.Detach(tunnel.ReasonRestart); err != nil {
		opt.log.Debug("Detach", "err", err)
	}
	return runErr
}

// publish перекладывает события супервизора в сокет клиентов (§3.3). Здесь же
// единственное место, где внутреннее событие агента становится машинным.
func publish(sup *supervisor.Supervisor, srv *events.Server) {
	for ev := range sup.Subscribe() {
		out := events.Event{At: ev.At, Phase: ev.Phase}
		if ev.Switch != nil {
			sw := events.FromSwitch(*ev.Switch)
			out.Switch = &sw
		}
		srv.Publish(out)
	}
}

// stopTunnel — `hop down` (§С7): туннель снимает сервис, он владеет
// интерфейсом, маршрутами и снапшотом сети.
func stopTunnel(opt options) error {
	cl, err := ipc.Connect(opt.sock)
	if err != nil {
		return err
	}
	defer cl.Close()
	if err := cl.Stop(); err != nil {
		return err
	}
	return removeToken(opt.token)
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

// heartbeat — детектор заклинившего агента с той стороны границы (§6.2). Его
// отказ означает, что сервиса больше нет: держать туннель, которым никто не
// управляет, незачем, поэтому агент уходит.
func heartbeat(ctx context.Context, cl *ipc.Client, every time.Duration, stop context.CancelFunc, log *slog.Logger) {
	t := clock.System{}.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			if err := cl.Heartbeat(); err != nil {
				log.Error("heartbeat", "err", err)
				stop()
				return
			}
		}
	}
}

// forceOnSignal — форс-проверка §6.6 по внешнему сигналу.
//
// SIGHUP — временная замена платформенным наблюдателям за сменой интерфейса,
// пробуждением и правкой таблицы маршрутизации: их место в §6.6, а сами они
// приезжают с платформенным слоем этапа 8. Сигнал даёт то же самое ребро руками
// и systemd-юниту, и тесту.
func forceOnSignal(ctx context.Context, sup *supervisor.Supervisor, log *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			log.Info("форс-проверка узлов по сигналу")
			sup.Force(health.TriggerInterface)
		}
	}
}

// defaultStoreDir — каталог стора агента. Права 0700 выставляет сам стор
// (§6.14): в узлах лежат ключи доступа.
func defaultStoreDir() string {
	if dir := os.Getenv("HOP_STORE"); dir != "" {
		return dir
	}
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "hop")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "hop")
	}
	return filepath.Join(home, ".local", "share", "hop")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "hop:", err)
	os.Exit(1)
}
