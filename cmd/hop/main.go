// Команда hop — агент (§3.4, §5.2). Разбор аргументов и сборка модулей, и
// больше ничего: вся логика живёт в internal/agent, который проверяется на
// фейковых часах, без прав, на трёх ОС.
//
// До этапа С здесь была заглушка этапа 2: агент брал у сервиса дескриптор,
// читал его и выбрасывал прочитанное. Маршруты при этом заворачивали в туннель
// весь трафик машины, то есть «hop up» означал чёрную дыру, а не прокси.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shafed/hop/internal/agent"
	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/outbound"
	"github.com/shafed/hop/internal/resolver"
	"github.com/shafed/hop/internal/store"
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
		tok   = flag.String("token-file", defaultTokenFile(), "где лежит attach-token")
		down  = flag.Bool("down", false, "снять туннель и выйти")
		stat  = flag.Bool("status", false, "показать состояние и выйти")
		debug = flag.Bool("debug", false, "подробный лог")

		// Ввод узлов (Р40) — временный интерфейс этапа С. Подкоманды приедут
		// этапом 9 и наденутся поверх тех же вызовов.
		subURL = flag.String("sub", "", "скачать подписку по ссылке, слить в стор и выйти")
		link   = flag.String("node", "", "добавить один узел по ссылке (vless://…) и выйти")
		list   = flag.Bool("nodes", false, "показать узлы из стора и выйти")
		rm     = flag.String("rm", "", "удалить узел или группу по id и выйти")
		probe  = flag.Bool("probe", false, "проверить узлы через outbound без туннеля и выйти")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// Режимы стора идут до соединения с сервисом: добавить подписку можно и
	// при неподнятом hopd, и требовать сокет ради записи на диск незачем.
	switch {
	case *subURL != "":
		physical, err := outbound.New(*name)
		if err != nil {
			fail(err)
		}
		defer physical.Close()
		fail(withStore(func(st *store.Store) error {
			return addSubscription(context.Background(), st, *subURL, os.Stdout, physical.HTTPClient())
		}))
		return
	case *link != "":
		fail(withStore(func(st *store.Store) error {
			return addNode(st, *link, os.Stdout)
		}))
		return
	case *rm != "":
		fail(withStore(func(st *store.Store) error {
			return removeNode(st, *rm, os.Stdout)
		}))
		return
	case *probe:
		physical, err := outbound.New(*name)
		if err != nil {
			fail(err)
		}
		defer physical.Close()
		fail(withStore(func(st *store.Store) error {
			return probeNodes(context.Background(), st, os.Stdout, physical.Interface)
		}))
		return
	case *list:
		fail(withStore(func(st *store.Store) error {
			listNodes(st, os.Stdout)
			return nil
		}))
		return
	}

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
		_ = removeToken(*tok)
		return
	}

	physical, err := outbound.New(*name)
	if err != nil {
		fail(err)
	}
	defer physical.Close()

	if err := run(log, cl, *tok, *beat, tunnelParams(*name, *addr, *mtu, *table),
		physical.Interface, physical.DialDirect); err != nil {
		fail(err)
	}
}

// tunnelParams собирает только параметры привилегированной поверхности.
// Защита от петли §6.8 теперь остаётся в агенте и через IPC не проходит.
func tunnelParams(name, addr string, mtu, table int) tunnel.Params {
	return tunnel.Params{
		Name: name, MTU: mtu, Addr: addr, Table: table,
	}
}

// withStore открывает стор, отдаёт его fn и закрывает.
//
// Закрытие обязательно и в отказном пути: стор держит межпроцессный замок
// (§6.14), и брошенный замок сделал бы следующий запуск отказом на ровном месте.
func withStore(fn func(*store.Store) error) error {
	root, err := storeRoot()
	if err != nil {
		return err
	}
	st, err := store.Open(root, clock.System{})
	if err != nil {
		return err
	}
	err = fn(st)
	if cerr := st.Close(); err == nil {
		err = cerr
	}
	return err
}

// run — весь агент: стор, живость, связка, туннель.
//
// Порядок сборки продиктован одним кругом: проберу нужен дозвон через outbound
// узла (§6.7), дозвон живёт в связке, а связке нужна живость, которой нужен
// пробер. Круг разрывается замыканием — пробер зовёт дозвон лениво, к моменту
// первой пробы связка уже собрана.
func run(log *slog.Logger, cl control, tokenFile string, beat time.Duration, p tunnel.Params, physical engine.InterfaceFunc, dialDirect resolver.DialDirectFunc) error {
	root, err := storeRoot()
	if err != nil {
		return err
	}
	st, err := store.Open(root, clock.System{})
	if err != nil {
		return err
	}
	defer st.Close()

	var a *agent.Agent
	hm := health.New(health.Config{
		Clock: clock.System{},
		Prober: newProber(func(ctx context.Context, nodeID, network, addr string) (net.Conn, error) {
			return a.ProbeDial(ctx, nodeID, network, addr)
		}),
		Interrupt: func() int { return a.InterruptConnections() },
	})

	tr := newTransport(cl, tokenFile, beat, log)
	defer tr.close()

	a, err = agent.New(agent.Config{
		Store:    st,
		Health:   hm,
		Trans:    tr,
		Params:   p,
		Clock:    clock.System{},
		Log:      log,
		Physical: physical,
		// Прямой путь §6.8: им ходят bootstrap и перехваченный DNS в фазе
		// bypass. Строится из селектора, а не из net.Dialer: непривязанный
		// сокет вернулся бы в туннель, и §5.7(а) дал бы петлю на старте.
		DialDirect: dialDirect,
	})
	if err != nil {
		return err
	}
	defer a.Close()

	a.Start()
	if err := a.Up(); err != nil {
		return err
	}
	log.Info("туннель поднят", "интерфейс", p.Name)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Наблюдаемость до этапа 9: без неё «трафик пошёл» и «трафик в никуда»
	// выглядят в логе одинаково — молчанием.
	go watch(ctx, a, log, 3*time.Second)

	<-ctx.Done()

	// Плановый уход: сервис узнаёт причину и показывает её в status, а окно
	// отказа схлопывается до времени respawn (§6.2). Detach, а не Stop:
	// интерфейс обязан пережить перезапуск агента (T24).
	tr.detach()
	return nil
}

func fail(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "hop:", err)
	os.Exit(1)
}
