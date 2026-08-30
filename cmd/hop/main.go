// Команда hop — тонкий клиент и фоновый агент в одном бинаре (§5.2, §5.9).
//
// Разбор аргументов и сборка модулей, и больше ничего: вся логика живёт в
// internal/agent, который проверяется на фейковых часах, без прав, на трёх ОС.
// Грамматика подкоманд, коды возврата и `--json` — в cli.go и output.go.
//
// До этапа С здесь была заглушка этапа 2: агент брал у сервиса дескриптор,
// читал его и выбрасывал прочитанное. Маршруты при этом заворачивали в туннель
// весь трафик машины, то есть «hop up» означал чёрную дыру, а не прокси.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shafed/hop/internal/agent"
	"github.com/shafed/hop/internal/bypass"
	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/resolver"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/tunnel"
)

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
func run(log *slog.Logger, cl control, tokenFile, clientSocket string, beat time.Duration, p tunnel.Params, physical engine.InterfaceFunc, dialDirect resolver.DialDirectFunc, bypassControl bypass.ControlFunc) error {
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

	cfg := agent.Config{
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
		// BypassControl — тот же селектор, тот же механизм §6.8, что у
		// DialDirect: привязка свежего сокета к физическому интерфейсу.
		// Разница только в том, кто сокет открывает — здесь bypass.NAT,
		// а не резолвер.
		BypassControl: bypassControl,
	}
	// Списки §6.10 и апстримы §5.7 — из настроек стора. Отдельным вызовом, а
	// не полями литерала: шов молчалив, и W52 с W53 смотрят именно на него.
	applySettings(&cfg, st)

	a, err = agent.New(cfg)
	if err != nil {
		return err
	}
	defer a.Close()

	a.Start()

	// Сокет клиентов (§3.3) открывается до подъёма туннеля: `hop status` во
	// время долгого старта — это ровно тот момент, когда он нужен, и агент,
	// который начинает отвечать только после успешного Up, молчит именно в
	// фазе waiting (§5.6).
	//
	// Отказ слушателя — отказ запуска, а не предупреждение в лог. Агент,
	// поднявший туннель и недостижимый ни одной командой, — это продукт без
	// поверхности §5.9: снять туннель можно будет только через сервис.
	l, err := ipc.Listen(clientSocket, -1)
	if err != nil {
		return fmt.Errorf("сокет клиентов %s не открылся: %w", clientSocket, err)
	}
	clients := agent.NewClientServer(a, log)
	defer clients.Close()
	go func() {
		if err := clients.Serve(l); err != nil {
			log.Debug("сокет клиентов закрыт", "err", err)
		}
	}()
	defer l.Close()
	log.Info("сокет клиентов открыт", "путь", clientSocket)

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
