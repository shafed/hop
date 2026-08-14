package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/shafed/hop/internal/events"
	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/tunnel"
)

// errNoAgent — агент не отвечает. Для команд, которым без него делать нечего.
var errNoAgent = errors.New("агент не запущен (hop up)")

// cmdUp — §С3. Агент уже работает — второй туннель не поднимается: `up`
// делает то единственное, чего от него в этом случае ждут, — фиксирует узел.
func cmdUp(ctx context.Context, env Env, args []string) error {
	fs := flags(env, "up")
	node := fs.String("node", "", "зафиксировать узел и выключить автопереключение")
	if err := parse(fs, args); err != nil {
		return err
	}

	if cl, err := dial(env); err == nil {
		defer cl.Close()
		if *node == "" {
			fmt.Fprintln(env.Out, "агент уже работает")
			return nil
		}
		if err := cl.Pin(*node); err != nil {
			return err
		}
		fmt.Fprintf(env.Out, "узел зафиксирован: %s; автопереключение выключено (hop auto on вернёт)\n", *node)
		return nil
	}

	if env.Up == nil {
		return errors.New("поднимать туннель некому")
	}
	return env.Up(ctx, *node)
}

// cmdDown — §С7. Туннель снимает сервис: он владеет интерфейсом, маршрутами и
// снапшотом сети, и снять их обязан даже тогда, когда агента уже нет (C11).
func cmdDown(env Env, args []string) error {
	fs := flags(env, "down")
	if err := parse(fs, args); err != nil {
		return err
	}
	if env.Down == nil {
		return errors.New("снимать туннель некому")
	}
	if err := env.Down(); err != nil {
		return err
	}
	fmt.Fprintln(env.Out, "туннель снят")
	return nil
}

// cmdStatus — §С5 и §2: фаза (включая orphaned), активный узел, его
// латентность и причина последнего переключения.
func cmdStatus(env Env, args []string) error {
	fs := flags(env, "status")
	asJSON := fs.Bool("json", false, "машинный формат")
	if err := parse(fs, args); err != nil {
		return err
	}

	st, err := status(env)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env.Out, st)
	}
	renderStatus(env.Out, st)
	return nil
}

// status спрашивает агента, а если его нет — сервис.
//
// Второй путь нужен ровно для §2: `orphaned` наступает тогда, когда агента не
// стало, и показать это состояние больше некому (C11).
func status(env Env) (events.Status, error) {
	if cl, err := dial(env); err == nil {
		defer cl.Close()
		return cl.Status()
	}

	svc, err := ipc.Connect(env.Service)
	if err != nil {
		// Ни агента, ни сервиса: туннеля нет и быть не может.
		return events.Status{Phase: tunnel.Down}, nil
	}
	defer svc.Close()

	s, err := svc.Status()
	if err != nil {
		return events.Status{}, err
	}
	return events.Status{
		Phase:        s.Phase,
		Device:       s.Device,
		OrphanLeftMS: s.OrphanLeft.Milliseconds(),
		DetachReason: s.DetachReason,
	}, nil
}

// cmdNodes — §С5. Без агента список берётся из стора: узлы надо видеть сразу
// после `hop sub add`, то есть до первого подключения (§С2).
func cmdNodes(env Env, args []string) error {
	fs := flags(env, "nodes")
	asJSON := fs.Bool("json", false, "машинный формат")
	if err := parse(fs, args); err != nil {
		return err
	}

	var (
		list []events.NodeInfo
		live bool
	)
	if cl, err := dial(env); err == nil {
		defer cl.Close()
		if list, err = cl.Nodes(); err != nil {
			return err
		}
		live = true
	} else {
		st, err := openStore(env)
		if err != nil {
			return err
		}
		defer st.Close()
		list = StoreNodes(st)
	}

	if *asJSON {
		return writeJSON(env.Out, list)
	}
	renderNodes(env.Out, list, live)
	return nil
}

// cmdEvents — §С5. Без --follow показывается последнее переключение: истории
// событий агент не хранит, и врать про неё нечем.
func cmdEvents(ctx context.Context, env Env, args []string) error {
	fs := flags(env, "events")
	follow := fs.Bool("follow", false, "поток событий, пока не прервут")
	if err := parse(fs, args); err != nil {
		return err
	}

	if !*follow {
		st, err := status(env)
		if err != nil {
			return err
		}
		if st.LastSwitch == nil {
			fmt.Fprintln(env.Out, "переключений не было")
			return nil
		}
		fmt.Fprintln(env.Out, switchLine(*st.LastSwitch))
		return nil
	}

	cl, err := dial(env)
	if err != nil {
		return errNoAgent
	}
	defer cl.Close()
	if err := cl.Follow(); err != nil {
		return err
	}
	// Чтение просыпается только закрытием соединения, поэтому Ctrl-C доезжает
	// до него, а не ждёт следующего события. Свой cancel — чтобы сторож ушёл и
	// тогда, когда поток кончился сам.
	watch, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		<-watch.Done()
		cl.Close()
	}()

	for {
		ev, err := cl.Next()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		fmt.Fprintln(env.Out, eventLine(ev))
	}
}

// cmdBypass — §С6: осознанный выпуск трафика мимо узлов. Флаг обязателен и
// ровно один: `hop bypass` без него слишком похож на «выключить».
func cmdBypass(env Env, args []string) error {
	fs := flags(env, "bypass")
	on := fs.Bool("on", false, "выпустить трафик напрямую")
	off := fs.Bool("off", false, "вернуть трафик в туннель")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *on == *off {
		fmt.Fprintln(env.Err, "hop bypass: нужен ровно один флаг, --on или --off")
		return errUsage
	}

	cl, err := dial(env)
	if err != nil {
		return errNoAgent
	}
	defer cl.Close()
	if err := cl.Bypass(*on); err != nil {
		return err
	}
	if *on {
		fmt.Fprintln(env.Out, "обход включён: трафик идёт мимо узлов и не защищён, до перезапуска агента")
	} else {
		fmt.Fprintln(env.Out, "обход выключен")
	}
	return nil
}

// cmdAuto — §С3: вернуть автопереключение после `up --node`.
func cmdAuto(env Env, args []string) error {
	fs := flags(env, "auto")
	if err := parse(fs, args); err != nil {
		return err
	}
	var on bool
	switch fs.Arg(0) {
	case "on":
		on = true
	case "off":
	default:
		fmt.Fprintln(env.Err, "hop auto: нужен аргумент on или off")
		return errUsage
	}

	cl, err := dial(env)
	if err != nil {
		return errNoAgent
	}
	defer cl.Close()
	if err := cl.Auto(on); err != nil {
		return err
	}
	if on {
		fmt.Fprintln(env.Out, "автопереключение включено")
	} else {
		fmt.Fprintln(env.Out, "автопереключение выключено")
	}
	return nil
}
