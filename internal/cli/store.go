package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/shafed/hop/internal/events"
)

// Состав узлов §С2 и §5.8: шесть команд, каждая — один запрос агенту.
//
// Правит стор агент (internal/catalog), а не этот процесс. Прежде было
// наоборот (отклонение C12), и оправдание у того было одно: `hop sub add`
// обязан работать до первого `hop up`, то есть когда агента ещё нет. Оправдание
// отпало вместе с §6.13 — агент стартует при старте ОС. А под системным
// пользователем `hop` (§6.8) прежний путь и невозможен: до каталога агента
// клиент под своим UID не достаёт.

// cmdSub — подписки §5.8 и §С2.
func cmdSub(ctx context.Context, env Env, args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(env.Err, "hop sub: нужна подкоманда add, update, rm или list")
		return errUsage
	}
	switch args[0] {
	case "add":
		return subAdd(ctx, env, args[1:])
	case "update":
		return subUpdate(ctx, env, args[1:])
	case "rm":
		return subRemove(env, args[1:])
	case "list":
		return subList(env, args[1:])
	default:
		fmt.Fprintf(env.Err, "hop sub: неизвестная подкоманда %q\n", args[0])
		return errUsage
	}
}

// subAdd — §С2. Скачивает, разбирает и сливает агент; здесь печать сводки.
func subAdd(_ context.Context, env Env, args []string) error {
	fs := flags(env, "sub add")
	name := fs.String("name", "", "имя группы")
	// Адрес вынимается до разбора флагов. Справка §5.9 пишет его первым
	// (`sub add <url> [--name <имя>]`), а flag.Parse останавливается на первом
	// позиционном аргументе — и `--name` за адресом молча пропадал бы.
	var src string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		src, args = args[0], args[1:]
	}
	if err := parse(fs, args); err != nil {
		return err
	}
	if src == "" {
		src = fs.Arg(0)
	}
	if src == "" {
		fmt.Fprintln(env.Err, "hop sub add: нужен адрес подписки")
		return errUsage
	}

	cl, err := dial(env)
	if err != nil {
		return errNoAgent
	}
	defer cl.Close()

	res, err := cl.SubAdd(src, *name)
	if err != nil {
		return err
	}
	printSub(env, res)
	noteAgentRestart(env)
	return nil
}

// subUpdate — §С8 и `hop sub update`. Без аргумента агент обновляет все
// подписки: типичный пользователь держит две-три ради отказоустойчивости.
func subUpdate(_ context.Context, env Env, args []string) error {
	fs := flags(env, "sub update")
	if err := parse(fs, args); err != nil {
		return err
	}

	cl, err := dial(env)
	if err != nil {
		return errNoAgent
	}
	defer cl.Close()

	res, err := cl.SubUpdate(fs.Arg(0))
	if err != nil {
		return err
	}
	for _, r := range res {
		printSub(env, r)
	}
	noteAgentRestart(env)
	return nil
}

func subRemove(env Env, args []string) error {
	fs := flags(env, "sub rm")
	if err := parse(fs, args); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		fmt.Fprintln(env.Err, "hop sub rm: нужен id подписки")
		return errUsage
	}

	cl, err := dial(env)
	if err != nil {
		return errNoAgent
	}
	defer cl.Close()

	if err := cl.SubRemove(id); err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "подписка %s удалена\n", id)
	noteAgentRestart(env)
	return nil
}

func subList(env Env, args []string) error {
	fs := flags(env, "sub list")
	if err := parse(fs, args); err != nil {
		return err
	}

	cl, err := dial(env)
	if err != nil {
		return errNoAgent
	}
	defer cl.Close()

	groups, err := cl.SubList()
	if err != nil {
		return err
	}
	renderGroups(env.Out, groups)
	return nil
}

// cmdNode — отдельные узлы §С2 и поштучная проверка.
func cmdNode(ctx context.Context, env Env, args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(env.Err, "hop node: нужна подкоманда add, rm или ping")
		return errUsage
	}
	switch args[0] {
	case "add":
		return nodeAdd(env, args[1:])
	case "rm":
		return nodeRemove(env, args[1:])
	case "ping":
		return nodePing(env, args[1:])
	default:
		fmt.Fprintf(env.Err, "hop node: неизвестная подкоманда %q\n", args[0])
		return errUsage
	}
}

// nodeAdd — §С2: ссылка на отдельный узел попадает в группу manual.
func nodeAdd(env Env, args []string) error {
	fs := flags(env, "node add")
	if err := parse(fs, args); err != nil {
		return err
	}
	link := fs.Arg(0)
	if link == "" {
		fmt.Fprintln(env.Err, "hop node add: нужна ссылка на узел")
		return errUsage
	}

	cl, err := dial(env)
	if err != nil {
		return errNoAgent
	}
	defer cl.Close()

	n, err := cl.NodeAdd(link)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "узел добавлен: %s (%s), группа %s\n", n.ID, n.Name, n.Group)
	if !n.Supported {
		// §6.11: узел сохранён и виден в списке, но кандидатом не станет.
		fmt.Fprintln(env.Out, "протокол этой сборкой не поддержан: узел в выборе не участвует")
	}
	noteAgentRestart(env)
	return nil
}

// nodeRemove удаляет узел. Агент называет подписку, из которой тот пришёл:
// такой узел вернётся при следующем обновлении, и молчать об этом нельзя —
// удаление выглядело бы несработавшим.
func nodeRemove(env Env, args []string) error {
	fs := flags(env, "node rm")
	if err := parse(fs, args); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		fmt.Fprintln(env.Err, "hop node rm: нужен id узла")
		return errUsage
	}

	cl, err := dial(env)
	if err != nil {
		return errNoAgent
	}
	defer cl.Close()

	from, err := cl.NodeRemove(id)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "узел %s удалён\n", id)
	if from != "" {
		fmt.Fprintf(env.Out, "узел из подписки %s: он вернётся при hop sub update\n", from)
	}
	noteAgentRestart(env)
	return nil
}

// nodePing — форс-проверка узла (§6.6) и его состояние после неё. Проба идёт
// тем же путём, что трафик (§6.7), поэтому без агента её сделать нечем.
func nodePing(env Env, args []string) error {
	fs := flags(env, "node ping")
	if err := parse(fs, args); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		fmt.Fprintln(env.Err, "hop node ping: нужен id узла")
		return errUsage
	}

	cl, err := dial(env)
	if err != nil {
		return errNoAgent
	}
	defer cl.Close()

	n, err := cl.Ping(id)
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Out, nodeLine(n))
	return nil
}

// printSub — §С2: сводка о том, сколько добавлено и сколько неподдерживаемых.
// Сохранённые и удалённые тоже здесь: это и есть наблюдаемый результат
// diff-слияния (§5.8).
func printSub(env Env, r events.SubResult) {
	fmt.Fprintf(env.Out, "подписка %s (%s): добавлено %d, сохранено %d, удалено %d, не поддержано %d\n",
		r.GroupName, r.GroupID, r.Added, r.Kept, r.Removed, r.Unsupported)
	if r.Warning != "" {
		fmt.Fprintf(env.Err, "нераспознанные строки пропущены: %v\n", r.Warning)
	}
}

// noteAgentRestart предупреждает, что живой агент состава узлов не перечитывает
// (отклонение C12): список кандидатов он собрал при запуске. Команда сюда
// доходит только через живого агента, поэтому проверять его наличие уже нечем.
func noteAgentRestart(env Env) {
	fmt.Fprintln(env.Out, "агент уже работает: новый состав узлов вступит в силу после hop down и hop up")
}
