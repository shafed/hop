package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"

	"github.com/shafed/hop/internal/events"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/node"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/sub"
)

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

// subAdd — §С2: скачать, разобрать, создать группу, показать сводку.
//
// Повторный add того же адреса не плодит вторую группу: id считается от адреса,
// и подписка обновляется на месте вместе с историей проб (§5.8).
func subAdd(ctx context.Context, env Env, args []string) error {
	fs := flags(env, "sub add")
	name := fs.String("name", "", "имя группы")
	if err := parse(fs, args); err != nil {
		return err
	}
	src := fs.Arg(0)
	if src == "" {
		fmt.Fprintln(env.Err, "hop sub add: нужен адрес подписки")
		return errUsage
	}

	st, err := openStore(env)
	if err != nil {
		return err
	}
	defer st.Close()

	g, ok := st.Group(groupID(src))
	if !ok {
		g = store.Group{ID: groupID(src)}
	}
	g.SourceURL = src
	switch {
	case *name != "":
		g.Name = *name
	case g.Name == "":
		g.Name = hostOf(src)
	}
	// Группа доезжает до стора только вместе с узлами (это делает applySub):
	// иначе опечатка в адресе оставляла бы в списке пустую подписку.
	return applySub(ctx, env, st, g)
}

// subUpdate — §С8 и `hop sub update`. Без аргумента обновляются все подписки:
// типичный пользователь держит две-три ради отказоустойчивости (§5.8).
func subUpdate(ctx context.Context, env Env, args []string) error {
	fs := flags(env, "sub update")
	if err := parse(fs, args); err != nil {
		return err
	}

	st, err := openStore(env)
	if err != nil {
		return err
	}
	defer st.Close()

	var groups []store.Group
	if id := fs.Arg(0); id != "" {
		g, ok := st.Group(id)
		if !ok {
			return fmt.Errorf("подписка %q не найдена", id)
		}
		groups = []store.Group{g}
	} else {
		for _, g := range st.Groups() {
			if g.SourceURL != "" {
				groups = append(groups, g)
			}
		}
	}
	if len(groups) == 0 {
		return errors.New("обновлять нечего: подписок нет")
	}

	for _, g := range groups {
		if g.SourceURL == "" {
			return fmt.Errorf("у группы %s нет источника: это ручные узлы", g.ID)
		}
		if err := applySub(ctx, env, st, g); err != nil {
			return err
		}
	}
	return nil
}

// applySub — общий путь add и update: загрузка, разбор, diff-слияние (§5.8).
func applySub(ctx context.Context, env Env, st *store.Store, g store.Group) error {
	body, quota, err := env.Fetch(ctx, g.SourceURL)
	if err != nil {
		return err
	}
	parsed, perr := sub.ParseSubscription(body, g.ID)
	if len(parsed) == 0 {
		if perr != nil {
			return perr
		}
		return fmt.Errorf("подписка %s: узлов нет", g.ID)
	}

	g.QuotaInfo = quota
	g.LastUpdatedAt = env.Clock.Now()
	if err := st.PutGroup(g); err != nil {
		return err
	}
	diff, err := st.ApplySubscription(g.ID, parsed)
	if err != nil {
		return err
	}

	var unsupported int
	for _, n := range parsed {
		if !n.Supported {
			unsupported++
		}
	}
	// §С2: сводка — сколько добавлено и сколько неподдерживаемых. Сохранённые и
	// удалённые тоже здесь: это и есть наблюдаемый результат diff-слияния (§5.8).
	fmt.Fprintf(env.Out, "подписка %s (%s): добавлено %d, сохранено %d, удалено %d, не поддержано %d\n",
		g.Name, g.ID, len(diff.Added), len(diff.Kept), len(diff.Removed), unsupported)
	if perr != nil {
		fmt.Fprintf(env.Err, "нераспознанные строки пропущены: %v\n", perr)
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

	st, err := openStore(env)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.DeleteGroup(id); err != nil {
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

	st, err := openStore(env)
	if err != nil {
		return err
	}
	defer st.Close()
	renderGroups(env.Out, st)
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

	n, err := sub.ParseLink(link)
	if err != nil {
		return err
	}
	n.GroupID = store.ManualGroup
	n.MergeKey = sub.MergeKey(n)

	st, err := openStore(env)
	if err != nil {
		return err
	}
	defer st.Close()

	n, err = st.PutNode(n)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "узел добавлен: %s (%s), группа %s\n", n.ID, nodeName(n), n.GroupID)
	if !n.Supported {
		// §6.11: узел сохранён и виден в списке, но кандидатом не станет.
		fmt.Fprintf(env.Out, "протокол %s этой сборкой не поддержан: узел в выборе не участвует\n", n.Protocol)
	}
	noteAgentRestart(env)
	return nil
}

// nodeRemove удаляет узел.
//
// Стор умеет удалять группу целиком и сливать в неё состав, но не умеет
// удалять узел поштучно, поэтому удаление выражено слиянием оставшегося
// состава: узлы, пережившие его, сохраняют id и историю проб (§5.8) — ровно то
// же свойство, на котором стоит обновление подписки.
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

	st, err := openStore(env)
	if err != nil {
		return err
	}
	defer st.Close()

	target, ok := st.Node(id)
	if !ok {
		return fmt.Errorf("узел %q не найден", id)
	}
	var rest []node.Node
	for _, n := range st.Nodes(target.GroupID) {
		if n.ID == id {
			continue
		}
		if n.MergeKey == "" {
			n.MergeKey = sub.MergeKey(n)
		}
		rest = append(rest, n)
	}
	if _, err := st.ApplySubscription(target.GroupID, rest); err != nil {
		return err
	}

	fmt.Fprintf(env.Out, "узел %s удалён\n", id)
	if g, ok := st.Group(target.GroupID); ok && g.SourceURL != "" {
		fmt.Fprintf(env.Out, "узел из подписки %s: он вернётся при hop sub update\n", g.ID)
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

// StoreNodes — список узлов из стора без всякой живости. Им пользуются оба:
// вывод `hop nodes` при спящем агенте и сам агент, который накладывает на этот
// список текущее здоровье.
func StoreNodes(st *store.Store) []events.NodeInfo {
	all := st.AllNodes()
	out := make([]events.NodeInfo, 0, len(all))
	for _, n := range all {
		out = append(out, events.NodeInfo{
			ID:        n.ID,
			Name:      nodeName(n),
			Group:     n.GroupID,
			State:     health.Untested,
			Supported: n.Supported,
		})
	}
	return out
}

// noteAgentRestart предупреждает, что живой агент состава узлов не перечитывает
// (отклонение C12): список кандидатов он собрал при запуске.
func noteAgentRestart(env Env) {
	cl, err := dial(env)
	if err != nil {
		return
	}
	cl.Close()
	fmt.Fprintln(env.Out, "агент уже работает: новый состав узлов вступит в силу после hop down и hop up")
}

// groupID — устойчивый id подписки: адрес и есть её тождество (§5.8).
func groupID(src string) string {
	sum := sha256.Sum256([]byte(src))
	return hex.EncodeToString(sum[:4])
}

func hostOf(src string) string {
	if u, err := url.Parse(src); err == nil && u.Host != "" {
		return u.Host
	}
	return src
}

func nodeName(n node.Node) string {
	if n.Name != "" {
		return n.Name
	}
	return n.Addr()
}
