package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/subscription"
)

// Ввод узлов (Р40). Три одноразовых режима: сделали дело и вышли.
//
// Это временный интерфейс. Подкоманды `hop sub add`, `hop node add`,
// `hop nodes` — этап 9; они надеваются поверх этих же вызовов, потому что вся
// работа здесь делается пакетами subscription и store, а не флагами.

// addSubscription скачивает подписку и сливает её в группу (§5.8, §6.16).
//
// Вся логика — в subscription.Updater, включая Р7: любой отказ до последнего
// шага оставляет группу ровно такой, какой она была. Здесь только выбор группы
// и вывод.
func addSubscription(ctx context.Context, st *store.Store, url string, out io.Writer, doer subscription.Doer) error {
	u := &subscription.Updater{
		Store:      st,
		Downloader: subscription.NewDownloader(doer, clock.System{}),
	}

	// Группа именуется по ссылке, а не случайно: повторный `-sub` с той же
	// ссылкой обязан обновить ту же группу, а не завести вторую. Слияние §6.16
	// иначе не увидело бы прежних узлов и потеряло бы всю их историю проб.
	groupID := groupIDFor(url)

	res, err := u.Update(ctx, groupID, url)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "подписка %s: формат %s, добавлено %d, оставлено %d, удалено %d\n",
		groupID, res.Format, len(res.Merged.Added), len(res.Merged.Kept), len(res.Merged.Removed))
	for _, reason := range sortedReasons(res.Merged.Unsupported) {
		fmt.Fprintf(out, "  не поддержано (%s): %d\n", reason, res.Merged.Unsupported[reason])
	}
	return nil
}

// addNode кладёт одну ссылку в группу manual (Р10).
func addNode(st *store.Store, link string, out io.Writer) error {
	p, err := subscription.Parse([]byte(link))
	if err != nil {
		return err
	}
	if len(p.Nodes) == 0 {
		if len(p.Unsupported) > 0 {
			return fmt.Errorf("ссылка не разобрана: %s", p.Unsupported[0].Reason)
		}
		return fmt.Errorf("в ссылке не нашлось ни одного узла")
	}
	if len(p.Nodes) > 1 {
		return fmt.Errorf("в аргументе %d узлов, а -node берёт один; для пачки есть -sub", len(p.Nodes))
	}

	m := subscription.Add(store.ManualGroupID, st.Nodes(store.ManualGroupID), p.Nodes[0], subscription.NewID)
	if err := st.Apply(store.ManualGroupID, m); err != nil {
		return err
	}
	if len(m.Added) == 0 {
		fmt.Fprintln(out, "такой узел уже есть, стор не изменился")
		return nil
	}
	fmt.Fprintf(out, "узел добавлен в группу %s\n", store.ManualGroupID)
	return nil
}

// removeNode убирает узел или всю группу.
//
// Один флаг на два случая намеренно: пользователь видит в `-nodes` и то и
// другое одним списком и не обязан знать, что у них разная природа. Пустой
// состав группы стор принимает — это тот же Apply, что и слияние, только
// состав пуст, — и живость удалённых узлов уходит вместе с ними (§1/С8).
func removeNode(st *store.Store, id string, out io.Writer) error {
	for _, g := range st.Groups() {
		if g.ID != id {
			continue
		}
		n := len(st.Nodes(g.ID))
		if err := st.Apply(g.ID, store.Merged{}); err != nil {
			return err
		}
		fmt.Fprintf(out, "группа %s очищена, узлов удалено: %d\n", g.ID, n)
		return nil
	}

	node, ok := st.Node(id)
	if !ok {
		return fmt.Errorf("в сторе нет ни узла, ни группы с id %q", id)
	}
	m := subscription.Remove(st.Nodes(node.GroupID), id)
	if err := st.Apply(node.GroupID, m); err != nil {
		return err
	}
	fmt.Fprintf(out, "узел %s удалён из группы %s\n", id, node.GroupID)
	return nil
}

// listNodes печатает, что лежит в сторе.
//
// Ключи не печатаются ни в каком виде (§6.14): в выводе только id, имя, адрес
// и порт — того, чем узел опознаётся глазом, для этого хватает.
func listNodes(st *store.Store, out io.Writer) {
	groups := st.Groups()
	if len(groups) == 0 {
		fmt.Fprintln(out, "стор пуст: добавьте подписку через -sub или узел через -node")
		return
	}
	for _, g := range groups {
		nodes := st.Nodes(g.ID)
		fmt.Fprintf(out, "группа %s (%d узлов)\n", g.ID, len(nodes))
		for _, n := range nodes {
			mark := " "
			if !n.Supported {
				mark = "×"
			}
			fmt.Fprintf(out, "  %s %-12s %s  %s:%d\n", mark, n.ID, n.Name, n.Server, n.Port)
		}
	}
}

// groupIDFor — устойчивый id группы по ссылке подписки.
//
// Устойчивый, а не случайный: см. addSubscription. Берётся хост ссылки плюс
// короткий отпечаток всей ссылки — хост читаем глазом, отпечаток разводит две
// подписки у одного провайдера. Сама ссылка в id не входит: она содержит токен
// (§6.14), а id попадает в имена файлов и в вывод.
func groupIDFor(url string) string {
	sum := sha256.Sum256([]byte(url))
	return "sub-" + hex.EncodeToString(sum[:6])
}

// sortedReasons — порядок причин в выводе, чтобы он не прыгал между запусками.
func sortedReasons(m map[store.UnsupReason]int) []store.UnsupReason {
	out := make([]store.UnsupReason, 0, len(m))
	for r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
