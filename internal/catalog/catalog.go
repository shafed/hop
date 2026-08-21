// Package catalog — состав узлов агента: подписки (§5.8) и отдельные узлы (§С2).
//
// Живёт на стороне агента, а не клиента. §3.3 требует, чтобы вся логика и весь
// стор были в агенте, и клиент не открывал стор даже на чтение; с системным
// пользователем `hop` (§6.8) это перестало быть вопросом стиля — под своим UID
// клиент до каталога агента попросту не достаёт.
//
// Прежде эти шесть операций делал процесс CLI (отклонение C12), и оправдание у
// него было одно: `hop sub add` обязан работать до первого `hop up`, то есть
// когда агента ещё нет. Оправдание отпало вместе с §6.13 — агент стартует при
// старте ОС и логина не ждёт.
//
// Типы ответов взяты из `events`: это то, что уедет клиенту, и вторая пара
// структур ради чистоты слоя добавила бы только перекладывание полей.
package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/events"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/node"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/sub"
)

// Fetch — загрузка подписки. Шов существует затем, чтобы приёмка §1
// проверялась без сети (§8.1).
type Fetch func(ctx context.Context, url string) (body []byte, quota string, err error)

// Catalog — стор агента вместе с тем, что умеет его менять.
type Catalog struct {
	st    *store.Store
	clk   clock.Clock
	fetch Fetch
}

// New связывает каталог со стором. Часы инъектируются: §8 запрещает настоящее
// время в продуктовом коде вне internal/clock.
func New(st *store.Store, clk clock.Clock, fetch Fetch) *Catalog {
	if fetch == nil {
		fetch = sub.Fetch
	}
	return &Catalog{st: st, clk: clk, fetch: fetch}
}

// SubAdd — §С2: скачать, разобрать, создать группу, вернуть сводку.
//
// Повторный add того же адреса не плодит вторую группу: id считается от адреса,
// и подписка обновляется на месте вместе с историей проб (§5.8).
func (c *Catalog) SubAdd(ctx context.Context, src, name string) (events.SubResult, error) {
	if src == "" {
		return events.SubResult{}, errors.New("нужен адрес подписки")
	}
	g, ok := c.st.Group(groupID(src))
	if !ok {
		g = store.Group{ID: groupID(src)}
	}
	g.SourceURL = src
	switch {
	case name != "":
		g.Name = name
	case g.Name == "":
		g.Name = hostOf(src)
	}
	// Группа доезжает до стора только вместе с узлами (это делает apply):
	// иначе опечатка в адресе оставляла бы в списке пустую подписку.
	return c.apply(ctx, g)
}

// SubUpdate — §С8 и `hop sub update`. Без id обновляются все подписки:
// типичный пользователь держит две-три ради отказоустойчивости (§5.8).
func (c *Catalog) SubUpdate(ctx context.Context, id string) ([]events.SubResult, error) {
	var groups []store.Group
	if id != "" {
		g, ok := c.st.Group(id)
		if !ok {
			return nil, fmt.Errorf("подписка %q не найдена", id)
		}
		if g.SourceURL == "" {
			return nil, fmt.Errorf("у группы %s нет источника: это ручные узлы", g.ID)
		}
		groups = []store.Group{g}
	} else {
		for _, g := range c.st.Groups() {
			if g.SourceURL != "" {
				groups = append(groups, g)
			}
		}
	}
	if len(groups) == 0 {
		return nil, errors.New("обновлять нечего: подписок нет")
	}

	out := make([]events.SubResult, 0, len(groups))
	for _, g := range groups {
		res, err := c.apply(ctx, g)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// SubRemove удаляет подписку вместе с её узлами.
func (c *Catalog) SubRemove(id string) error {
	if id == "" {
		return errors.New("нужен id подписки")
	}
	return c.st.DeleteGroup(id)
}

// SubList — состав подписок для `hop sub list`.
func (c *Catalog) SubList() []events.GroupInfo {
	groups := c.st.Groups()
	out := make([]events.GroupInfo, 0, len(groups))
	for _, g := range groups {
		out = append(out, events.GroupInfo{
			ID:        g.ID,
			Name:      g.Name,
			Nodes:     len(c.st.Nodes(g.ID)),
			UpdatedAt: g.LastUpdatedAt,
			SourceURL: g.SourceURL,
		})
	}
	return out
}

// NodeAdd — §С2: ссылка на отдельный узел попадает в группу manual.
func (c *Catalog) NodeAdd(link string) (events.NodeInfo, error) {
	if link == "" {
		return events.NodeInfo{}, errors.New("нужна ссылка на узел")
	}
	n, err := sub.ParseLink(link)
	if err != nil {
		return events.NodeInfo{}, err
	}
	n.GroupID = store.ManualGroup
	n.MergeKey = sub.MergeKey(n)

	n, err = c.st.PutNode(n)
	if err != nil {
		return events.NodeInfo{}, err
	}
	return info(n), nil
}

// NodeRemove удаляет узел и называет подписку, из которой тот пришёл: узел из
// подписки вернётся при следующем обновлении, и молчать об этом нельзя —
// удаление выглядело бы несработавшим. Для ручного узла имя пусто.
//
// Стор умеет удалять группу целиком и сливать в неё состав, но не умеет удалять
// узел поштучно, поэтому удаление выражено слиянием оставшегося состава: узлы,
// пережившие его, сохраняют id и историю проб (§5.8) — ровно то же свойство, на
// котором стоит обновление подписки.
func (c *Catalog) NodeRemove(id string) (string, error) {
	if id == "" {
		return "", errors.New("нужен id узла")
	}
	target, ok := c.st.Node(id)
	if !ok {
		return "", fmt.Errorf("узел %q не найден", id)
	}
	var rest []node.Node
	for _, n := range c.st.Nodes(target.GroupID) {
		if n.ID == id {
			continue
		}
		if n.MergeKey == "" {
			n.MergeKey = sub.MergeKey(n)
		}
		rest = append(rest, n)
	}
	if _, err := c.st.ApplySubscription(target.GroupID, rest); err != nil {
		return "", err
	}
	if g, ok := c.st.Group(target.GroupID); ok && g.SourceURL != "" {
		return g.ID, nil
	}
	return "", nil
}

// Nodes — весь состав стора без всякой живости. Им пользуется и `hop nodes`,
// и сам агент, который накладывает на этот список текущее здоровье.
func (c *Catalog) Nodes() []events.NodeInfo {
	all := c.st.AllNodes()
	out := make([]events.NodeInfo, 0, len(all))
	for _, n := range all {
		out = append(out, info(n))
	}
	return out
}

// apply — общий путь add и update: загрузка, разбор, diff-слияние (§5.8).
func (c *Catalog) apply(ctx context.Context, g store.Group) (events.SubResult, error) {
	body, quota, err := c.fetch(ctx, g.SourceURL)
	if err != nil {
		return events.SubResult{}, err
	}
	parsed, perr := sub.ParseSubscription(body, g.ID)
	if len(parsed) == 0 {
		if perr != nil {
			return events.SubResult{}, perr
		}
		return events.SubResult{}, fmt.Errorf("подписка %s: узлов нет", g.ID)
	}

	g.QuotaInfo = quota
	g.LastUpdatedAt = c.clk.Now()
	if err := c.st.PutGroup(g); err != nil {
		return events.SubResult{}, err
	}
	diff, err := c.st.ApplySubscription(g.ID, parsed)
	if err != nil {
		return events.SubResult{}, err
	}

	res := events.SubResult{
		GroupID:   g.ID,
		GroupName: g.Name,
		Added:     len(diff.Added),
		Kept:      len(diff.Kept),
		Removed:   len(diff.Removed),
	}
	for _, n := range parsed {
		if !n.Supported {
			res.Unsupported++
		}
	}
	if perr != nil {
		res.Warning = perr.Error()
	}
	return res, nil
}

// info — узел стора в том виде, в каком его видит клиент. Ключей здесь нет и
// быть не может (§6.14): клиент называет id, всё остальное знает агент.
func info(n node.Node) events.NodeInfo {
	return events.NodeInfo{
		ID:        n.ID,
		Name:      nodeName(n),
		Group:     n.GroupID,
		State:     health.Untested,
		Supported: n.Supported,
	}
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
