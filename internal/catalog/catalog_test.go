package catalog

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/store"
)

const subBody = "vless://11111111-1111-1111-1111-111111111111@a.example:443?type=ws&security=tls#Токио\n" +
	"tuic://22222222-2222-2222-2222-222222222222@b.example:443#Осака\n"

func newCatalog(t *testing.T, fetch Fetch) *Catalog {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("стор: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, clock.NewFake(time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)), fetch)
}

func fixedFetch(body string) Fetch {
	return func(context.Context, string) ([]byte, string, error) { return []byte(body), "", nil }
}

// §С2: скачать, разобрать, создать группу, показать сводку. Сводка — не
// украшение вывода, а наблюдаемый результат diff-слияния (§5.8), поэтому её
// считает агент, а не тот, кто печатает.
func TestSubAddSummarisesSubscription(t *testing.T) {
	c := newCatalog(t, fixedFetch(subBody))

	got, err := c.SubAdd(context.Background(), "https://sub.example/list", "")
	if err != nil {
		t.Fatalf("SubAdd: %v", err)
	}
	if got.GroupID != "ee8e3a30" || got.GroupName != "sub.example" {
		t.Fatalf("группа %s/%s, ожидалась ee8e3a30/sub.example", got.GroupID, got.GroupName)
	}
	if got.Added != 2 || got.Kept != 0 || got.Removed != 0 || got.Unsupported != 1 {
		t.Fatalf("сводка %+v: ожидалось добавлено 2, не поддержано 1", got)
	}

	// Тот же адрес второй раз — не вторая группа, а обновление: id считается от
	// адреса, и история проб переживает его (§5.8).
	again, err := c.SubAdd(context.Background(), "https://sub.example/list", "")
	if err != nil {
		t.Fatalf("повторный SubAdd: %v", err)
	}
	if again.Added != 0 || again.Kept != 2 {
		t.Fatalf("повторный SubAdd: %+v, ожидалось добавлено 0, сохранено 2", again)
	}
	if list := c.SubList(); len(list) != 1 {
		t.Fatalf("подписок %d, ожидалась одна: %+v", len(list), list)
	}
}

// Недоступная подписка не оставляет после себя пустую группу: иначе опечатка в
// адресе навсегда поселяется в `sub list`.
func TestSubAddKeepsNothingOnFetchError(t *testing.T) {
	c := newCatalog(t, func(context.Context, string) ([]byte, string, error) {
		return nil, "", errors.New("сеть недоступна")
	})

	if _, err := c.SubAdd(context.Background(), "https://sub.example/list", ""); err == nil {
		t.Fatal("SubAdd с недоступным адресом обязан быть ошибкой")
	}
	if list := c.SubList(); len(list) != 0 {
		t.Fatalf("в сторе осталась группа: %+v", list)
	}
}

// `hop sub list` показывает состав: сколько узлов в группе и когда обновлялась.
func TestSubListCountsNodes(t *testing.T) {
	c := newCatalog(t, fixedFetch(subBody))
	if _, err := c.SubAdd(context.Background(), "https://sub.example/list", "мои"); err != nil {
		t.Fatalf("SubAdd: %v", err)
	}

	list := c.SubList()
	if len(list) != 1 {
		t.Fatalf("подписок %d, ожидалась одна", len(list))
	}
	g := list[0]
	if g.Name != "мои" || g.Nodes != 2 || g.SourceURL != "https://sub.example/list" {
		t.Fatalf("подписка %+v", g)
	}
	if g.UpdatedAt.IsZero() {
		t.Fatal("время обновления не проставлено: часы агента до стора не доехали")
	}
}

// Обновление без аргумента берёт все подписки с источником; ручная группа
// источника не имеет и обновлению не подлежит.
func TestSubUpdateWalksEverySubscription(t *testing.T) {
	c := newCatalog(t, fixedFetch(subBody))
	if _, err := c.SubAdd(context.Background(), "https://one.example/list", ""); err != nil {
		t.Fatalf("SubAdd: %v", err)
	}
	if _, err := c.SubAdd(context.Background(), "https://two.example/list", ""); err != nil {
		t.Fatalf("SubAdd: %v", err)
	}
	if _, err := c.NodeAdd("vless://33333333-3333-3333-3333-333333333333@c.example:443?security=tls#Прага"); err != nil {
		t.Fatalf("NodeAdd: %v", err)
	}

	res, err := c.SubUpdate(context.Background(), "")
	if err != nil {
		t.Fatalf("SubUpdate: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("обновлено подписок %d, ожидалось две: %+v", len(res), res)
	}

	// Обновлять нечего — это ошибка, а не молчаливый успех: пользователь просил
	// действие, которого не случилось.
	empty := newCatalog(t, fixedFetch(subBody))
	if _, err := empty.SubUpdate(context.Background(), ""); err == nil {
		t.Fatal("SubUpdate без подписок обязан быть ошибкой")
	}
	if _, err := c.SubUpdate(context.Background(), "нет-такой"); err == nil {
		t.Fatal("SubUpdate несуществующей подписки обязан быть ошибкой")
	}
}

func TestSubRemoveDropsGroup(t *testing.T) {
	c := newCatalog(t, fixedFetch(subBody))
	got, err := c.SubAdd(context.Background(), "https://sub.example/list", "")
	if err != nil {
		t.Fatalf("SubAdd: %v", err)
	}
	if err := c.SubRemove(got.GroupID); err != nil {
		t.Fatalf("SubRemove: %v", err)
	}
	if list := c.SubList(); len(list) != 0 {
		t.Fatalf("подписка пережила удаление: %+v", list)
	}
	if nodes := c.Nodes(); len(nodes) != 0 {
		t.Fatalf("узлы пережили удаление подписки: %+v", nodes)
	}
}

// §С2: ссылка на отдельный узел уезжает в группу manual.
func TestNodeAddAndRemove(t *testing.T) {
	c := newCatalog(t, fixedFetch(subBody))
	n, err := c.NodeAdd("vless://33333333-3333-3333-3333-333333333333@c.example:443?security=tls#Прага")
	if err != nil {
		t.Fatalf("NodeAdd: %v", err)
	}
	if n.Group != store.ManualGroup || n.Name != "Прага" || !n.Supported {
		t.Fatalf("узел %+v", n)
	}

	from, err := c.NodeRemove(n.ID)
	if err != nil {
		t.Fatalf("NodeRemove: %v", err)
	}
	// Ручной узел ниоткуда не вернётся, и предупреждать не о чем.
	if from != "" {
		t.Fatalf("ручной узел приписан подписке %q", from)
	}
	if nodes := c.Nodes(); len(nodes) != 0 {
		t.Fatalf("узел пережил удаление: %+v", nodes)
	}
	if _, err := c.NodeRemove(n.ID); err == nil {
		t.Fatal("удаление несуществующего узла обязано быть ошибкой")
	}
}

// Узел из подписки удаляется, но вернётся при следующем обновлении — про это
// надо предупредить, иначе удаление выглядит несработавшим.
func TestNodeRemoveNamesSubscriptionItCameFrom(t *testing.T) {
	c := newCatalog(t, fixedFetch(subBody))
	res, err := c.SubAdd(context.Background(), "https://sub.example/list", "")
	if err != nil {
		t.Fatalf("SubAdd: %v", err)
	}

	var target string
	for _, n := range c.Nodes() {
		if n.Name == "Токио" {
			target = n.ID
		}
	}
	if target == "" {
		t.Fatalf("узел Токио не найден: %+v", c.Nodes())
	}

	from, err := c.NodeRemove(target)
	if err != nil {
		t.Fatalf("NodeRemove: %v", err)
	}
	if from != res.GroupID {
		t.Fatalf("удалённый узел приписан %q, а пришёл из %q", from, res.GroupID)
	}
}

// Неподдержанный узел (§6.11) виден в списке, но помечен: иначе пользователь не
// поймёт, почему в подписке узлов больше, чем в выборе.
func TestNodesShowUnsupported(t *testing.T) {
	c := newCatalog(t, fixedFetch(subBody))
	if _, err := c.SubAdd(context.Background(), "https://sub.example/list", ""); err != nil {
		t.Fatalf("SubAdd: %v", err)
	}
	var names []string
	for _, n := range c.Nodes() {
		if !n.Supported {
			names = append(names, n.Name)
		}
	}
	if strings.Join(names, ",") != "Осака" {
		t.Fatalf("неподдержанными оказались %v, ожидалась одна Осака", names)
	}
}
