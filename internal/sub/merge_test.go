package sub_test

import (
	"fmt"
	"strings"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/node"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/sub"
)

// Слияние проверяется на настоящем сторе: ключ считает sub, а сохраняет id и
// историю store, и утверждение T18 живёт ровно на стыке. Импорт store из
// внешнего тест-пакета цикла не создаёт (обратной зависимости нет).

const groupID = "sub1"

// TestT18MergeKeepsHistoryOnSNIChange — T18 (§8.2): узел остался, но сменился
// SNI. id и история проб те же.
//
// Развилка политики merge_key стоит в sub.MergeKey: при HOP_DISABLE=merge_key
// ключ становится полным отпечатком, смена SNI делает узел новым, и история
// обнуляется — тест краснеет.
func TestT18MergeKeepsHistoryOnSNIChange(t *testing.T) {
	st := openStore(t)

	const link = "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443" +
		"?type=ws&security=tls&host=cdn.example.com&sni=%s#%s"

	first := apply(t, st, fmt.Sprintf(link, "old.example.com", "Токио"))
	if len(first.Added) != 1 {
		t.Fatalf("первая подписка: добавлено %d узлов, ожидался 1", len(first.Added))
	}
	id := first.Added[0]

	// История, которую обновление обязано пережить.
	want := health.NodeHealth{
		NodeID:      id,
		State:       health.Alive,
		RTT:         120 * time.Millisecond,
		Window:      []health.Outcome{health.OK, health.OK, health.OK},
		LastProbeAt: time.Unix(1700000000, 0).UTC(),
	}
	if err := st.PutHealth(want); err != nil {
		t.Fatal(err)
	}

	// Провайдер поменял SNI и имя — косметика на том же сервере.
	second := apply(t, st, fmt.Sprintf(link, "new.example.com", "Токио-2"))
	if len(second.Added) != 0 || len(second.Removed) != 0 {
		t.Fatalf("смена sni дала added=%v removed=%v, ожидалось пусто", second.Added, second.Removed)
	}
	if len(second.Kept) != 1 || second.Kept[0] != id {
		t.Fatalf("kept=%v, ожидался прежний id %s", second.Kept, id)
	}

	n, ok := st.Node(id)
	if !ok {
		t.Fatalf("узел %s исчез после обновления", id)
	}
	if got := n.Param("sni"); got != "new.example.com" {
		t.Errorf("sni не обновился: %q", got)
	}
	if n.Name != "Токио-2" {
		t.Errorf("имя не обновилось: %q", n.Name)
	}

	got, ok := st.Health(id)
	if !ok {
		t.Fatal("история проб пропала при смене sni")
	}
	if got.State != want.State || got.RTT != want.RTT || len(got.Window) != len(want.Window) {
		t.Errorf("история изменилась: %+v, было %+v", got, want)
	}
}

// TestT19RemovedNodeIsDeleted — T19 (§8.2): узел исчез из подписки. Он удалён
// вместе с историей, порядок группы обновлён, соседи целы.
//
// Переизбрание активного узла — часть health.Selector (§6.4): здесь
// проверяется то, из чего оно исходит, — что узла и его истории в сторе
// больше нет, а Diff.Removed его назвал.
func TestT19RemovedNodeIsDeleted(t *testing.T) {
	st := openStore(t)

	const (
		a = "vless://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa@a.example.com:443?security=tls#A"
		b = "vless://bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb@b.example.com:443?security=tls#B"
	)

	first := apply(t, st, a, b)
	if len(first.Added) != 2 {
		t.Fatalf("добавлено %d узлов, ожидалось 2", len(first.Added))
	}
	idA, idB := first.Added[0], first.Added[1]
	for _, id := range first.Added {
		if err := st.PutHealth(health.NodeHealth{NodeID: id, State: health.Alive}); err != nil {
			t.Fatal(err)
		}
	}

	second := apply(t, st, b)
	if len(second.Removed) != 1 || second.Removed[0] != idA {
		t.Fatalf("removed=%v, ожидался %s", second.Removed, idA)
	}
	if len(second.Kept) != 1 || second.Kept[0] != idB {
		t.Fatalf("kept=%v, ожидался %s", second.Kept, idB)
	}
	if _, ok := st.Node(idA); ok {
		t.Error("исчезнувший из подписки узел остался в сторе")
	}
	if _, ok := st.Health(idA); ok {
		t.Error("история исчезнувшего узла осталась в сторе")
	}
	if _, ok := st.Health(idB); !ok {
		t.Error("история уцелевшего узла пропала")
	}

	g, _ := st.Group(groupID)
	if len(g.NodeOrder) != 1 || g.NodeOrder[0] != idB {
		t.Errorf("node_order=%v, ожидался [%s]", g.NodeOrder, idB)
	}
	if nodes := st.Nodes(groupID); len(nodes) != 1 || nodes[0].ID != idB {
		t.Errorf("в группе %d узлов, ожидался один — %s", len(nodes), idB)
	}
}

// TestMergeKeyDistinguishesUserID — §6.16: ключ только по адресу склеил бы
// узлы, различающиеся ключом доступа. Два узла на одном сервере и порту с
// разными user_id обязаны остаться двумя и после обновления.
func TestMergeKeyDistinguishesUserID(t *testing.T) {
	st := openStore(t)

	const (
		one = "vless://11111111-1111-1111-1111-111111111111@shared.example.com:443?security=tls#Первый"
		two = "vless://22222222-2222-2222-2222-222222222222@shared.example.com:443?security=tls#Второй"
	)

	n1, err := sub.ParseLink(one)
	if err != nil {
		t.Fatal(err)
	}
	n2, err := sub.ParseLink(two)
	if err != nil {
		t.Fatal(err)
	}
	if sub.MergeKey(n1) == sub.MergeKey(n2) {
		t.Fatalf("ключи совпали: %s", sub.MergeKey(n1))
	}

	first := apply(t, st, one, two)
	if len(first.Added) != 2 {
		t.Fatalf("добавлено %d узлов, ожидалось 2", len(first.Added))
	}
	second := apply(t, st, one, two)
	if len(second.Kept) != 2 || len(second.Added) != 0 || len(second.Removed) != 0 {
		t.Fatalf("повторная подписка: kept=%v added=%v removed=%v",
			second.Kept, second.Added, second.Removed)
	}

	users := map[string]bool{}
	for _, n := range st.Nodes(groupID) {
		users[n.UserID] = true
	}
	if len(users) != 2 {
		t.Errorf("в сторе %d различных user_id, ожидалось 2", len(users))
	}
}

// TestMergeKeySurvivesTransportChange — §6.16: смена транспорта на том же
// сервере — тот же узел.
func TestMergeKeySurvivesTransportChange(t *testing.T) {
	st := openStore(t)

	first := apply(t, st,
		"vless://cccccccc-cccc-cccc-cccc-cccccccccccc@c.example.com:443?type=ws&security=tls#C")
	second := apply(t, st,
		"vless://cccccccc-cccc-cccc-cccc-cccccccccccc@c.example.com:443?type=grpc&security=tls&serviceName=g#C")

	if len(second.Kept) != 1 || second.Kept[0] != first.Added[0] {
		t.Fatalf("смена транспорта завела новый узел: kept=%v added=%v", second.Kept, second.Added)
	}
	n, _ := st.Node(first.Added[0])
	if n.Transport != node.GRPC {
		t.Errorf("транспорт не обновился: %q", n.Transport)
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.PutGroup(store.Group{
		ID:        groupID,
		Name:      "провайдер",
		SourceURL: "https://example.invalid/sub",
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

// apply разбирает ссылки как тело подписки и сливает их в группу.
func apply(t *testing.T, st *store.Store, links ...string) store.Diff {
	t.Helper()
	nodes, err := sub.ParseSubscription([]byte(strings.Join(links, "\n")), groupID)
	if err != nil {
		t.Fatalf("разбор подписки: %v", err)
	}
	diff, err := st.ApplySubscription(groupID, nodes)
	if err != nil {
		t.Fatalf("слияние: %v", err)
	}
	return diff
}
