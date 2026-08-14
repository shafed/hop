package store_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/node"
	"github.com/shafed/hop/internal/store"
)

// Узлы здесь собираются литералами, а не разбором ссылки: направление
// store → sub запрещено (§3.4), и ключ слияния стору приносят снаружи.
func nodeWith(name, server, user string) node.Node {
	return node.Node{
		Name:      name,
		MergeKey:  "vless|" + server + "|443|" + user,
		Protocol:  node.VLESS,
		Server:    server,
		Port:      443,
		Transport: node.WS,
		Security:  node.SecTLS,
		UserID:    user,
		Params:    map[string]string{"sni": server},
		Supported: true,
		RawLink:   "vless://" + user + "@" + server + ":443",
	}
}

// TestPermissions — §6.14: каталог 0700, файлы 0600. В узлах лежат ключи
// доступа, и права — единственное, что отделяет их от любого другого процесса
// пользователя.
func TestPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("права POSIX на Windows не выражаются; §6.14 там закрывается ACL инсталлятора")
	}
	dir := filepath.Join(t.TempDir(), "hop")
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.PutGroup(store.Group{ID: "g", Name: "g"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutNode(nodeWith("A", "a.example.com", "user-a")); err != nil {
		t.Fatal(err)
	}
	if err := st.PutHealth(health.NodeHealth{NodeID: "x", State: health.Alive}); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("права каталога %o, ожидались 0700", perm)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files int
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		files++
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("права %s: %o, ожидались 0600", e.Name(), perm)
		}
	}
	if files == 0 {
		t.Fatal("стор не создал ни одного файла — проверять нечего")
	}
}

// TestOpenTightensExistingDir — каталог, оставшийся от прошлой установки с
// мягкими правами, доводится до 0700: §6.14 не зависит от того, кто создал
// каталог.
func TestOpenTightensExistingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("права POSIX на Windows не выражаются")
	}
	dir := filepath.Join(t.TempDir(), "hop")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("права каталога %o, ожидались 0700", perm)
	}
}

// TestReopenKeepsState — стор переживает перезапуск агента: группы, узлы,
// история и порядок узлов читаются обратно.
func TestReopenKeepsState(t *testing.T) {
	dir := t.TempDir()

	// Сырой заголовок Subscription-UserInfo (§2, Group.quota_info) хранится
	// как есть: §7 (вопрос 3) ещё не решил, что с ним делать, и разбирать его
	// сейчас значило бы решить за него.
	const quota = "upload=1024; download=2048; total=107374182400; expire=2147483647"

	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	g := store.Group{
		ID:             "sub1",
		Name:           "провайдер",
		SourceURL:      "https://example.invalid/sub",
		LastUpdatedAt:  time.Unix(1700000000, 0).UTC(),
		QuotaInfo:      quota,
		AutoUpdate:     true,
		UpdateInterval: 6 * time.Hour,
	}
	if err := st.PutGroup(g); err != nil {
		t.Fatal(err)
	}
	diff, err := st.ApplySubscription("sub1", []node.Node{
		nodeWith("A", "a.example.com", "user-a"),
		nodeWith("B", "b.example.com", "user-b"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutHealth(health.NodeHealth{
		NodeID: diff.Added[0], State: health.Alive, RTT: 90 * time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()

	got, ok := again.Group("sub1")
	if !ok {
		t.Fatal("группа не прочиталась")
	}
	if got.QuotaInfo != quota {
		t.Errorf("quota_info = %q, ожидалось %q", got.QuotaInfo, quota)
	}
	if !got.LastUpdatedAt.Equal(g.LastUpdatedAt) || got.UpdateInterval != g.UpdateInterval {
		t.Errorf("метаданные группы разъехались: %+v", got)
	}
	if len(got.NodeOrder) != 2 || got.NodeOrder[0] != diff.Added[0] {
		t.Errorf("node_order=%v, ожидался %v", got.NodeOrder, diff.Added)
	}

	nodes := again.Nodes("sub1")
	if len(nodes) != 2 || nodes[0].Name != "A" || nodes[1].Name != "B" {
		t.Fatalf("узлы прочитались как %+v", nodes)
	}
	if nodes[0].Param("sni") != "a.example.com" || nodes[0].UserID != "user-a" {
		t.Errorf("узел прочитался неполно: %+v", nodes[0])
	}
	h, ok := again.Health(diff.Added[0])
	if !ok || h.RTT != 90*time.Millisecond || h.State != health.Alive {
		t.Errorf("история прочиталась как %+v (ok=%v)", h, ok)
	}
}

// TestPutGroupKeepsNodeOrder — правка метаданных группы не трогает порядок
// узлов: он принадлежит ApplySubscription.
func TestPutGroupKeepsNodeOrder(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.PutGroup(store.Group{ID: "sub1", Name: "было"}); err != nil {
		t.Fatal(err)
	}
	diff, err := st.ApplySubscription("sub1", []node.Node{nodeWith("A", "a.example.com", "user-a")})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutGroup(store.Group{ID: "sub1", Name: "стало", QuotaInfo: "q"}); err != nil {
		t.Fatal(err)
	}
	g, _ := st.Group("sub1")
	if len(g.NodeOrder) != 1 || g.NodeOrder[0] != diff.Added[0] {
		t.Errorf("node_order=%v, ожидался %v", g.NodeOrder, diff.Added)
	}
	if g.Name != "стало" {
		t.Errorf("имя не обновилось: %q", g.Name)
	}
}

// TestApplySubscriptionRejectsEmptyKey — узел без ключа слияния отвергается:
// пустой ключ склеил бы всю подписку в один узел, а посчитать ключ стору
// нечем (§3.4).
func TestApplySubscriptionRejectsEmptyKey(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.PutGroup(store.Group{ID: "sub1"}); err != nil {
		t.Fatal(err)
	}
	n := nodeWith("A", "a.example.com", "user-a")
	n.MergeKey = ""
	if _, err := st.ApplySubscription("sub1", []node.Node{n}); err == nil {
		t.Fatal("узел без ключа слияния принят")
	}
}

// TestPutNodeGoesToManualGroup — `hop node add` (§С2): узел без группы
// попадает в manual и получает id.
func TestPutNodeGoesToManualGroup(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	n, err := st.PutNode(nodeWith("ручной", "m.example.com", "user-m"))
	if err != nil {
		t.Fatal(err)
	}
	if n.ID == "" {
		t.Fatal("узлу не выдан id")
	}
	if n.GroupID != store.ManualGroup {
		t.Errorf("группа %q, ожидалась %q", n.GroupID, store.ManualGroup)
	}
	if nodes := st.Nodes(store.ManualGroup); len(nodes) != 1 || nodes[0].ID != n.ID {
		t.Errorf("в manual %d узлов", len(nodes))
	}
	if all := st.AllNodes(); len(all) != 1 {
		t.Errorf("AllNodes вернул %d узлов", len(all))
	}
}

// TestDeleteGroupRemovesNodesAndHealth — удаление группы уносит её узлы и их
// историю: осиротевшая история копилась бы вечно.
func TestDeleteGroupRemovesNodesAndHealth(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutGroup(store.Group{ID: "sub1"}); err != nil {
		t.Fatal(err)
	}
	diff, err := st.ApplySubscription("sub1", []node.Node{nodeWith("A", "a.example.com", "user-a")})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutHealth(health.NodeHealth{NodeID: diff.Added[0], State: health.Alive}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteGroup("sub1"); err != nil {
		t.Fatal(err)
	}
	st.Close()

	again, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if _, ok := again.Group("sub1"); ok {
		t.Error("группа осталась")
	}
	if _, ok := again.Node(diff.Added[0]); ok {
		t.Error("узел удалённой группы остался")
	}
	if _, ok := again.Health(diff.Added[0]); ok {
		t.Error("история удалённого узла осталась")
	}
}

// TestWriteIsAtomic — временных файлов после записи не остаётся: обрыв на
// середине не должен оставлять стор с половиной подписки.
func TestWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.PutGroup(store.Group{ID: "sub1"}); err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) == ".tmp" {
			t.Errorf("остался временный файл %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
