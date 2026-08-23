// Персистентность стора — docs/verification-store.md §5.4. S* — номера
// регистра. Уровень L1: диск здесь — t.TempDir(), а не привилегия.
package store

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time" //hop:realtime — точка отсчёта фейковых часов, обращения к настоящему времени нет

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/health"
)

// testEpoch — откуда стартуют фейковые часы. Значение произвольно и важно
// только тем, что оно одно на все проверки.
var testEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// newStore открывает стор в собственном временном каталоге.
func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	return openStore(t, dir), dir
}

func openStore(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir, clock.NewFake(testEpoch))
	if err != nil {
		t.Fatalf("стор не открылся: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// seed кладёт группу с узлами прямо в состояние стора, минуя Apply: слияние —
// шаг 5 регистра, а проверяется здесь запись, а не то, что с чем слилось.
func seed(t *testing.T, s *Store, g Group, nodes ...Node) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.groups[g.ID]; !ok {
		s.groupOrder = append(s.groupOrder, g.ID)
	}
	for _, n := range nodes {
		s.nodes[n.ID] = n
		g.NodeOrder = append(g.NodeOrder, n.ID)
	}
	s.groups[g.ID] = g
	s.dirty |= sectionGroups | sectionNodes
}

// addNode правит только состав узлов, не трогая группу: так следующая запись
// касается ровно одного файла, и «прежнее состояние целиком» проверяется
// побайтно.
func addNode(t *testing.T, s *Store, n Node) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[n.ID] = n
	s.dirty |= sectionNodes
}

// putHealth кладёт живость в состояние стора, минуя дебаунс PutHealth: здесь
// проверяется запись, а не то, как часто она случается (шаг 6 — health_test.go).
//
// Обрезка та же, что у PutHealth: в healthByNode по построению лежит срез, а не
// вся NodeHealth (§2), и помощник, который клал бы туда окно, проверял бы стор,
// которого нет.
func putHealth(t *testing.T, s *Store, h health.NodeHealth) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthByNode[h.NodeID] = healthSlice(h)
	s.dirty |= sectionHealth
}

// node — узел с ключом доступа в params: nodes.json секретен целиком именно
// из-за них (Р12).
func node(id, group, server string) Node {
	return Node{
		ID:        id,
		GroupID:   group,
		MergeKey:  "vless|" + server + "|443|uuid",
		Name:      "узел " + id,
		Protocol:  "vless",
		Server:    server,
		Port:      443,
		Transport: "ws",
		Security:  "tls",
		Params:    map[string]string{"uuid": "11111111-1111-1111-1111-111111111111"},
		Supported: true,
		RawLink:   "vless://11111111-1111-1111-1111-111111111111@" + server + ":443",
	}
}

func nodeIDs(nodes []Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	return out
}

func readRaw(t *testing.T, dir, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("не прочитать %s: %v", name, err)
	}
	return raw
}

// TestS27MissingRootIsCreatedWithSpecPermissions — S27: каталога стора нет.
func TestS27MissingRootIsCreatedWithSpecPermissions(t *testing.T) {
	root := filepath.Join(t.TempDir(), "hop")
	s := openStore(t, root)
	if err := s.Flush(); err != nil {
		t.Fatalf("пустой стор не записался: %v", err)
	}

	// Файлы создаются сразу, а не при первой записи: права, которых ещё нет,
	// проверить нельзя, а §6.14 — не про будущее состояние каталога.
	for _, name := range []string{groupsFile, nodesFile, healthFile} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatalf("%s не создан: %v", name, err)
		}
	}

	if runtime.GOOS == "windows" {
		// Права POSIX на Windows не выражаются: os.Chmod там управляет только
		// признаком «только для чтения». Проверять нечего, и падать тоже не за
		// что (§5.4, оговорка S27).
		t.Skip("права POSIX на Windows не проверяются")
	}

	di, err := os.Stat(root)
	if err != nil {
		t.Fatalf("каталог стора не создан: %v", err)
	}
	if got := di.Mode().Perm(); got != dirPerm {
		t.Errorf("права каталога %04o, а §6.14 требует %04o", got, dirPerm)
	}
	for _, f := range files() {
		fi, err := os.Stat(filepath.Join(root, f.name))
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		if got := fi.Mode().Perm(); got != f.perm {
			t.Errorf("права %s %04o, а §2 требует %04o", f.name, got, f.perm)
		}
	}
}

// TestS27ExistingFilesGetSpecPermissions — продолжение S27: стор, доставшийся
// с чужими правами (скопирован, распакован, создан прежней версией), чинится
// при открытии. Иначе nodes.json остался бы читаемым для всех.
func TestS27ExistingFilesGetSpecPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("права POSIX на Windows не проверяются")
	}
	s, dir := newStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))
	if err := s.Flush(); err != nil {
		t.Fatalf("запись не прошла: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("закрытие не прошло: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, nodesFile), 0o644); err != nil {
		t.Fatalf("не испортить права: %v", err)
	}

	openStore(t, dir)

	fi, err := os.Stat(filepath.Join(dir, nodesFile))
	if err != nil {
		t.Fatalf("%s: %v", nodesFile, err)
	}
	if got := fi.Mode().Perm(); got != secretPerm {
		t.Errorf("права %s %04o, а §6.14 требует %04o", nodesFile, got, secretPerm)
	}
}

// TestS29BrokenHealthFileIsNotFatal — S29: health.json испорчен.
func TestS29BrokenHealthFileIsNotFatal(t *testing.T) {
	s, dir := newStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))
	putHealth(t, s, health.NodeHealth{NodeID: "n1", State: health.Alive, RTT: 42 * time.Millisecond, LastProbeAt: testEpoch})
	if err := s.Flush(); err != nil {
		t.Fatalf("запись не прошла: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("закрытие не прошло: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, healthFile), []byte("{это не json"), publicPerm); err != nil {
		t.Fatalf("не испортить файл: %v", err)
	}

	s2 := openStore(t, dir)

	// Живость пуста: восстановит первый же раунд проб (Р13).
	s2.mu.Lock()
	live := len(s2.healthByNode)
	s2.mu.Unlock()
	if live != 0 {
		t.Errorf("живость восстановлена из битого файла: %d записей", live)
	}

	// Узлы и группы при этом прочитаны.
	if got := len(s2.Groups()); got != 1 {
		t.Errorf("групп %d, а битой была только живость", got)
	}
	if _, ok := s2.Node("n1"); !ok {
		t.Error("узел потерян из-за битой живости — цена ошибки перепутана (Р13)")
	}
}

// TestS30BrokenNodesFileFailsOpen — S30: nodes.json испорчен. Громкий отказ, а
// не пустой список: пустой список выглядит как исчезнувшая подписка и
// провоцирует добавить её заново, потеряв всё окончательно (Р13).
func TestS30BrokenNodesFileFailsOpen(t *testing.T) {
	for _, tc := range []struct{ name, file string }{
		{"nodes", nodesFile},
		{"groups", groupsFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, dir := newStore(t)
			seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))
			if err := s.Flush(); err != nil {
				t.Fatalf("запись не прошла: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("закрытие не прошло: %v", err)
			}

			broken := []byte(`{"version": 1, "узлы": обрубок`)
			if err := os.WriteFile(filepath.Join(dir, tc.file), broken, publicPerm); err != nil {
				t.Fatalf("не испортить файл: %v", err)
			}

			s2, err := Open(dir, clock.NewFake(testEpoch))
			if err == nil {
				_ = s2.Close()
				t.Fatalf("стор открылся с битым %s — отказ обязан быть громким", tc.file)
			}
			if !strings.Contains(err.Error(), tc.file) {
				t.Errorf("в ошибке нет имени файла, чинить нечего: %v", err)
			}

			// Битый файл не тронут: перезаписав его пустым, стор уничтожил бы
			// последнее, из чего пользователь мог бы его восстановить.
			if got := readRaw(t, dir, tc.file); string(got) != string(broken) {
				t.Errorf("битый %s перезаписан при отказе старта", tc.file)
			}
		})
	}
}

// TestOpenRestoresGroupsNodesAndHealth — то, на чём стоят шаги 5 и 6: запись и
// чтение сходятся.
func TestOpenRestoresGroupsNodesAndHealth(t *testing.T) {
	s, dir := newStore(t)
	g := Group{
		ID:                 "g",
		Name:               "подписка",
		SourceURL:          "https://example.invalid/sub",
		LastUpdatedAt:      testEpoch,
		QuotaInfo:          "upload=1; download=2",
		AutoUpdate:         true,
		AutoUpdateInterval: 6 * time.Hour,
	}
	seed(t, s, g, node("n1", "g", "a.example"), node("n2", "g", "b.example"))
	putHealth(t, s, health.NodeHealth{
		NodeID:      "n1",
		State:       health.Alive,
		RTT:         42 * time.Millisecond,
		Window:      []health.Outcome{health.OK, health.OK},
		LastProbeAt: testEpoch,
	})
	if err := s.Flush(); err != nil {
		t.Fatalf("запись не прошла: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("закрытие не прошло: %v", err)
	}

	s2 := openStore(t, dir)

	groups := s2.Groups()
	if len(groups) != 1 {
		t.Fatalf("групп %d, ожидалась одна", len(groups))
	}
	got := groups[0]
	if got.ID != g.ID || got.Name != g.Name || got.SourceURL != g.SourceURL ||
		got.QuotaInfo != g.QuotaInfo || got.AutoUpdate != g.AutoUpdate ||
		got.AutoUpdateInterval != g.AutoUpdateInterval || !got.LastUpdatedAt.Equal(g.LastUpdatedAt) {
		t.Errorf("группа восстановлена иначе: %+v", got)
	}

	n, ok := s2.Node("n1")
	if !ok {
		t.Fatal("узел n1 не восстановлен")
	}
	if n.Param("uuid") != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("params потеряны: %+v", n.Params)
	}
	if n.MergeKey == "" {
		t.Error("merge_key не восстановлен, а он хранимое поле (§2)")
	}

	// Срез живости переживает рестарт, окно — нет (§2). Дебаунс и флаг
	// health_slice — шаг 6 регистра.
	s2.mu.Lock()
	h := s2.healthByNode["n1"]
	s2.mu.Unlock()
	if h.State != health.Alive || h.RTT != 42*time.Millisecond {
		t.Errorf("срез живости восстановлен иначе: %+v", h)
	}
	if len(h.Window) != 0 {
		t.Errorf("окно восстановлено, хотя после паузы оно врёт (§2): %v", h.Window)
	}
}

// TestNodesFollowNodeOrder — Nodes отдаёт группу в порядке node_order (Р8):
// при равных rtt выигрывает первый по порядку (§6.4), поэтому порядок —
// наблюдаемое, а не деталь хранения.
func TestNodesFollowNodeOrder(t *testing.T) {
	s, dir := newStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"},
		node("n1", "g", "a.example"), node("n2", "g", "b.example"), node("n3", "g", "c.example"))

	s.mu.Lock()
	g := s.groups["g"]
	g.NodeOrder = []string{"n3", "n1", "n2"}
	s.groups["g"] = g
	s.mu.Unlock()

	if err := s.Flush(); err != nil {
		t.Fatalf("запись не прошла: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("закрытие не прошло: %v", err)
	}

	s2 := openStore(t, dir)
	if got := nodeIDs(s2.Nodes("g")); !slices.Equal(got, []string{"n3", "n1", "n2"}) {
		t.Errorf("порядок узлов %v, а node_order задавал n3, n1, n2", got)
	}
	if got := s2.Nodes("нет такой группы"); len(got) != 0 {
		t.Errorf("узлы несуществующей группы: %v", nodeIDs(got))
	}
}

// TestNodesAreCopies — отданный узел не разделяет карту params со стором:
// иначе граница держалась бы на договорённости не писать в чужое.
func TestNodesAreCopies(t *testing.T) {
	s, _ := newStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))

	n, ok := s.Node("n1")
	if !ok {
		t.Fatal("узел не найден")
	}
	n.Params["uuid"] = "подменён"

	again, _ := s.Node("n1")
	if again.Param("uuid") == "подменён" {
		t.Error("правка отданной копии изменила стор")
	}
}
