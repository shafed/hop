// Запись состава группы — docs/verification-store.md §5.1, шаг 5 регистра.
// T18, T19 — номера из §8.3 спеки, S8 — из регистра. Уровень L1: диск здесь —
// t.TempDir(), а не привилегия.
package store

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time" //hop:realtime — длительности и метки фейковых часов, обращений к настоящему времени нет

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/health"
)

// composition — состав группы, каким его приносит слияние: узлы, порядок и
// списки id. Собирается руками, потому что store про слияние не знает ничего —
// ему приносят готовое (docs/verification-store.md §2).
func composition(nodes ...Node) Merged {
	m := Merged{Nodes: nodes, Unsupported: map[UnsupReason]int{}}
	for _, n := range nodes {
		m.Order = append(m.Order, n.ID)
		m.Kept = append(m.Kept, n.ID)
	}
	return m
}

func mustApply(t *testing.T, s *Store, groupID string, m Merged) {
	t.Helper()
	if err := s.Apply(groupID, m); err != nil {
		t.Fatalf("состав группы %q не применился: %v", groupID, err)
	}
}

// TestT18HistorySurvivesUpdate — T18, вторая половина: узел остался, сменился
// SNI — история проб цела. Первую половину (тот же id при смене SNI) закрыл
// Diff, здесь проверяется, что запись состава её не стирает.
func TestT18HistorySurvivesUpdate(t *testing.T) {
	s, dir := newStore(t)

	before := composition(node("n1", "g", "a.example"), node("n2", "g", "b.example"))
	mustApply(t, s, "g", before)
	putHealth(t, s, health.NodeHealth{
		NodeID:      "n1",
		State:       health.Alive,
		RTT:         42 * time.Millisecond,
		LastProbeAt: testEpoch,
	})
	if err := s.Flush(); err != nil {
		t.Fatalf("запись не прошла: %v", err)
	}

	// Обновление подписки: у узла сменился SNI и имя, id тот же — то самое
	// «косметическая правка у провайдера не наблюдаема изнутри» (§5.8, §6.16).
	updated := node("n1", "g", "a.example")
	updated.Params["sni"] = "new.example"
	updated.Name = "узел n1 после правки"
	mustApply(t, s, "g", composition(updated, node("n2", "g", "b.example")))

	s.mu.Lock()
	h := s.healthByNode["n1"]
	s.mu.Unlock()
	if h.State != health.Alive || h.RTT != 42*time.Millisecond || !h.LastProbeAt.Equal(testEpoch) {
		t.Errorf("история проб выжившего узла изменилась: %+v", h)
	}

	// И переживает рестарт: живость, стёртая только в памяти, отличалась бы от
	// стёртой на диске лишь до первого перезапуска.
	if err := s.Close(); err != nil {
		t.Fatalf("закрытие не прошло: %v", err)
	}
	s2 := openStore(t, dir)

	s2.mu.Lock()
	h2 := s2.healthByNode["n1"]
	s2.mu.Unlock()
	if h2.State != health.Alive || h2.RTT != 42*time.Millisecond {
		t.Errorf("история проб не пережила рестарт: %+v", h2)
	}

	n, ok := s2.Node("n1")
	if !ok {
		t.Fatal("узел n1 потерян обновлением")
	}
	if n.Param("sni") != "new.example" || n.Name != "узел n1 после правки" {
		t.Errorf("правка провайдера не доехала до стора: %+v", n)
	}
}

// TestT19RemovedNodeIsDeletedWithItsHealth — T19: узел исчез из подписки.
//
// Вторая половина строки регистра («активный переизбран, если это был он») —
// шов со связкой агента (этап 8): ни слияние, ни стор событий переключения не
// порождают, переизбрание живёт в internal/health. Здесь проверяется то, за что
// отвечает стор: узла нет, живости его нет, соседи целы.
func TestT19RemovedNodeIsDeletedWithItsHealth(t *testing.T) {
	s, dir := newStore(t)

	mustApply(t, s, "g", composition(node("n1", "g", "a.example"), node("n2", "g", "b.example")))
	putHealth(t, s, health.NodeHealth{NodeID: "n1", State: health.Alive, RTT: 10 * time.Millisecond, LastProbeAt: testEpoch})
	putHealth(t, s, health.NodeHealth{NodeID: "n2", State: health.Dead, LastProbeAt: testEpoch})
	if err := s.Flush(); err != nil {
		t.Fatalf("запись не прошла: %v", err)
	}

	// Провайдер убрал n2.
	gone := composition(node("n1", "g", "a.example"))
	gone.Removed = []string{"n2"}
	mustApply(t, s, "g", gone)

	if _, ok := s.Node("n2"); ok {
		t.Error("исчезнувший из подписки узел остался в сторе (§1/С8)")
	}
	if got := nodeIDs(s.Nodes("g")); !slices.Equal(got, []string{"n1"}) {
		t.Errorf("состав группы %v, ожидался один n1", got)
	}

	// Живость мёртвого id — мусор, который переживёт рестарт и однажды
	// приклеится к чужому узлу: id новых узлов выдаются заново.
	s.mu.Lock()
	_, stale := s.healthByNode["n2"]
	s.mu.Unlock()
	if stale {
		t.Error("живость удалённого узла осталась в памяти")
	}

	if err := s.Close(); err != nil {
		t.Fatalf("закрытие не прошло: %v", err)
	}
	s2 := openStore(t, dir)

	s2.mu.Lock()
	_, revived := s2.healthByNode["n2"]
	alive := s2.healthByNode["n1"]
	s2.mu.Unlock()
	if revived {
		t.Error("живость удалённого узла вернулась с диска — удаление шло только в памяти")
	}
	if alive.State != health.Alive || alive.RTT != 10*time.Millisecond {
		t.Errorf("удаление соседа задело историю выжившего: %+v", alive)
	}
	if _, ok := s2.Node("n2"); ok {
		t.Error("удалённый узел вернулся с диска")
	}
}

// TestS8UnchangedUpdateDoesNotRewriteHealth — S8, вторая половина: повторное
// обновление без изменений не переписывает health.json. Первую половину («Added
// и Removed пусты») закрыл Diff.
//
// Наблюдается счётчиком записей слоя, а не временем модификации файла: у mtime
// разрешение файловой системы, и два соседних обновления по нему неотличимы.
func TestS8UnchangedUpdateDoesNotRewriteHealth(t *testing.T) {
	s, _ := newStore(t)

	same := func() Merged {
		return composition(node("n1", "g", "a.example"), node("n2", "g", "b.example"))
	}
	mustApply(t, s, "g", same())
	putHealth(t, s, health.NodeHealth{NodeID: "n1", State: health.Alive, RTT: 42 * time.Millisecond, LastProbeAt: testEpoch})
	if err := s.Flush(); err != nil {
		t.Fatalf("запись не прошла: %v", err)
	}

	healthWrites := s.w.writes(healthFile)
	nodeWrites := s.w.writes(nodesFile)
	if healthWrites == 0 || nodeWrites == 0 {
		t.Fatalf("счётчик записей не считает (health %d, nodes %d): проверка была бы пустой", healthWrites, nodeWrites)
	}

	// Та же подписка второй раз: состав тот же, порядок тот же.
	mustApply(t, s, "g", same())

	if got := s.w.writes(healthFile); got != healthWrites {
		t.Errorf("health.json переписан %d раз вместо %d: обновление без изменений трогает живость", got, healthWrites)
	}
	if got := s.w.writes(nodesFile); got != nodeWrites {
		t.Errorf("nodes.json переписан %d раз вместо %d: состав не менялся", got, nodeWrites)
	}
	// groups.json переписывается законно: отметка времени группы меняется даже
	// тогда, когда состав не изменился, — обновление всё же состоялось.
	if got := s.w.writes(groupsFile); got == 0 {
		t.Error("groups.json не записан ни разу: отметка времени обновления не сохраняется")
	}

	// Живость на месте, а не «не переписана, потому что потеряна».
	s.mu.Lock()
	h := s.healthByNode["n1"]
	s.mu.Unlock()
	if h.RTT != 42*time.Millisecond {
		t.Errorf("живость изменилась: %+v", h)
	}
}

// TestApplyStampsGroupTimeFromStoreClock — отметку времени группы ставит стор
// по своим часам: Diff оставлен чистой функцией и часов не знает, а настоящее
// время в продукте берётся только из clock.Clock (§8.1).
func TestApplyStampsGroupTimeFromStoreClock(t *testing.T) {
	dir := t.TempDir()
	fake := clock.NewFake(testEpoch)
	s, err := Open(dir, fake)
	if err != nil {
		t.Fatalf("стор не открылся: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	fake.Advance(90 * time.Minute)
	mustApply(t, s, "g", composition(node("n1", "g", "a.example")))

	groups := s.Groups()
	if len(groups) != 1 {
		t.Fatalf("групп %d, ожидалась одна: Apply не завёл группу под её составом", len(groups))
	}
	want := testEpoch.Add(90 * time.Minute)
	if !groups[0].LastUpdatedAt.Equal(want) {
		t.Errorf("last_updated_at %s, а часы стора показывали %s", groups[0].LastUpdatedAt, want)
	}
	if got := groups[0].NodeOrder; !slices.Equal(got, []string{"n1"}) {
		t.Errorf("node_order %v, а состав задавал n1", got)
	}
}

// TestApplyKeepsGroupMetadata — состав меняет состав, а не подписку: имя,
// ссылка и настройки автообновления переживают обновление. Merged их не несёт,
// и перезапись группы целиком стёрла бы source_url — то есть возможность
// обновиться ещё раз.
func TestApplyKeepsGroupMetadata(t *testing.T) {
	s, _ := newStore(t)
	seed(t, s, Group{
		ID:                 "g",
		Name:               "подписка",
		SourceURL:          "https://example.invalid/sub",
		QuotaInfo:          "upload=1; download=2",
		AutoUpdate:         true,
		AutoUpdateInterval: 6 * time.Hour,
	}, node("n1", "g", "a.example"))

	mustApply(t, s, "g", composition(node("n2", "g", "b.example")))

	g := s.Groups()[0]
	if g.Name != "подписка" || g.SourceURL != "https://example.invalid/sub" ||
		g.QuotaInfo != "upload=1; download=2" || !g.AutoUpdate || g.AutoUpdateInterval != 6*time.Hour {
		t.Errorf("обновление состава стёрло параметры подписки: %+v", g)
	}
}

// TestApplyRefusesForeignNode — Р9: слияние не пересекает границу группы. Стор
// — последнее место, где чужой узел ещё можно заметить: дальше он лёг бы в
// nodes.json с чужим group_id.
func TestApplyRefusesForeignNode(t *testing.T) {
	s, _ := newStore(t)
	mustApply(t, s, "чужая", composition(node("n1", "чужая", "a.example")))

	// Узел помечен своей группой, но id занят чужой.
	stolen := node("n1", "g", "a.example")
	if err := s.Apply("g", composition(stolen)); err == nil {
		t.Error("состав с чужим id применился — история проб чужой подписки досталась бы этой (Р9)")
	}

	// Узел помечен чужой группой прямо в составе.
	if err := s.Apply("g", composition(node("n2", "чужая", "b.example"))); err == nil {
		t.Error("узел с чужим group_id применился к группе g")
	}

	// Чужая группа при этом цела.
	if got := nodeIDs(s.Nodes("чужая")); !slices.Equal(got, []string{"n1"}) {
		t.Errorf("состав чужой группы изменился: %v", got)
	}
}

// TestApplyRefusesBrokenComposition — состав, который нельзя записать,
// отбраковывается до единой правки: применение состава не бывает наполовину.
func TestApplyRefusesBrokenComposition(t *testing.T) {
	s, _ := newStore(t)
	mustApply(t, s, "g", composition(node("n1", "g", "a.example")))

	for _, tc := range []struct {
		name string
		m    Merged
	}{
		{"узел без id", composition(node("", "g", "b.example"))},
		{"узел дважды", composition(node("n2", "g", "b.example"), node("n2", "g", "b.example"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.Apply("g", tc.m); err == nil {
				t.Fatal("состав применился, хотя записать его нельзя")
			}
			if got := nodeIDs(s.Nodes("g")); !slices.Equal(got, []string{"n1"}) {
				t.Errorf("отвергнутый состав всё же изменил группу: %v", got)
			}
		})
	}

	if err := s.Apply("", composition(node("n2", "", "b.example"))); err == nil {
		t.Error("состав применился к группе без id")
	}
}

// TestApplyOnClosedStoreFails — закрытый стор не принимает записей: иначе они
// молча ложились бы в память процесса, который уже отпустил замок.
func TestApplyOnClosedStoreFails(t *testing.T) {
	s, _ := newStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("закрытие не прошло: %v", err)
	}
	err := s.Apply("g", composition(node("n1", "g", "a.example")))
	if err == nil || !strings.Contains(err.Error(), "закрыт") {
		t.Errorf("закрытый стор принял состав: %v", err)
	}
	if err != nil && errors.Is(err, ErrLocked) {
		t.Errorf("отказ выдан за занятость замка: %v", err)
	}
}
