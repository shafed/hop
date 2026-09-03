package netstate

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// fakeSystem — сеть без сети: карта «ключ → значение» вместо адресов,
// маршрутов и правил. Достаточно, чтобы проверить сам контракт §8.4 без прав
// и на всех трёх ОС.
type fakeSystem struct {
	routes map[string]string
	rules  map[string]string
}

func newFakeSystem() *fakeSystem {
	return &fakeSystem{
		routes: map[string]string{"default": "via 192.168.1.1 dev eth0"},
		rules:  map[string]string{"32766": "from all lookup main"},
	}
}

func (f *fakeSystem) Capture() (Snapshot, error) {
	return NewSnapshot(
		Section{Name: "routes", Lines: dump(f.routes)},
		Section{Name: "rules", Lines: dump(f.rules)},
	), nil
}

func dump(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+" "+v)
	}
	sort.Strings(out)
	return out
}

// set/unset — пара «изменение и его откат», какой её кладут в журнал.
func (f *fakeSystem) set(m map[string]string, k, v string) (apply, undo func() error) {
	old, had := m[k]
	return func() error { m[k] = v; return nil },
		func() error {
			if had {
				m[k] = old
			} else {
				delete(m, k)
			}
			return nil
		}
}

// TestRollbackReturnsToSnapshot — охраняющий тест политики snapshot_restore и
// L1-половина общего платформенного контракта §8.4.
//
// С выключенной политикой откат становится пустышкой, изменения остаются в
// системе, и снапшот перестаёт совпадать — ровно то, что на L3 увидели бы T22,
// T23-slow и T29, но уже без прав.
func TestRollbackReturnsToSnapshot(t *testing.T) {
	sys := newFakeSystem()
	before, err := sys.Capture()
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}

	var j Journal
	// Всё, что делает `up`: своя таблица, свой маршрут, своё правило,
	// подменённый дефолт.
	steps := []struct{ k, v string }{
		{"table100 default", "dev hop0"},
		{"default", "dev hop0"},
	}
	for _, s := range steps {
		apply, undo := sys.set(sys.routes, s.k, s.v)
		if err := j.Do("route "+s.k, apply, undo); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	apply, undo := sys.set(sys.rules, "100", "uidrange 1000-1000 lookup main")
	if err := j.Do("rule uidrange", apply, undo); err != nil {
		t.Fatalf("Do: %v", err)
	}

	dirty, _ := sys.Capture()
	if before.Equal(dirty) {
		t.Fatal("после изменений снапшот совпал — тест ничего не измерил")
	}

	if err := j.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if err := Verify(before, sys); err != nil {
		t.Fatal(err)
	}
}

// Откат идёт в обратном порядке: подменённый дефолт надо вернуть раньше, чем
// исчезнет интерфейс, на который он указывает.
func TestRollbackIsReversed(t *testing.T) {
	var j Journal
	var order []string
	for _, name := range []string{"первое", "второе", "третье"} {
		if err := j.Do(name, func() error { return nil }, func() error {
			order = append(order, name)
			return nil
		}); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if err := j.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got := strings.Join(order, ","); got != "третье,второе,первое" {
		t.Fatalf("порядок отката = %s", got)
	}
	if j.Len() != 0 {
		t.Fatalf("после отката в журнале %d изменений", j.Len())
	}
}

// Неудачный шаг отката не прерывает остальные: остановиться на первой ошибке
// значит гарантированно оставить в системе всё, что было записано раньше неё.
func TestRollbackContinuesAfterError(t *testing.T) {
	sys := newFakeSystem()
	before, _ := sys.Capture()

	var j Journal
	apply, undo := sys.set(sys.routes, "default", "dev hop0")
	_ = j.Do("подменить дефолт", apply, undo)
	_ = j.Do("шаг, который не откатится",
		func() error { return nil },
		func() error { return errors.New("ядро отказало") })

	err := j.Rollback()
	if err == nil {
		t.Fatal("ошибка отката потерялась")
	}
	if !strings.Contains(err.Error(), "ядро отказало") {
		t.Fatalf("ошибка = %v", err)
	}
	// И тем не менее откатилось то, что откатывалось.
	if verr := Verify(before, sys); verr != nil {
		t.Fatalf("после частичного отката: %v", verr)
	}
}

// Изменение, которое не применилось, в журнал не попадает: иначе откат
// попытается отменить то, чего не было.
func TestFailedApplyIsNotRecorded(t *testing.T) {
	var j Journal
	err := j.Do("шаг", func() error { return errors.New("нет прав") }, func() error {
		t.Fatal("откат вызван для неприменённого изменения")
		return nil
	})
	if err == nil {
		t.Fatal("ошибка применения потерялась")
	}
	if j.Len() != 0 {
		t.Fatalf("в журнале %d изменений", j.Len())
	}
	if err := j.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
}

// Diff обязан замечать и лишнее, и пропавшее, и кратность: маршрут, добавленный
// дважды и снятый один раз, — это утечка состояния.
func TestDiff(t *testing.T) {
	a := NewSnapshot(Section{Name: "routes", Lines: []string{"x", "y", "y"}})
	b := NewSnapshot(Section{Name: "routes", Lines: []string{"y", "z"}})

	got := fmt.Sprint(a.Diff(b))
	for _, want := range []string{"routes: -x", "routes: -y", "routes: +z"} {
		if !strings.Contains(got, want) {
			t.Fatalf("в разнице %s нет %q", got, want)
		}
	}
	if a.Equal(b) {
		t.Fatal("разные снапшоты признаны равными")
	}
	// Порядок строк из системных утилит не стабилен, сравнение — обязано.
	shuffled := NewSnapshot(Section{Name: "routes", Lines: []string{"y", "x", "y"}})
	if !a.Equal(shuffled) {
		t.Fatalf("порядок строк повлиял на сравнение: %v", a.Diff(shuffled))
	}
}

// W72: Classify делит расхождение по следу, и пустой след означает «всё
// чужое», а не «всё наше».
//
// Направление ошибки проверяется отдельно от самого деления: строка, попавшая
// не в ту половину, у Classify — это либо ложный отказ штатной остановки,
// либо пропущенная течь, и это разные беды.
func TestW72ClassifySplitsByFootprint(t *testing.T) {
	diff := []string{
		"addrs: +2: hop0    inet 10.255.0.1/24 scope global hop0",
		"addrs: +1: lo    inet 10.99.0.1/32 scope global lo",
		"rules: +31000:\tfrom all to 10.0.0.0/8 lookup main",
		"routes: -local 10.98.0.1 dev lo table local",
	}
	marks := []string{"hop0", "31000:"}

	mine, foreign := Classify(diff, marks)
	if want := []string{diff[0], diff[2]}; !sameLines(mine, want) {
		t.Errorf("своим сочтено %v, ожидалось %v", mine, want)
	}
	if want := []string{diff[1], diff[3]}; !sameLines(foreign, want) {
		t.Errorf("чужим сочтено %v, ожидалось %v", foreign, want)
	}
}

// W72: без следа своего нет. Так выглядит сервис, простоявший без единого
// `up`, и так же — платформа, где Up ещё не написан (Unsupported.Footprint).
func TestW72ClassifyWithoutFootprintClaimsNothing(t *testing.T) {
	diff := []string{"addrs: +2: hop0 inet 10.255.0.1/24", "routes: +default dev hop0 table 8420"}
	for _, marks := range [][]string{nil, {}, {""}} {
		mine, foreign := Classify(diff, marks)
		if len(mine) != 0 {
			t.Errorf("marks=%v: своим сочтено %v", marks, mine)
		}
		if len(foreign) != len(diff) {
			t.Errorf("marks=%v: чужих %d, ожидалось %d", marks, len(foreign), len(diff))
		}
	}
}

// W72: совпадение снапшотов — по-прежнему обе половины пустые. Отдельным
// утверждением, потому что штатный выход hopd опирается именно на это.
func TestW72ClassifyOfEmptyDiffIsEmpty(t *testing.T) {
	mine, foreign := Classify(nil, []string{"hop0"})
	if len(mine) != 0 || len(foreign) != 0 {
		t.Fatalf("на пустом расхождении получили %v / %v", mine, foreign)
	}
}

func sameLines(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
