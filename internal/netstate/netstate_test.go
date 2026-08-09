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
