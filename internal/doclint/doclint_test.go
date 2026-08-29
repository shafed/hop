package doclint

import (
	"fmt"
	"path/filepath"
	"sort"
	"testing"
)

// fixturePolicies — реестр политик поддельного репозитория из testdata.
var fixturePolicies = []string{"known_flag"}

// fixtureRefs — поддельный git: worktree-here есть, worktree-gone нет.
func fixtureRefs(name string) bool { return name == "worktree-here" }

func run(t *testing.T, dir string) []string {
	t.Helper()
	found, err := Check(Config{
		Root:       filepath.Join("testdata", dir),
		Policies:   fixturePolicies,
		ResolveRef: fixtureRefs,
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range found {
		got = append(got, fmt.Sprintf("%s|%s|%s", filepath.ToSlash(f.File), f.Kind, f.Token))
	}
	sort.Strings(got)
	return got
}

// TestDirtyFixtureIsRed — на поддельном репозитории с одной гнилью каждого
// вида линтер обязан назвать ровно их и ничего сверх. Это мета-проверка того
// же жанра, что TestMetaCheck у negcheck: без неё линтер сам непроверен.
func TestDirtyFixtureIsRed(t *testing.T) {
	want := []string{
		"HANDOFF.json|путь|internal/thing/nope.go",
		"HANDOFF.json|ссылка git|worktree-gone",
		"PLAN.md|политика|nowhere_flag",
		"PLAN.md|путь|docs/gone.md",
		"PLAN.md|тест|T77",
		"SPEC.md|тест|T76",
		"docs/not-yet-written.md|лишняя строка|T70",
		"docs/verification-agent.md|тест|W79",
		"implementation-notes.md|путь|internal/thing/absent.go",
	}
	got := run(t, "dirty")
	if len(got) != len(want) {
		t.Fatalf("находок %d, ожидалось %d:\nполучено: %v\nожидалось: %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("находка %d: %s, ожидалась %s", i, got[i], want[i])
		}
	}
}

// TestCleanFixtureIsGreen — второе направление, без которого первое ничего не
// стоит: на документе, где те же обороты употреблены честно (CIDR, чужой
// референс, pkg.Symbol, абсолютный путь, шаблон, snake_case не про политику,
// диапазон номеров, помеченная doclint:ignore мёртвая ссылка), линтер обязан
// молчать.
func TestCleanFixtureIsGreen(t *testing.T) {
	if got := run(t, "clean"); len(got) != 0 {
		t.Fatalf("ложные срабатывания на честном документе: %v", got)
	}
}
