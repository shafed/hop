// Package netstate — снапшот состояния сети и откат изменений до него.
//
// §8.4 объявляет это общим платформенным контрактом: до старта снимается
// снапшот (адреса, маршруты, правила, настройки DNS), после `down` снимается
// снова и обязан совпасть. План (этап 2) требует, чтобы это был
// самостоятельный тестируемый объект, а не побочный эффект `down`, — иначе
// проверять его можно только целиком поднятым туннелем, то есть только на
// привилегированном раннере.
//
// Отсюда две половины пакета:
//
//   - Snapshot + Source — что было и чем это читать. Source подменяем, поэтому
//     сравнение снапшотов проверяется без прав.
//   - Journal — изменения вместе с их откатом. Откат идёт по журналу, а не
//     по разнице снапшотов: разница говорит, что не сходится, но не говорит,
//     как это вернуть, и «восстановление» превратилось бы в угадывание.
package netstate

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/shafed/hop/internal/policy"
)

// Section — один раздел снапшота: имя и отсортированные строки.
type Section struct {
	Name  string
	Lines []string
}

// Snapshot — состояние сети в момент съёмки.
type Snapshot struct {
	Sections []Section
}

// Source — откуда читается состояние. Реальная реализация — платформенная,
// фейковая живёт в тестах.
type Source interface {
	Capture() (Snapshot, error)
}

// Equal — то самое «совпал побайтово» из §8.4.
func (s Snapshot) Equal(o Snapshot) bool { return len(s.Diff(o)) == 0 }

// Diff возвращает расхождения в форме «раздел: -было / +стало».
// Пустой результат означает совпадение.
func (s Snapshot) Diff(o Snapshot) []string {
	var out []string
	for _, name := range sectionNames(s, o) {
		was, is := s.section(name), o.section(name)
		for _, l := range missing(was, is) {
			out = append(out, fmt.Sprintf("%s: -%s", name, l))
		}
		for _, l := range missing(is, was) {
			out = append(out, fmt.Sprintf("%s: +%s", name, l))
		}
	}
	return out
}

// String — читаемая форма для сообщения об ошибке теста.
func (s Snapshot) String() string {
	var b strings.Builder
	for _, sec := range s.Sections {
		fmt.Fprintf(&b, "[%s]\n", sec.Name)
		for _, l := range sec.Lines {
			fmt.Fprintf(&b, "  %s\n", l)
		}
	}
	return b.String()
}

func (s Snapshot) section(name string) []string {
	for _, sec := range s.Sections {
		if sec.Name == name {
			return sec.Lines
		}
	}
	return nil
}

func sectionNames(a, b Snapshot) []string {
	seen := map[string]bool{}
	var names []string
	for _, s := range [][]Section{a.Sections, b.Sections} {
		for _, sec := range s {
			if !seen[sec.Name] {
				seen[sec.Name] = true
				names = append(names, sec.Name)
			}
		}
	}
	sort.Strings(names)
	return names
}

// missing возвращает строки a, которых нет в b, с учётом кратности.
func missing(a, b []string) []string {
	count := map[string]int{}
	for _, l := range b {
		count[l]++
	}
	var out []string
	for _, l := range a {
		if count[l] > 0 {
			count[l]--
			continue
		}
		out = append(out, l)
	}
	return out
}

// NewSnapshot собирает снапшот, приводя каждый раздел к сортированному виду:
// порядок строк в выводе системных утилит не стабилен, а сравнение обязано
// быть стабильным.
func NewSnapshot(sections ...Section) Snapshot {
	out := make([]Section, len(sections))
	for i, sec := range sections {
		lines := append([]string(nil), sec.Lines...)
		sort.Strings(lines)
		out[i] = Section{Name: sec.Name, Lines: lines}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return Snapshot{Sections: out}
}

// Journal — изменения сети вместе с их откатом.
//
// Откат — единственный способ вернуть снапшот, поэтому запись отката и запись
// изменения происходят в одном вызове Do: разнести их значит однажды сделать
// изменение без отката и узнать об этом от пользователя.
type Journal struct {
	mu      sync.Mutex
	changes []change
}

type change struct {
	name string
	undo func() error
}

// Do выполняет изменение и запоминает, как его откатить.
func (j *Journal) Do(name string, apply, undo func() error) error {
	if err := apply(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	j.mu.Lock()
	j.changes = append(j.changes, change{name, undo})
	j.mu.Unlock()
	return nil
}

// Len — сколько изменений ждёт отката.
func (j *Journal) Len() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.changes)
}

// Rollback откатывает изменения в обратном порядке.
//
// Ошибка одного шага не прерывает откат: остановиться на первой значит
// гарантированно оставить остальное в системе. Возвращается всё, что не
// вышло, — но откатывается всё, что вышло.
func (j *Journal) Rollback() error {
	j.mu.Lock()
	changes := j.changes
	j.changes = nil
	j.mu.Unlock()

	// Политика §8: без неё откат становится пустышкой, и снапшот после down
	// перестаёт совпадать с исходным — T22, T23-slow, T29.
	if !policy.SnapshotRestore.On() {
		return nil
	}

	var errs []string
	for i := len(changes) - 1; i >= 0; i-- {
		if changes[i].undo == nil {
			continue
		}
		if err := changes[i].undo(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", changes[i].name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("откат не полон: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Verify снимает снапшот заново и сравнивает с исходным — общий платформенный
// контракт §8.4 одной строкой.
func Verify(before Snapshot, src Source) error {
	after, err := src.Capture()
	if err != nil {
		return err
	}
	if d := before.Diff(after); len(d) > 0 {
		return fmt.Errorf("снапшот сети не совпал с исходным:\n  %s", strings.Join(d, "\n  "))
	}
	return nil
}
