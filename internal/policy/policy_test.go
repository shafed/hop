package policy

import "testing"

func TestEveryPolicyIsGuarded(t *testing.T) {
	for _, p := range append(All(), Fixtures()...) {
		if p.Name == "" {
			t.Errorf("политика без имени: %+v", p)
		}
		if len(p.Guards) == 0 {
			t.Errorf("политика %q без охраняющего теста", p.Name)
		}
	}
}

func TestNamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range append(All(), Fixtures()...) {
		if seen[p.Name] {
			t.Errorf("дубликат имени политики: %q", p.Name)
		}
		seen[p.Name] = true
	}
}

func TestParseDisabled(t *testing.T) {
	got := parseDisabled(" a, b ,,c ")
	for _, want := range []string{"a", "b", "c"} {
		if !got[want] {
			t.Errorf("не разобрано имя %q из списка", want)
		}
	}
	if len(got) != 3 {
		t.Errorf("лишние имена: %v", got)
	}
}
