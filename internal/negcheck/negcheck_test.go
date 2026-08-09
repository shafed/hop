package negcheck

import (
	"testing"

	"github.com/shafed/hop/internal/policy"
)

// TestMetaCheck — мета-проверка этапа 0: negcheck обязан покраснить заведомо
// плохой тест и пропустить честный. Без неё негативная задача сама была бы
// непроверенной.
func TestMetaCheck(t *testing.T) {
	root, err := ModuleRoot(".")
	if err != nil {
		t.Fatal(err)
	}

	problems := Check(root, policy.Fixtures())

	byPolicy := map[string]Problem{}
	for _, p := range problems {
		byPolicy[p.Policy] = p
	}

	if p, found := byPolicy[policy.FixtureGood.Name]; found {
		t.Errorf("честная фикстура объявлена дефектной: %s", p)
	}
	if _, found := byPolicy[policy.FixtureBad.Name]; !found {
		t.Errorf("заведомо плохой тест не обнаружен; найдено: %v", problems)
	}
}
