// Package doclint — проверка документов на утверждения о состоянии, за
// которыми нет исполнимой проверки (§8, третий линтер семьи negcheck и
// realtimelint).
package doclint

import "fmt"

// Kind — класс находки.
type Kind string

const (
	KindTest   Kind = "тест"
	KindPolicy Kind = "политика"
	KindPath   Kind = "путь"
	KindRef    Kind = "ссылка git"
	KindStale  Kind = "лишняя строка"
)

// Finding — одно утверждение документа, за которым ничего не стоит.
type Finding struct {
	File  string
	Line  int
	Kind  Kind
	Token string
	Msg   string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s %s — %s", f.File, f.Line, f.Kind, f.Token, f.Msg)
}

// Config — что и чем проверять.
type Config struct {
	// Root — корень дерева документов (для продукта — корень модуля).
	Root string
	// Policies — имена зарегистрированных политик (policy.All()).
	Policies []string
	// ResolveRef отвечает, разрешается ли имя ветки или хеш в этом
	// репозитории. nil выключает проверку целиком: у CI-чекаута нет ни
	// локальных веток проходов, ни полной истории.
	ResolveRef func(name string) bool
}

// Check возвращает находки, отсортированные по файлу и строке.
func Check(cfg Config) ([]Finding, error) {
	return nil, nil
}
