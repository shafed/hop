package policy

// Все политики продукта. Добавление политики без Guards не пройдёт
// TestEveryPolicyIsGuarded.
var (
	// PacketFraming — length-prefix framing на пакетной границе (этап 1).
	// Выключение переводит запись в режим «просто склеить полезные нагрузки»,
	// после чего читатель не может восстановить границы пакетов.
	PacketFraming = &Policy{
		Name: "packet_framing",
		Doc:  "length-prefix framing на границе агент↔сервис (§3.2, этап 1)",
		Guards: []Guard{
			{Pkg: "./internal/framing", Test: "^TestBatchRoundTrip$"},
		},
	}
)

// All — полный список политик продукта.
func All() []*Policy {
	return []*Policy{
		PacketFraming,
	}
}

// Фикстуры мета-проверки. В All() их нет намеренно: они существуют только
// чтобы доказать, что negcheck отличает честно охраняемую политику от
// политики, чей «охраняющий» тест зелен при любом её состоянии.
var (
	FixtureGood = &Policy{
		Name: "fixture_good",
		Doc:  "фикстура: тест действительно смотрит на флаг",
		Guards: []Guard{
			{Pkg: "./internal/negcheck/fixture", Test: "^TestFixtureGood$"},
		},
	}
	FixtureBad = &Policy{
		Name: "fixture_bad",
		Doc:  "фикстура: заведомо плохой тест, зелёный при выключенной политике",
		Guards: []Guard{
			{Pkg: "./internal/negcheck/fixture", Test: "^TestFixtureBad$"},
		},
	}
)

// Fixtures — политики мета-проверки negcheck.
func Fixtures() []*Policy {
	return []*Policy{FixtureGood, FixtureBad}
}
