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

	// OrphanReject — подмена маршрутов туннеля на reject-маршруты ядра на
	// ребре в orphaned (§6.2, этап 2). Выключение оставляет окно молчаливым:
	// интерфейс жив, читателя нет, пакеты дропаются — ровно то, что запрещает
	// §5.6. Краснит L1-тест ребра и L3-тесты T23-fast/T23b.
	OrphanReject = &Policy{
		Name: "orphan_reject",
		Doc:  "reject-маршруты в состоянии orphaned (§6.2, T23-fast, T23b)",
		Guards: []Guard{
			{Pkg: "./internal/tunnel", Test: "^TestEdgeInstallsReject$"},
			{Pkg: "./internal/reject", Test: "^TestReplyRefusesInsteadOfSilence$"},
		},
	}

	// OrphanDeadline — окно, в котором новый агент может забрать живой туннель
	// по токену (§6.2, §3.1). Выключение схлопывает окно в ноль: интерфейс
	// исчезает до реаттача, и T24 краснеет.
	OrphanDeadline = &Policy{
		Name: "orphan_deadline",
		Doc:  "окно реаттача по attach-token (§6.2, T24)",
		Guards: []Guard{
			{Pkg: "./internal/tunnel", Test: "^TestAttachWithinDeadline$"},
		},
	}

	// SnapshotRestore — восстановление состояния сети из снапшота (§8.4,
	// общий платформенный контракт). Выключение превращает откат в пустышку,
	// и снапшот после down перестаёт совпадать с исходным: T22, T23-slow, T29.
	SnapshotRestore = &Policy{
		Name: "snapshot_restore",
		Doc:  "откат изменений сети до снапшота (§8.4, T22, T23-slow, T29)",
		Guards: []Guard{
			{Pkg: "./internal/netstate", Test: "^TestRollbackReturnsToSnapshot$"},
		},
	}

	// VerdictOrder — порядок вердиктов §3.4: hijack-dns стоит перед bypass
	// (этап 3). Выключение меняет их местами, и DNS-запрос на локальный роутер
	// уходит в локальную сеть при формально работающем перехвате: T16.
	VerdictOrder = &Policy{
		Name: "verdict_order",
		Doc:  "hijack-dns прежде bypass (§3.4, T16)",
		Guards: []Guard{
			{Pkg: "./internal/netstack", Test: "^TestT16DNSToLocalRouterIsHijacked$"},
		},
	}

	// RejectMode — fail-close отвечает отказом, а не молчанием (§5.6, этап 3).
	// Выключение переводит отказ в молчаливый дроп, и приложение ждёт таймаута
	// вместо RST/ICMP: T12, T13.
	RejectMode = &Policy{
		Name: "reject_mode",
		Doc:  "fail-close через RST/ICMP, а не дроп (§5.6, T12, T13)",
		Guards: []Guard{
			{Pkg: "./internal/netstack", Test: "^TestT12FailCloseAnswersRST$"},
			{Pkg: "./internal/netstack", Test: "^TestT13FailCloseAnswersICMP$"},
		},
	}

	// NATKey — UDP full-cone: NAT по source addr:port (§5.3, этап 3).
	// Выключение переводит ключ на пару src+dst: записей становится по одной на
	// адрес назначения, а ответ с адреса, на который клиент не слал, теряется.
	// T15 и рост таблицы в B3.
	NATKey = &Policy{
		Name: "nat_key",
		Doc:  "NAT по source addr:port, full-cone (§5.3, T15, B3)",
		Guards: []Guard{
			{Pkg: "./internal/netstack", Test: "^TestT15FullConeKeepsOneEntry$"},
		},
	}
)

// All — полный список политик продукта.
func All() []*Policy {
	return []*Policy{
		PacketFraming,
		OrphanReject,
		OrphanDeadline,
		SnapshotRestore,
		VerdictOrder,
		RejectMode,
		NATKey,
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
