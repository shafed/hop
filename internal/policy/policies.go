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

	// KOfN — узел мёртв при k неудачах из n последних результатов (§6.3,
	// этап 5). Выключение ставит k=1: одна неудачная проба стирает узел,
	// ровно как DeleteURLTestHistory в sing-box, из-за чего на нестабильной
	// сети выбор мечется. Краснит T2 и A3 (воскрешение стоит k успехов).
	KOfN = &Policy{
		Name: "k_of_n",
		Doc:  "смерть по k из n результатов, а не по последнему (§6.3, T1, T2, A1–A3)",
		Guards: []Guard{
			{Pkg: "./internal/health", Test: "^TestT2SingleFailureKeepsNodeAlive$"},
			{Pkg: "./internal/health", Test: "^TestA3DeadNodeReturnsAfterTwoSuccesses$"},
		},
	}

	// Tolerance — гистерезис выбора (§6.4, этап 5). Выключение обнуляет
	// порог, и два узла с 90 и 95 мс перекидывают пользователя туда-сюда на
	// каждом цикле проб.
	Tolerance = &Policy{
		Name: "tolerance",
		Doc:  "гистерезис 50 мс при выборе более быстрого узла (§6.4, T3)",
		Guards: []Guard{
			{Pkg: "./internal/health", Test: "^TestT3HysteresisLimitsSwitching$"},
		},
	}

	// SwitchReason — причина переключения решает судьбу активных соединений
	// (§5.5, этап 5). Выключение рвёт их всегда — путь sing-box, где причины
	// нет и разрыв сделан глобальным флагом. Краснит A19: обрыв загрузки ради
	// 30 мс выигрыша.
	SwitchReason = &Policy{
		Name: "switch_reason",
		Doc:  "рвать соединения только при reason=dead (§5.5, T7, T8, A18, A19)",
		Guards: []Guard{
			{Pkg: "./internal/health", Test: "^TestA19FasterSwitchKeepsConnections$"},
		},
	}

	// ForcedProbe — форс-прогон проб на событиях сети (§6.6, этап 5).
	// Выключение оставляет только тикер: после пробуждения из сна пользователь
	// ждёт полный интервал на заведомо мёртвом узле.
	ForcedProbe = &Policy{
		Name: "forced_probe",
		Doc:  "немедленный прогон проб на событиях сети (§6.6, T6, A24)",
		Guards: []Guard{
			{Pkg: "./internal/health", Test: "^TestT6NetworkChangeProbesImmediately$"},
			{Pkg: "./internal/health", Test: "^TestA24ForcedProbesCoalesce$"},
		},
	}

	// MultiURL — несколько тестовых URL (§5.4, этап 5). Выключение оставляет
	// один, и блокировка единственного тестового домена убивает всю подписку
	// разом при полностью живых узлах.
	MultiURL = &Policy{
		Name: "multi_url",
		Doc:  "проба по нескольким URL, успех хотя бы одного (§5.4, T5, A30–A32)",
		Guards: []Guard{
			{Pkg: "./internal/health", Test: "^TestT5OneBlockedURLDoesNotKillNodes$"},
			{Pkg: "./internal/health", Test: "^TestA31RTTIsTheFastestURL$"},
		},
	}

	// ProbeTiers — ярусное расписание проб (§6.5, этап 5). Выключение
	// схлопывает ярусы в полный обход подписки на каждом тике: 200 узлов дают
	// тысячи TLS-хендшейков в час к одному провайдеру. Краснит A25 и A26.
	ProbeTiers = &Policy{
		Name: "probe_tiers",
		Doc:  "ярусы расписания проб и джиттер хвоста (§6.5, A25, A26)",
		Guards: []Guard{
			{Pkg: "./internal/health", Test: "^TestA25ProbeCostStaysBounded$"},
			{Pkg: "./internal/health", Test: "^TestA26TailProbesAreSpread$"},
		},
	}

	// TrafficKills — ошибки реального трафика влияют на живость (§5.4, §6.15,
	// этап 5). Выключение оставляет только пробы, и узел, умерший под
	// трафиком, живёт до следующей пробы — то есть до 45 с вместо 5 с.
	TrafficKills = &Policy{
		Name: "traffic_kills",
		Doc:  "ошибки трафика §6.15 убивают узел наравне с пробами (A5, A29)",
		Guards: []Guard{
			{Pkg: "./internal/health", Test: "^TestA5TrafficFailuresKillNode$"},
			{Pkg: "./internal/health", Test: "^TestA29SwitchUnderTrafficIsFast$"},
		},
	}

	// ErrorClassify — классификация ошибок §6.15: смертью считаются только
	// отказы на пути к узлу (этап 4). Выключение переводит движок в режим
	// «убивает любой отказ», и живой узел умирает от отказа целевого сайта —
	// ровно та ошибка, ради которой перечисление §6.15 замкнуто. Краснит T20.
	ErrorClassify = &Policy{
		Name: "error_classify",
		Doc:  "смертельны только отказы на пути к узлу (§6.15, T20)",
		// Охраняет не T20, а TestStreamErrorIsNotFatal, и вот почему.
		// Когда целевой хост отказывает через живой узел, клиент видит
		// обычный EOF — вердикта в этом случае нет вовсе, и T20 остаётся
		// зелёным при любом состоянии флага. Различает флаг другой случай:
		// ошибку потока «closed pipe», за которой может стоять и мёртвый
		// узел, и мёртвый сайт. Именно её выключенная политика объявляет
		// смертью — а T20 идёт спутником, проверяя, что до health при этом
		// ничего не доехало.
		Guards: []Guard{
			{Pkg: "./internal/engine", Test: "^TestStreamErrorIsNotFatal$"},
		},
	}

	// ParseCascade — каскад распознавателей §6.12: первый взявший забирает
	// вход целиком (этап 7). Выключение переводит каскад в режим «ступени
	// объединяют результаты»: base64-обёртка, разобравшаяся заодно и
	// построчно, даёт узлы дважды, а тело Clash YAML вместо одной внятной
	// ошибки уезжает в построчный разбор и превращается в шум. S22, S23, S24.
	ParseCascade = &Policy{
		Name: "parse_cascade",
		Doc:  "первый взявший распознаватель забирает вход целиком (§6.12, S22–S24)",
		Guards: []Guard{
			{Pkg: "./internal/subscription", Test: "^TestS22Base64BodyTakenByFirstStage$"},
			{Pkg: "./internal/subscription", Test: "^TestS23ClashBodyRejectedWithOneError$"},
			{Pkg: "./internal/subscription", Test: "^TestS24Base64ContentIsNotParsedTwice$"},
		},
	}

	// MergeKey — ключ слияния подписок §6.16: protocol + server + port +
	// user_id (этап 7). Выключение переводит ключ на полный отпечаток узла —
	// второй вариант nekoray (ProfileFilter_ent_key), который §6.16 отвергает:
	// косметическая правка у провайдера (сменился транспорт, сменился SNI)
	// перестаёт быть тем же узлом, узел получает новый id и теряет историю проб
	// на ровном месте. T18, S1.
	MergeKey = &Policy{
		Name: "merge_key",
		Doc:  "ключ слияния §6.16, а не полный отпечаток узла (§5.8, T18, S1)",
		Guards: []Guard{
			{Pkg: "./internal/subscription", Test: "^TestT18SNIChangeKeepsSameID$"},
			{Pkg: "./internal/subscription", Test: "^TestS1TransportChangeKeepsID$"},
		},
	}

	// MergeKeyUserID — в ключ §6.16 входит user_id по таблице протоколов (этап
	// 7). Выключение оставляет один адрес — первый вариант nekoray, — и два
	// узла на одном сервере и порту, различающиеся только ключом доступа,
	// склеиваются в один: история одного приписывается другому. S3.
	//
	// Флаг отдельный от merge_key, а не режим внутри него: HOP_DISABLE двоичен,
	// и одним флагом одна из двух проверок осталась бы без охранника
	// (docs/verification-store.md §6).
	MergeKeyUserID = &Policy{
		Name: "merge_key_userid",
		Doc:  "user_id по таблице §6.16 в ключе слияния, а не один адрес (S3)",
		Guards: []Guard{
			{Pkg: "./internal/subscription", Test: "^TestS3UserIDDistinguishesNodes$"},
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
		KOfN,
		Tolerance,
		SwitchReason,
		ForcedProbe,
		MultiURL,
		ProbeTiers,
		TrafficKills,
		ErrorClassify,
		ParseCascade,
		MergeKey,
		MergeKeyUserID,
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
