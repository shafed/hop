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

	// ErrorClassify — замкнутое перечисление §6.15: смертью узла считаются
	// только отказы на пути к узлу и внутри него (этап 4). Выключение сводит
	// классификацию к «любая ошибка убивает», и упавший сайт уносит с собой
	// живой узел: T20.
	ErrorClassify = &Policy{
		Name: "error_classify",
		Doc:  "смертью узла считаются только отказы узла, не сайта (§6.15, T20)",
		Guards: []Guard{
			{Pkg: "./internal/engine", Test: "^TestT20SiteErrorDoesNotKillNode$"},
		},
	}

	// KOfN — окно смерти §6.3: мёртв при k неудачах из n последних проб (этап
	// 5). Выключение схлопывает окно до одной пробы, и на нестабильной сети
	// первая же ошибка убивает узел — путь sing-box с DeleteURLTestHistory: T2.
	KOfN = &Policy{
		Name: "k_of_n",
		Doc:  "окно k-из-n вместо одной пробы (§6.3, T2)",
		Guards: []Guard{
			{Pkg: "./internal/health", Test: "^TestT2SingleFailureDoesNotKill$"},
		},
	}

	// Tolerance — гистерезис выбора §6.4 (этап 5). Выключение обнуляет порог, и
	// два узла с 90 и 95 мс перекидывают пользователя туда-сюда на каждом
	// цикле: T3.
	Tolerance = &Policy{
		Name: "tolerance",
		Doc:  "переключаемся, только если кандидат быстрее на tolerance (§6.4, T3)",
		Guards: []Guard{
			{Pkg: "./internal/health", Test: "^TestT3NoFlappingWithinTolerance$"},
		},
	}

	// MultiURL — пробы по нескольким URL §5.4 (этап 5). Выключение оставляет
	// один тестовый домен, и его блокировка убивает всю подписку разом: T5.
	MultiURL = &Policy{
		Name: "multi_url",
		Doc:  "пробы по нескольким URL, а не по одному (§5.4, T5)",
		Guards: []Guard{
			{Pkg: "./internal/health", Test: "^TestT5OneDeadURLDoesNotKillNode$"},
		},
	}

	// ForcedProbe — форс-проверка на событиях §6.6 (этап 5). Выключение
	// заставляет ждать тикера после смены сети, то есть держать пользователя на
	// заведомо мёртвом узле: T6.
	ForcedProbe = &Policy{
		Name: "forced_probe",
		Doc:  "немедленный прогон проб по событию смены сети (§6.6, T6)",
		Guards: []Guard{
			{Pkg: "./internal/health", Test: "^TestT6ForcedProbeOnEvent$"},
		},
	}

	// SwitchReason — разрыв соединений зависит от причины переключения §5.5
	// (этап 5). Выключение стирает различие и рвёт всегда, как глобальный флаг
	// sing-box: загрузка не доживает до конца ради выигранных 30 мс: T10.
	SwitchReason = &Policy{
		Name: "switch_reason",
		Doc:  "рвём соединения только при reason=dead (§5.5, T10)",
		Guards: []Guard{
			{Pkg: "./internal/health", Test: "^TestT10FasterSwitchKeepsConnections$"},
		},
	}

	// DNSCacheFlushOnSwitch — сброс кэша при смене узла §5.7в (этап 6).
	// Выключение оставляет старые адреса жить дальше, и после переключения
	// трафик уходит в CDN чужого региона: T14.
	DNSCacheFlushOnSwitch = &Policy{
		Name: "dns_cache_flush_on_switch",
		Doc:  "кэш DNS обнуляется при смене активного узла (§5.7в, T14)",
		Guards: []Guard{
			{Pkg: "./internal/dns", Test: "^TestT14CacheFlushedOnSwitch$"},
		},
	}

	// Bootstrap — резолв хостнеймов узлов мимо туннеля §5.7а (этап 6).
	// Выключение отправляет их через туннель, и старт уходит в петлю: чтобы
	// поднять узел, надо резолвить его имя, а чтобы резолвить — поднять узел.
	Bootstrap = &Policy{
		Name: "bootstrap",
		Doc:  "хостнеймы узлов резолвятся мимо туннеля (§5.7а)",
		Guards: []Guard{
			{Pkg: "./internal/dns", Test: "^TestBootstrapGoesDirect$"},
		},
	}

	// ConfirmProbe — подтверждающая проба сразу после отказа горячего узла
	// (§6.3, §8.3). Выключение оставляет окно k-из-n набираться по одному
	// исходу за период яруса, и смерть активного узла признаётся через минуту
	// вместо секунд — бюджет T9/T11 в пять секунд не берётся ни одним из двух
	// видов отказа.
	ConfirmProbe = &Policy{
		Name: "confirm_probe",
		Doc:  "подтверждающая проба после отказа, а не через период яруса (§6.3, T9, T11)",
		Guards: []Guard{
			{Pkg: "./internal/supervisor", Test: "^TestT9BlackholeInterruptsConnectionWithinBudget$"},
			{Pkg: "./internal/supervisor", Test: "^TestT11BothFailureKindsSwitchWithinBudget$"},
		},
	}

	// MergeKey — ключ слияния подписок §6.16 (этап 7). Выключение переводит
	// ключ на полный отпечаток: косметическая правка у провайдера — смена SNI —
	// делает узел новым и обнуляет его историю проб: T18.
	MergeKey = &Policy{
		Name: "merge_key",
		Doc:  "ключ слияния protocol+server+port+user_id, не полный отпечаток (§6.16, T18)",
		Guards: []Guard{
			{Pkg: "./internal/sub", Test: "^TestT18MergeKeepsHistoryOnSNIChange$"},
		},
	}

	// LoopGuard — защита от петли §6.8 (этап 8): исходящие сокеты агента не
	// заходят обратно в туннель. Выключение возвращает соединение к узлу в
	// собственный TUN, и трафик наматывается сам на себя вместо того, чтобы
	// уйти в сеть: T25.
	LoopGuard = &Policy{
		Name: "loop_guard",
		Doc:  "исходящее к узлу идёт мимо туннеля (§6.8, T25)",
		Guards: []Guard{
			{Pkg: "./internal/loopguard", Test: "^TestT25NoLoopOnNodeDial$"},
		},
	}

	// IPv6Block — блокировка IPv6 §6.9 (этап 8). Выключение выпускает
	// IPv6-трафик мимо туннеля: частично поднятый IPv6 хуже отсутствующего,
	// потому что утечка молчаливая — пользователь узнаёт о ней постфактум: T28.
	IPv6Block = &Policy{
		Name: "ipv6_block",
		Doc:  "IPv6 заблокирован, а не выпущен мимо туннеля (§6.9, T28)",
		Guards: []Guard{
			{Pkg: "./internal/loopguard", Test: "^TestT28IPv6IsBlocked$"},
		},
	}

	// EventBroadcast — рассылка событий всем подписчикам §3.3 (этап 9).
	// Выключение оставляет одного получателя, и второй клиент — трей рядом с
	// CLI — не узнаёт о переключении вовсе: TestTwoClientsBothGetEvent.
	EventBroadcast = &Policy{
		Name: "event_broadcast",
		Doc:  "события уходят всем подписчикам, а не одному (§3.3)",
		Guards: []Guard{
			{Pkg: "./internal/events", Test: "^TestTwoClientsBothGetEvent$"},
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
		ErrorClassify,
		KOfN,
		Tolerance,
		MultiURL,
		ForcedProbe,
		SwitchReason,
		ConfirmProbe,
		DNSCacheFlushOnSwitch,
		Bootstrap,
		MergeKey,
		LoopGuard,
		IPv6Block,
		EventBroadcast,
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
