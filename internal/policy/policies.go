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
			{Pkg: "./internal/l2", Test: "^TestT16DNSToLocalRouterIsHijackedRealResolver$"},
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
		Doc:  "ошибки трафика §6.15 убивают узел наравне с пробами (A5, A29, W30)",
		// Третий охраняющий — сквозной, а не модульный: A5 и A29 зовут
		// ReportFailure сами, то есть проверяют политику от того места, куда
		// вердикт уже доехал. W30 начинает с SYN'а в датаплейне и проходит
		// связку целиком, поэтому выключенная политика краснит его по всей
		// длине пути, а не только в живости.
		Guards: []Guard{
			{Pkg: "./internal/health", Test: "^TestA5TrafficFailuresKillNode$"},
			{Pkg: "./internal/health", Test: "^TestA29SwitchUnderTrafficIsFast$"},
			{Pkg: "./internal/agent", Test: "^TestW30DialFailureFromDataplaneReachesHealth$"},
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

	// AtomicWrite — запись стора через временный файл рядом и rename (§2,
	// этап 7). Выключение переводит запись на место, с O_TRUNC: обрыв посреди
	// неё оставляет читаемым не прежнее состояние и не новое, а обрубок —
	// ровно третье наблюдаемое состояние, которого У4 не допускает. S25, S26.
	AtomicWrite = &Policy{
		Name: "atomic_write",
		Doc:  "запись стора временным файлом и rename, а не на месте (§2, S25, S26)",
		Guards: []Guard{
			{Pkg: "./internal/store", Test: "^TestS25FailureBetweenFsyncAndRenameKeepsOldState$"},
			{Pkg: "./internal/store", Test: "^TestS26FailureWhileWritingTempKeepsMainFile$"},
		},
	}

	// StoreLock — файловый замок каталога стора на время «прочитать —
	// изменить — записать» (Р14, этап 7). Писателей двое по построению: агент
	// пишет живость, процесс команды правит подписки (C12). Выключение не
	// отсекает второго, и одновременные правки теряют одну из них — файлы
	// пишутся целиком. S28.
	StoreLock = &Policy{
		Name: "store_lock",
		Doc:  "второй писатель в стор ждёт замок и падает внятно, а не пишет поверх (Р14, S28)",
		Guards: []Guard{
			{Pkg: "./internal/store", Test: "^TestS28SecondWriterWaitsThenFails$"},
		},
	}

	// HealthSlice — на диск идёт срез живости, а не вся NodeHealth (§2, этап
	// 7). Выключение пишет и восстанавливает окно, traffic_failures и
	// last_error: окно, пролежавшее выключенным час, воскрешает узел по §6.3 из
	// записей, которым час, а восстановленный alive выдаёт себя за проверенный —
	// стартовый бюджет §5.6 не отсчитывается заново. S36, S37.
	HealthSlice = &Policy{
		Name: "health_slice",
		Doc:  "на диск идёт срез живости, а не окно (§2, S36, S37)",
		Guards: []Guard{
			{Pkg: "./internal/store", Test: "^TestS36RestoredHealthHasNoWindow$"},
			{Pkg: "./internal/store", Test: "^TestS37RestoredAliveNodeCarriesNoProbe$"},
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

	// BypassSink — вердикт bypass выпускается настоящим NAT-путём через сокет,
	// привязанный к физическому интерфейсу (§6.10, §6.8). Выключение возвращает
	// молчаливый дроп: пакет уходит в никуда. T17 при этом остаётся зелёным —
	// он проверяет только вердикт, а не доставку.
	BypassSink = &Policy{
		Name: "bypass_sink",
		Doc:  "вердикт bypass уходит настоящим NAT-путём (§6.10, §6.8)",
		Guards: []Guard{
			{Pkg: "./internal/bypass", Test: "^TestBypassSendsDatagramFromBoundSocket$"},
			{Pkg: "./internal/bypass", Test: "^TestBypassReplyReturnsToClient$"},
		},
	}

	// BypassTCPReject — TCP в локальную сеть, который приёмник bypass не
	// несёт, получает RST, а не молчаливый дроп (§5.6, §6.10). Выключение
	// возвращает дроп: приложение висит до своего connect timeout, ровно то
	// поведение, из-за которого §5.6 написан. Краснит T33.
	//
	// Флаг свой, а не reject_mode: тот гасит **fail-close**, и в его doc так и
	// написано; здесь узлы живы, вердикт — bypass, и отказ означает «этим
	// путём такой поток не пройдёт», а не «выхода нет». Сосед по смыслу —
	// bypass_sink, тоже про путь bypass, тоже с молчаливым дропом в
	// выключенном состоянии; довод целиком — в implementation-notes.md.
	BypassTCPReject = &Policy{
		Name: "bypass_tcp_reject",
		Doc:  "TCP с вердиктом bypass получает RST, а не дроп (§5.6, §6.10, T33)",
		Guards: []Guard{
			{Pkg: "./internal/netstack", Test: "^TestT33TCPToLocalNetworkGetsRST$"},
		},
	}

	// BypassRebind — сокет bypass, привязанный к интерфейсу, который больше не
	// является исходящим, не переиспользуется: он закрывается, и следующий
	// Send заводит новый, привязанный к нынешнему интерфейсу («следствие
	// первое» §6.8 — привязка сокета неизменна, значит смена сети означает
	// передозвон). Выключение возвращает прежнее поведение: сокет живёт по
	// прежней привязке, пока клиент продолжает слать, — а уборка простоя его
	// не собирает никогда, потому что sock.seen обновляется на каждый Send.
	//
	// Флаг свой, а не bypass_sink: тот гасит путь bypass целиком (Send сразу
	// отдаёт ErrDisabled), и охраняющая перепривязку проверка покраснела бы
	// под ним по чужой причине — не «сокет не сменился», а «наружу вообще
	// ничего не ушло». Такая охрана ничего не охраняет; довод целиком — в
	// implementation-notes.md.
	BypassRebind = &Policy{
		Name: "bypass_rebind",
		Doc:  "сокет bypass переоткрывается при смене физического интерфейса (§6.8)",
		Guards: []Guard{
			{Pkg: "./internal/bypass", Test: "^TestBypassInterfaceChangeRebindsSocket$"},
			{Pkg: "./internal/agent", Test: "^TestBypassSocketRebindsOnInterfaceChange$"},
		},
	}

	// BypassIdleSweep — сокет bypass, простоявший без трафика дольше Idle,
	// закрывается сам: фоновый тикер на инъектируемых часах прокручивает
	// уборку, не дожидаясь ни Send, ни Close. Выключение возвращает прежнее
	// поведение — уборка едет только на Send, и клиент, который замолчал
	// навсегда (обнаружение служб закончилось, приложение вышло), оставляет
	// сокет и его горутину чтения жить до Close всего NAT.
	//
	// Флаг свой, а не bypass_sink и не bypass_rebind. bypass_sink гасит путь
	// целиком: под ним Send отдаёт ErrDisabled, сокета не заводится вовсе, и
	// охрана краснела бы по чужой причине — «нечего убирать» вместо «не
	// убрано». bypass_rebind закрывает сокет по смене интерфейса, то есть по
	// событию, а не по молчанию; его собственная проверка нарочно держит часы
	// стоящими, а эта нарочно их двигает при молчащем клиенте — слить их
	// значило бы потерять ту самую разницу, из-за которой уборка простоя не
	// годится на роль перепривязки
	// (TestBypassIdleSweepNeverCollectsSocketUnderTraffic).
	//
	// Что флаг НЕ гасит: прокрутку уборки внутри Send. Она старше этого
	// прохода, у неё своя зелёная проверка (TestBypassIdleClosesSocket), и
	// увести её под новый флаг значило бы выключать заодно проверенное
	// поведение — граница проходит ровно по фоновой половине.
	BypassIdleSweep = &Policy{
		Name: "bypass_idle_sweep",
		Doc:  "фоновая уборка простоя сокетов bypass при остановленном трафике (§5.3, W51)",
		Guards: []Guard{
			{Pkg: "./internal/bypass", Test: "^TestW51IdleSocketIsCollectedWithoutTraffic$"},
		},
	}

	// NATIdleSweep — та же уборка простоя, что у BypassIdleSweep, только для
	// natTable (§5.3, W59): запись и сокет, простоявшие без трафика дольше
	// UDPIdle, закрываются сами, фоновым тикером на инъектируемых часах, не
	// дожидаясь ни следующего пакета (mapping), ни внешнего Sweep(). До этой
	// политики natTable убирала простой только по чужому событию — natTable
	// была тем самым долгом, что прошлый проход назвал вслух, вынося ту же
	// уборку из bypass.NAT.
	//
	// Выключение возвращает прежнее поведение: клиент, который замолчал
	// навсегда, оставляет запись и сокет жить до close() всего стека.
	//
	// Флаг гасит только фоновую половину. Прокрутка внутри mapping() и
	// внешний Sweep() (нужен замеру B3) остаются включёнными при любом
	// состоянии флага — у них своя польза и свои зелёные проверки, и увести
	// их под новый флаг значило бы красить охрану за двоих.
	NATIdleSweep = &Policy{
		Name: "nat_idle_sweep",
		Doc:  "фоновая уборка простоя записей и сокетов natTable (§5.3, W59)",
		Guards: []Guard{
			{Pkg: "./internal/netstack", Test: "^TestW59IdleEntryIsCollectedWithoutTraffic$"},
		},
	}

	// IPv6Block — пока туннель поднят, IPv6 закрыт правилом маршрутизации
	// unreachable (§6.9). Выключение убирает шаг из Up, и IPv6 снова уходит
	// мимо туннеля через физический интерфейс — замер: при поднятом туннеле
	// `ip -6 route get` ведёт на veth0, соединение с внешним пиром
	// устанавливается и данные до него доходят.
	//
	// Флаг свой, а не snapshot_restore и не routing_lists. snapshot_restore
	// гасит откат, а не раскладку: под ним Up поставит правило IPv6 как ни в
	// чём не бывало, и T28 останется зелёным — то есть охраной он не работает
	// вовсе. routing_lists живёт уровнем ниже, в вердикте netstack, куда
	// IPv6-пакет не доходит и не может дойти: утечка идёт мимо TUN, стек её не
	// видит. Довод целиком — в implementation-notes.md.
	//
	// Охраняет её W48 (внепривилегированный: список шагов Up — чистая
	// функция) и T28 в internal/l3, который в реестре не назван по общему
	// правилу — negcheck гоняет `go test`, а L3 без HOP_L3 и netns
	// пропускается и был бы зелен при любом состоянии флага.
	IPv6Block = &Policy{
		Name: "ipv6_block",
		Doc:  "IPv6 закрыт правилом unreachable, пока туннель поднят (§6.9, T28, W48)",
		Guards: []Guard{
			{Pkg: "./internal/platform", Test: "^TestW48UpBlocksIPv6$"},
		},
	}

	// IPv6KillEstablished — соединения IPv6, установленные ДО подъёма
	// туннеля, получают отказ, а не молчание (§5.6, §6.9). Правило
	// `ip -6 rule unreachable` их не касается: замер — у установленного сокета
	// TCP `write` после правила возвращает успех (n=26, err=nil), а `read`
	// упирается в собственный таймаут. Утечки нет, есть молчание. Выключение
	// убирает из Up шаг зачистки, и такие сокеты снова висят до таймаута TCP.
	//
	// Флаг свой, а не `ipv6_block`, по тому же доводу, которым `bypass_rebind`
	// не стал частью `bypass_sink`: при `ipv6_block=off` правила нет вовсе,
	// значит и устаревшего сокета не возникнет, и охрана краснела бы по чужой
	// причине. Обратная зависимость при этом есть и она односторонняя: без
	// правила зачистка не просто бесполезна, а вредна — она рвала бы живые
	// работающие соединения. Поэтому шаг стоит в Up только когда включены оба.
	//
	// Охраняет её W50 (внепривилегированный: список шагов Up — чистая
	// функция) и L3-проверка того же номера в internal/l3, которая в реестре
	// не названа по общему правилу — negcheck гоняет `go test`, а L3 без
	// HOP_L3 и netns пропускается и был бы зелен при любом состоянии флага.
	IPv6KillEstablished = &Policy{
		Name: "ipv6_kill_established",
		Doc:  "соединения IPv6 старше туннеля разрушаются, а не молчат (§5.6, §6.9, W50)",
		Guards: []Guard{
			{Pkg: "./internal/platform", Test: "^TestW50UpSweepsSilencedIPv6$"},
		},
	}

	// RoutingLists — списки §6.10 приходят из конфигурации, а не зашиты в
	// verdict.go. Выключение возвращает жёсткий набор: конфиг игнорируется
	// целиком, и стек ведёт себя ровно как до этой политики. Краснеют оба
	// направления — добавленное конфигом правило (T32) и убранное из конфига
	// обнаружение служб, — потому что при выключенной политике конфиг не
	// читается вовсе. T17 и T31 при этом зелены при любом её состоянии: они
	// гоняют умолчания, а умолчания совпадают с прежним жёстким набором.
	RoutingLists = &Policy{
		Name: "routing_lists",
		Doc:  "списки bypass/block §6.10 приходят из конфигурации (§6.10, T32)",
		Guards: []Guard{
			{Pkg: "./internal/netstack", Test: "^TestRoutingBypassListComesFromConfig$"},
			{Pkg: "./internal/netstack", Test: "^TestRoutingConfigCanDropServiceDiscovery$"},
			{Pkg: "./internal/netstack", Test: "^TestT32ConfiguredBypassLeavesTunnel$"},
		},
	}

	// SettingsFile — настройки продукта читаются с диска: списки §6.10 и
	// апстримы §5.7 приезжают из settings.json, а не остаются полями
	// конфигурации, которые снаружи Go-кода никто не заполняет.
	//
	// Выключение возвращает состояние до этой политики: файл не читается
	// вовсе, Store.Settings отдаёт пустое, agent.Config.Routing и
	// agent.Config.DNSUpstreams остаются nil, и продукт живёт на умолчаниях
	// §6.10 и §5.7. Разбор и проверка файла при этом тоже не происходят —
	// нечего проверять там, где ничего не читают.
	//
	// Флаг свой, а не routing_lists: тот гасит вердикт netstack (конфигурация
	// игнорируется стеком), и охрана проброса краснела бы под ним по чужой
	// причине — не «диск не доехал», а «стек не смотрит». Флаг один на два
	// поля, а не два: это один механизм, один файл и один разбор, и выключить
	// половину значило бы описать состояние, которого продукт не имеет.
	//
	// Отказ на кривом файле (§5.6) флага не имеет намеренно: это обработка
	// ошибки, а не ветвление поведения, — тот же довод, по которому S29 и S30
	// не получили флага (docs/verification-store.md §6).
	SettingsFile = &Policy{
		Name: "settings_file",
		Doc:  "списки §6.10 и апстримы §5.7 читаются из settings.json (§6.10, §5.9, W52)",
		Guards: []Guard{
			{Pkg: "./internal/store", Test: "^TestS40SettingsCarryRoutingListsFromDisk$"},
			{Pkg: "./cmd/hop", Test: "^TestW52SettingsReachAgentRouting$"},
			{Pkg: "./cmd/hop", Test: "^TestW53SettingsReachAgentDNSUpstreams$"},
		},
	}

	// ExitCodes — коды возврата 0/1/2/3 различают отказ, отсутствие фоновой
	// половины и fail-close (§5.9). Выключение схлопывает карту до 0/1 —
	// ровно то состояние, в котором CLI жил до этапа 9: fail() отвечал
	// единицей на всё подряд, и мониторинг вокруг `hop status` был вынужден
	// разбирать текст, чтобы отличить «всё работает, живых узлов нет» от
	// «утилита упала».
	//
	// Граница флага — карта, а не сами отказы: команда отказывает одинаково
	// при любом его состоянии, меняется только число, которое видит вызывающий.
	// Поэтому охрана смотрит на четыре кода разом: ценность каждого в том, что
	// он отличается от соседнего, и проверять их поодиночке нечего.
	//
	// Что флаг НЕ гасит: границу «кривой settings.json — это 1, а не 3» (W57).
	// При выключенной политике все коды и так единицы, утверждение становится
	// истинным само собой, и краснеть той проверке нечем — охраной она поэтому
	// не служит.
	ExitCodes = &Policy{
		Name: "exit_codes",
		Doc:  "коды возврата 0/1/2/3: отказ, недоступность и fail-close различимы (§5.9, W56)",
		Guards: []Guard{
			{Pkg: "./cmd/hop", Test: "^TestW56ExitCodesTellRefusalFromFailClose$"},
		},
	}

	// JSONSchema — у читающих команд есть машинный вывод с закреплённой схемой
	// (§5.9). Выключение возвращает состояние до этапа 9: машинного вывода нет
	// вовсе, и `--json` отказывает вместо того, чтобы напечатать неизвестно
	// что. Молчаливый откат к человеческой таблице был бы худшим из ответов:
	// вызывающая автоматика получила бы нулевой код и неразбираемый вход.
	//
	// Флаг гасит подачу, а не сбор: значения читающих команд собираются и
	// печатаются человеку при любом его состоянии. Иначе охрана краснела бы за
	// двоих — «команда сломалась» вместо «схемы больше нет».
	JSONSchema = &Policy{
		Name: "json_schema",
		Doc:  "`--json` у читающих команд, схема закреплена проверкой (§5.9, §8.5, W58)",
		Guards: []Guard{
			{Pkg: "./cmd/hop", Test: "^TestW58JSONSchemaIsFixed$"},
		},
	}

	// EventBroadcast — события переключения рассылаются ВСЕМ подписчикам
	// сокета §3.3, а не одному. Требование стоит в §3.3 буквально: в v1
	// клиент один, но GUI и трей подключатся одновременно, и «сокет с первого
	// дня рассчитан на несколько одновременных клиентов».
	//
	// Выключение оставляет одну живую подписку на сервер: второй клиент
	// получает историю и молчание. Это не выдуманное состояние, а та форма, к
	// которой приводит один канал событий на всех, — и снаружи она выглядит
	// хуже поломки: `hop events --follow` во втором окне не отказывает, он
	// просто ничего не показывает, пока переключения идут.
	//
	// Флаг гасит рассылку, а не кольцо: история отдаётся при любом его
	// состоянии, и `hop events` без `--follow` работает одинаково. Иначе
	// охрана краснела бы за двоих — «событий нет вовсе» вместо «событие ушло
	// одному».
	EventBroadcast = &Policy{
		Name: "event_broadcast",
		Doc:  "события переключения уходят всем подписчикам сокета §3.3, а не одному (§3.3, W60)",
		Guards: []Guard{
			{Pkg: "./internal/agent", Test: "^TestW60EventReachesEverySubscriber$"},
		},
	}

	// XrayDrain — дренаж прежнего инстанса Xray при смене набора узлов
	// (§5.8, Р32 регистра связки, этап С). Выключение убивает прежний инстанс
	// сразу, и обновление подписки рвёт живые соединения — а §5.5 обещает
	// рвать только по причине dead. Краснит W18, W20, W21.
	XrayDrain = &Policy{
		Name: "xray_drain",
		Doc:  "дренаж прежнего инстанса Xray при смене набора узлов (§5.8, T30, W18)",
		Guards: []Guard{
			{Pkg: "./internal/agent", Test: "^TestW18SubscriptionUpdateKeepsConnection$"},
			{Pkg: "./internal/agent", Test: "^TestW20DrainEndsWithLastConnection$"},
		},
	}

	// SwitchOrder — зафиксированный порядок реакций на переключение
	// (Р33 регистра связки). Выключение переставляет сброс кэша резолвера
	// после рассылки события: клиент, реагирующий на событие повторным
	// резолвом, получает адрес, добытый через мёртвый узел, и §5.7(в)
	// оказывается выполнен формально. Краснит W11, W13, W14.
	SwitchOrder = &Policy{
		Name: "switch_order",
		Doc:  "порядок реакций на переключение: кэш, разрыв, событие, диск (Р33, W11)",
		Guards: []Guard{
			{Pkg: "./internal/agent", Test: "^TestW11SwitchReactionsFollowOrder$"},
			{Pkg: "./internal/agent", Test: "^TestW13CacheFlushPrecedesEvent$"},
		},
	}

	// PhaseSplit — две фазы вместо одной (§2, D14). Выключение сводит их в
	// одну, и «туннель поднят, живых узлов нет» перестаёт быть выразимым:
	// снаружи видна половина правды. Краснит W24, W32.
	PhaseSplit = &Policy{
		Name: "phase_split",
		Doc:  "фаза туннеля и фаза трафика — раздельно (§2, W24, W32)",
		Guards: []Guard{
			{Pkg: "./internal/agent", Test: "^TestW24TunnelUpWithNoLiveNodes$"},
			{Pkg: "./internal/agent", Test: "^TestW32StartupBudgetIsWaiting$"},
		},
	}

	// BypassTeardown — `hop bypass --on` снимает туннель (Р35 регистра связки).
	// Выключение оставляет туннель поднятым, и «выпустить трафик напрямую»
	// (§1/С6) перестаёт что-либо выпускать: маршруты по-прежнему ведут в
	// туннель. Краснит W25, W26.
	BypassTeardown = &Policy{
		Name: "bypass_teardown",
		Doc:  "обход снимает туннель, а не разворачивает трафик внутри (§5.6, W25)",
		Guards: []Guard{
			{Pkg: "./internal/agent", Test: "^TestW25BypassTakesTunnelDown$"},
			{Pkg: "./internal/agent", Test: "^TestW26BypassOffRaisesTunnel$"},
		},
	}

	// --- Этап 6, DNS (docs/verification-dns.md §6). Десять флагов на этап —
	// много, и это осознанно: negcheck гоняет каждый охранник дважды, а список
	// сжат тем, что в Guards стоят только зарегистрированные охранники.

	// Bootstrap — имена узлов резолвятся отдельным резолвером мимо туннеля
	// (§5.7а, §6.8). Выключение отправляет их общим путём, через туннель, —
	// то есть через резолвер, которому для работы нужен живой узел, которого
	// нет, пока имя не разрешилось. Это петля старта, а не деградация.
	Bootstrap = &Policy{
		Name: "bootstrap",
		Doc:  "имена узлов резолвит bootstrap мимо туннеля (§5.7а, D51, D52)",
		Guards: []Guard{
			{Pkg: "./internal/resolver", Test: "^TestD51NodeNameResolvesViaBootstrap$"},
			{Pkg: "./internal/resolver", Test: "^TestD52BootstrapGoesDirect$"},
		},
	}

	// DNSUpstream — апстримов два, второй с форой 150 мс (§5.7). Выключение
	// оставляет один, и блокировка единственного апстрима означает мёртвый DNS
	// при полностью живом узле — та же ошибка, против которой стоит multi_url
	// в пробах.
	DNSUpstream = &Policy{
		Name: "dns_upstream",
		Doc:  "два апстрима, второй с форой 150 мс (§5.7, D41, D42)",
		Guards: []Guard{
			{Pkg: "./internal/resolver", Test: "^TestD41FastFirstUpstreamSkipsSecond$"},
			{Pkg: "./internal/resolver", Test: "^TestD42SilentFirstFallsToSecond$"},
		},
	}

	// DNSTCPRetry — флаг TC от апстрима означает повтор по TCP (§5.7).
	// Выключение отдаёт клиенту усечённое: большие RRset молча теряют записи,
	// и приложение видит часть адресов вместо всех.
	DNSTCPRetry = &Policy{
		Name: "dns_tcp_retry",
		Doc:  "повтор по TCP на флаг TC, а не усечённый ответ (§5.7, D33)",
		Guards: []Guard{
			{Pkg: "./internal/resolver", Test: "^TestD33TruncatedAnswerRetriesOverTCP$"},
			{Pkg: "./internal/l2", Test: "^TestD33TruncatedAnswerRetriesOverTCPRealNode$"},
		},
	}

	// DNSCacheFlushOnSwitch — кэш сбрасывается при смене того, через что мы
	// резолвим: и на событии переключения узла (§5.7в), и на краю bypass
	// (Р25). Выключение снимает оба сброса, и после переключения трафик уходит
	// в CDN чужого региона по адресу, добытому через прежний узел.
	//
	// Один флаг на два повода, а не два: Р25 говорит, что край bypass
	// сбрасывает кэш «так же, как смена узла», — значит и выключаться они
	// обязаны вместе. Флаг про то, сбрасываем ли мы кэш, а не про то, какой
	// провод об этом сообщил.
	DNSCacheFlushOnSwitch = &Policy{
		Name: "dns_cache_flush_on_switch",
		Doc:  "сброс кэша при смене узла и на краю bypass (§5.7в, Р25, T14, D19, D20)",
		Guards: []Guard{
			{Pkg: "./internal/resolver", Test: "^TestD19SwitchBumpsGeneration$"},
			{Pkg: "./internal/resolver", Test: "^TestD20BypassEdgesFlushTwice$"},
			{Pkg: "./internal/l2", Test: "^TestT14SwitchResolvesToNewIP$"},
		},
	}

	// DNSFailClose — нет живых узлов, нет резолва (§5.7б, Р15). Выключение
	// заставляет резолвер отвечать и без живых узлов: приложение получает
	// адреса и виснет на connect, то есть молчание §5.6 сдвигается на шаг
	// дальше вместо того, чтобы стать отказом.
	DNSFailClose = &Policy{
		Name: "dns_failclose",
		Doc:  "SERVFAIL без живых узлов, и кэш при этом не отдаётся (Р15, D9–D11, D17)",
		Guards: []Guard{
			{Pkg: "./internal/resolver", Test: "^TestD9FailingPhaseAnswersServfail$"},
			{Pkg: "./internal/resolver", Test: "^TestD10FailClosePreventsCacheHit$"},
		},
	}

	// DNSWaitingHold — в стартовом окне §5.6 запрос ждёт живого узла, но не
	// дольше 4 с (Р16). Выключение отвечает SERVFAIL сразу, и приложение,
	// стартовавшее вместе с агентом, получает отказ там, где через секунду всё
	// работало.
	DNSWaitingHold = &Policy{
		Name: "dns_waiting_hold",
		Doc:  "удержание запроса в фазе waiting до 4 с (Р16, D12, D13)",
		Guards: []Guard{
			{Pkg: "./internal/resolver", Test: "^TestD12WaitingHoldsUntilNodeAppears$"},
			{Pkg: "./internal/resolver", Test: "^TestD13WaitingGivesUpAtFourSeconds$"},
		},
	}

	// DNSAAAANodata — при заблокированном IPv6 (§6.9) на AAAA синтезируется
	// пустой NOERROR (Р19). Выключение отправляет AAAA наверх и отдаёт адреса,
	// которые §6.9 дропает молча, — приложение платит за это таймаутом Happy
	// Eyeballs на каждом соединении.
	DNSAAAANodata = &Policy{
		Name: "dns_aaaa_nodata",
		Doc:  "AAAA отвечается пустым NOERROR, наверх не идёт (Р19, D45, D46)",
		Guards: []Guard{
			{Pkg: "./internal/resolver", Test: "^TestD45AAAAIsSynthesizedNodata$"},
			{Pkg: "./internal/resolver", Test: "^TestD46AAAANodataKeepsAWorking$"},
		},
	}

	// DNSNegativeCache — NXDOMAIN и NODATA кэшируются (Р18). Выключение
	// отправляет через узел каждый запрос приложения, ищущего несуществующее
	// имя в цикле, — самый дешёвый способ превратить резолвер в источник
	// трафика.
	DNSNegativeCache = &Policy{
		Name: "dns_negative_cache",
		Doc:  "отрицательные ответы кэшируются по SOA (Р18, D26–D28)",
		Guards: []Guard{
			{Pkg: "./internal/resolver", Test: "^TestD26NXDomainCachedBySOAMinimum$"},
			{Pkg: "./internal/resolver", Test: "^TestD28NodataCachedLikeNXDomain$"},
		},
	}

	// DNSSingleFlight — одинаковые вопросы в полёте склеиваются (Р24).
	// Выключение отправляет наверх каждый клиентский запрос своим: один старт
	// браузера даёт десятки одинаковых вопросов и столько же ассоциаций UDP
	// через узел — ровно та деградация, которую меряет B3.
	DNSSingleFlight = &Policy{
		Name: "dns_single_flight",
		Doc:  "одинаковые вопросы в полёте склеиваются (Р24, D38)",
		Guards: []Guard{
			{Pkg: "./internal/resolver", Test: "^TestD38IdenticalQuestionsCoalesce$"},
		},
	}

	// DNSSwitchRetry — запрос, застигнутый переключением узла, повторяется
	// ровно один раз через нового активного (Р20). Выключение отдаёт SERVFAIL:
	// каждое переключение стоит отказа тем запросам, которые как раз летели.
	DNSSwitchRetry = &Policy{
		Name: "dns_switch_retry",
		Doc:  "один повтор запроса, застигнутого переключением (Р20, D16)",
		Guards: []Guard{
			{Pkg: "./internal/resolver", Test: "^TestD16SwitchMidResolveRetriesOnce$"},
		},
	}

	// AutoconnectState — состояние §6.13 в сторе гейтит первый `a.Up()` при
	// старте `hop agent` (cmd/hop/main.go, shouldAutoUp). Выключение
	// возвращает поведение, которое было в продукте до этого прохода: агент
	// поднимает туннель безусловно, что бы ни лежало в settings.json.
	AutoconnectState = &Policy{
		Name: "autoconnect_state",
		Doc:  "автоподключение при старте агента читает store.Settings, а не поднимает туннель безусловно (§6.13, W67)",
		Guards: []Guard{
			{Pkg: "./cmd/hop", Test: "^TestW67AutoconnectSettingGatesInitialUp$"},
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
		BypassSink,
		BypassTCPReject,
		BypassRebind,
		BypassIdleSweep,
		NATIdleSweep,
		NATKey,
		RoutingLists,
		SettingsFile,
		ExitCodes,
		JSONSchema,
		EventBroadcast,
		IPv6Block,
		IPv6KillEstablished,
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
		AtomicWrite,
		StoreLock,
		HealthSlice,
		XrayDrain,
		SwitchOrder,
		PhaseSplit,
		BypassTeardown,
		Bootstrap,
		DNSUpstream,
		DNSTCPRetry,
		DNSCacheFlushOnSwitch,
		DNSFailClose,
		DNSWaitingHold,
		DNSAAAANodata,
		DNSNegativeCache,
		DNSSingleFlight,
		DNSSwitchRetry,
		AutoconnectState,
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
