// Тождество узла при слиянии — docs/verification-store.md §5.1. T* — номера из
// §8.3 спеки, S* — из регистра. Всё здесь уровня L1: чистая функция, ни диска,
// ни сети, ни часов.
package subscription

import (
	"fmt"
	"strings"
	"testing"

	"github.com/shafed/hop/internal/store"
)

const (
	uuidA = "11111111-1111-1111-1111-111111111111"
	uuidB = "22222222-2222-2222-2222-222222222222"
)

// seqIDs — детерминированный генератор id. Слияние берёт генератор снаружи
// именно ради этого: со случайностью внутри проверки тождества узла зависели бы
// от неё, а не от ключа §6.16.
func seqIDs(prefix string) func() string {
	n := 0
	return func() string {
		n++
		return fmt.Sprintf("%s%d", prefix, n)
	}
}

// parsed разбирает набор ссылок и требует, чтобы все они стали узлами: тесты
// слияния не про разбор, и молча потерянная ссылка испортила бы их незаметно.
func parsed(t *testing.T, links ...string) Parsed {
	t.Helper()
	p, err := Parse([]byte(strings.Join(links, "\n")))
	if err != nil {
		t.Fatalf("ссылки не разобрались: %v", err)
	}
	if len(p.Nodes) != len(links) {
		t.Fatalf("узлов %d, ссылок %d: часть входа потерялась на разборе", len(p.Nodes), len(links))
	}
	return p
}

// firstImport — импорт в пустую группу, то состояние, с которым сравнивается
// второй.
func firstImport(t *testing.T, group string, gen func() string, links ...string) []store.Node {
	t.Helper()
	return Diff(group, nil, parsed(t, links...), gen).Nodes
}

// nodeByID — узел из состава по id.
func nodeByID(nodes []store.Node, id string) (store.Node, bool) {
	for _, n := range nodes {
		if n.ID == id {
			return n, true
		}
	}
	return store.Node{}, false
}

func idsOf(nodes []store.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	return out
}

func mustEqual(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %v, ожидалось %v", what, got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s = %v, ожидалось %v", what, got, want)
			return
		}
	}
}

// --- 5.1 Тождество узла при слиянии (У1) --------------------------------

// T18: узел остался, сменился SNI — тот же id, то есть история проб остаётся за
// ним. Половина проверки, которая про сохранность самой истории, ждёт
// store.Apply: здесь тождество, там персистентность.
//
// Охраняет merge_key: с выключенной политикой ключом становится полный
// отпечаток узла, правка SNI даёт новый узел, и история обнуляется.
func TestT18SNIChangeKeepsSameID(t *testing.T) {
	gen := seqIDs("n")
	before := firstImport(t, "sub", gen,
		"vless://"+uuidA+"@a.example.com:443?type=ws&security=tls&sni=one.example.org#a")
	id := before[0].ID

	m := Diff("sub", before, parsed(t,
		"vless://"+uuidA+"@a.example.com:443?type=ws&security=tls&sni=two.example.org#a"), gen)

	mustEqual(t, "Kept", m.Kept, []string{id})
	if len(m.Added) != 0 || len(m.Removed) != 0 {
		t.Errorf("Added %v, Removed %v: правка SNI — это тот же узел (§6.16)", m.Added, m.Removed)
	}
	if got := m.Nodes[0].Param("sni"); got != "two.example.org" {
		t.Errorf("sni = %q, ожидалось two.example.org: пришедшее переписывает прежнее", got)
	}
}

// S1: сменились транспорт и имя, адрес и uuid те же — тот же id, и Kept
// содержит именно его. Это и есть обещание §5.8: косметическая правка у
// провайдера не наблюдаема изнутри.
//
// Охраняет merge_key: с полным отпечатком смена транспорта даёт новый узел.
func TestS1TransportChangeKeepsID(t *testing.T) {
	gen := seqIDs("n")
	before := firstImport(t, "sub", gen,
		"vless://"+uuidA+"@a.example.com:443?type=ws&security=tls#staroe-imya")
	id := before[0].ID

	m := Diff("sub", before, parsed(t,
		"vless://"+uuidA+"@a.example.com:443?type=grpc&security=tls#novoe-imya"), gen)

	mustEqual(t, "Kept", m.Kept, []string{id})
	if len(m.Added) != 0 || len(m.Removed) != 0 {
		t.Errorf("Added %v, Removed %v: смена транспорта — это тот же узел (§6.16)", m.Added, m.Removed)
	}
	n := m.Nodes[0]
	if n.ID != id {
		t.Errorf("id %q, ожидался прежний %q", n.ID, id)
	}
	if n.Transport != "grpc" || n.Name != "novoe-imya" {
		t.Errorf("транспорт %q, имя %q: изменения провайдера обязаны доехать", n.Transport, n.Name)
	}
	if n.MergeKey != before[0].MergeKey {
		t.Errorf("ключ слияния сменился: %q против %q", n.MergeKey, before[0].MergeKey)
	}
}

// S2: сменился порт — новый узел, прежний в Removed. Порт входит в ключ §6.16,
// и другой порт означает другую точку входа, а не косметику.
func TestS2PortChangeCreatesNewNode(t *testing.T) {
	gen := seqIDs("n")
	before := firstImport(t, "sub", gen,
		"vless://"+uuidA+"@a.example.com:443?type=ws&security=tls#a")
	id := before[0].ID

	m := Diff("sub", before, parsed(t,
		"vless://"+uuidA+"@a.example.com:8443?type=ws&security=tls#a"), gen)

	mustEqual(t, "Removed", m.Removed, []string{id})
	if len(m.Added) != 1 {
		t.Fatalf("Added %v, ожидался ровно один новый узел", m.Added)
	}
	if m.Added[0] == id {
		t.Errorf("новому узлу достался прежний id %q", id)
	}
	if len(m.Kept) != 0 {
		t.Errorf("Kept %v, ожидалось пусто", m.Kept)
	}
}

// S3: два узла отличаются только user_id — это два узла с двумя историями.
// Единственное место, где склейка по адресу наблюдаема, и главная проверка
// таблицы §6.16.
//
// Охраняет merge_key_userid: с выключенной политикой ключ вырождается в один
// адрес, ключи совпадают, и второй узел на каждом обновлении получает новый id —
// то есть теряет историю, а первый забирает её себе.
func TestS3UserIDDistinguishesNodes(t *testing.T) {
	gen := seqIDs("n")
	links := []string{
		"vless://" + uuidA + "@a.example.com:443?type=ws&security=tls#a",
		"vless://" + uuidB + "@a.example.com:443?type=ws&security=tls#b",
	}

	before := firstImport(t, "sub", gen, links...)
	if len(before) != 2 {
		t.Fatalf("узлов %d, ожидалось 2", len(before))
	}
	if before[0].MergeKey == before[1].MergeKey {
		t.Fatalf("ключи слияния совпали (%q): узлы различаются ключом доступа", before[0].MergeKey)
	}
	if before[0].ID == before[1].ID {
		t.Fatalf("id совпали: %q", before[0].ID)
	}

	// Повторный импорт того же: оба узла обязаны пережить его целиком.
	m := Diff("sub", before, parsed(t, links...), gen)
	mustEqual(t, "Kept", m.Kept, idsOf(before))
	if len(m.Added) != 0 || len(m.Removed) != 0 {
		t.Errorf("Added %v, Removed %v: состав не менялся", m.Added, m.Removed)
	}
}

// S4: порядок узлов в подписке изменился — id сохранены, node_order переписан
// под новый порядок (Р8). Порядок принадлежит провайдеру, а не истории нашего
// стора: при равных rtt выигрывает первый по node_order (§6.4).
func TestS4OrderFollowsSubscription(t *testing.T) {
	gen := seqIDs("n")
	a := "vless://" + uuidA + "@a.example.com:443?type=ws&security=tls#a"
	b := "vless://" + uuidA + "@b.example.com:443?type=ws&security=tls#b"
	c := "vless://" + uuidA + "@c.example.com:443?type=ws&security=tls#c"

	before := firstImport(t, "sub", gen, a, b, c)
	byServer := map[string]string{}
	for _, n := range before {
		byServer[n.Server] = n.ID
	}

	m := Diff("sub", before, parsed(t, c, a, b), gen)

	if len(m.Added) != 0 || len(m.Removed) != 0 {
		t.Errorf("Added %v, Removed %v: переставили, а не поменяли", m.Added, m.Removed)
	}
	want := []string{byServer["c.example.com"], byServer["a.example.com"], byServer["b.example.com"]}
	mustEqual(t, "node_order", m.Order, want)
	mustEqual(t, "порядок состава", idsOf(m.Nodes), want)
}

// S5: одна и та же ссылка в двух группах — два узла с независимыми историями
// (Р9). Настоящий ключ — пара (group_id, merge_key): история проб измерена
// через провайдера, и перенос её между группами приписал бы одному провайдеру
// измерения другого.
//
// Узлы чужой группы во входе не сливаются и не удаляются: удалять чужое слияние
// права не имеет.
func TestS5SameLinkInTwoGroupsStaysTwoNodes(t *testing.T) {
	gen := seqIDs("n")
	link := "vless://" + uuidA + "@a.example.com:443?type=ws&security=tls#a"

	first := firstImport(t, "sub-one", gen, link)
	m := Diff("sub-two", first, parsed(t, link), gen)

	if len(m.Added) != 1 {
		t.Fatalf("Added %v, ожидался один новый узел во второй группе", m.Added)
	}
	if m.Added[0] == first[0].ID {
		t.Errorf("узел второй группы забрал id %q у первой", first[0].ID)
	}
	if len(m.Removed) != 0 {
		t.Errorf("Removed %v: узел чужой группы удалять нельзя", m.Removed)
	}
	if len(m.Nodes) != 1 || m.Nodes[0].GroupID != "sub-two" {
		t.Fatalf("состав второй группы %v: ожидался один свой узел", idsOf(m.Nodes))
	}
	if m.Nodes[0].MergeKey != first[0].MergeKey {
		t.Errorf("ключи разные (%q против %q): ссылка одна, разводит их группа, а не ключ",
			m.Nodes[0].MergeKey, first[0].MergeKey)
	}
}

// S6: из подписки исчез активный узел — он в Removed, состав группы состоит из
// остальных.
//
// Вторая половина строки регистра — «активный переизбран, событие переключения
// с from = он и reason: dead» — здесь не проверяется и проверяться не может:
// слияние событий не порождает, оно возвращает Removed. Переизбрание живёт в
// internal/health и подключается на шаге 5 вместе со store.Apply; это шов, а не
// пробел.
func TestS6ActiveNodeDisappearsFromSubscription(t *testing.T) {
	gen := seqIDs("n")
	a := "vless://" + uuidA + "@a.example.com:443?type=ws&security=tls#a"
	b := "vless://" + uuidA + "@b.example.com:443?type=ws&security=tls#b"

	before := firstImport(t, "sub", gen, a, b)
	active := before[0] // тот, что исчезнет

	m := Diff("sub", before, parsed(t, b), gen)

	mustEqual(t, "Removed", m.Removed, []string{active.ID})
	mustEqual(t, "Kept", m.Kept, []string{before[1].ID})
	if _, ok := nodeByID(m.Nodes, active.ID); ok {
		t.Errorf("исчезнувший узел %q остался в составе группы", active.ID)
	}
	if len(m.Nodes) != 1 || m.Nodes[0].Server != "b.example.com" {
		t.Errorf("состав группы %v: ожидался один узел b", idsOf(m.Nodes))
	}
}

// S7: слияние линейно по числу узлов (§4 регистра).
//
// Меряется не время, а работа: diff считает шаги, и шаг — это один взгляд на
// существующий узел. Линейное слияние тратит len(existing) + len(incoming),
// наивный двойной цикл — их произведение. Секундомер на 200 и 2000 узлах ловит
// то же самое, но мигает на загруженной машине и под -race, а предмет проверки
// — не скорость, а порядок роста.
func TestS7MergeIsLinear(t *testing.T) {
	sub := func(n int) Parsed {
		nodes := make([]Incoming, 0, n)
		for i := range n {
			nodes = append(nodes, Incoming{
				Protocol:  "vless",
				Server:    fmt.Sprintf("n%d.example.com", i),
				Port:      443,
				Transport: "ws",
				Security:  "tls",
				Params:    map[string]string{"uuid": fmt.Sprintf("11111111-1111-1111-1111-%012d", i)},
				Supported: true,
			})
		}
		return Parsed{Nodes: nodes}
	}

	measure := func(n int) int {
		gen := seqIDs("n")
		before := Diff("sub", nil, sub(n), gen)
		m, steps := diff("sub", before.Nodes, sub(n), gen)
		if len(m.Kept) != n {
			t.Fatalf("на %d узлах пережило обновление %d: счётчик мерил бы не ту работу", n, len(m.Kept))
		}
		return steps
	}

	small, large := measure(200), measure(2000)
	if small == 0 {
		t.Fatal("счётчик шагов не считает: проверка линейности пуста")
	}
	ratio := float64(large) / float64(small)
	if ratio > 20 {
		t.Errorf("шагов на 2000 узлах %d против %d на 200 — рост в %.0f раз, ожидалось около 10: слияние квадратично",
			large, small, ratio)
	}
}

// S8: повторное обновление без изменений — Added и Removed пусты. Вторая
// половина строки регистра («health.json не переписан») принадлежит стору и
// проверяется на шаге 5/6.
func TestS8RepeatedUpdateChangesNothing(t *testing.T) {
	gen := seqIDs("n")
	links := []string{
		"vless://" + uuidA + "@a.example.com:443?type=ws&security=tls#a",
		"vless://" + uuidB + "@b.example.com:443?type=grpc&security=reality&pbk=xxx#b",
	}
	before := firstImport(t, "sub", gen, links...)

	m := Diff("sub", before, parsed(t, links...), gen)

	if len(m.Added) != 0 || len(m.Removed) != 0 {
		t.Errorf("Added %v, Removed %v: подписка не менялась", m.Added, m.Removed)
	}
	mustEqual(t, "Kept", m.Kept, idsOf(before))
	mustEqual(t, "node_order", m.Order, idsOf(before))
}

// S9: в группе manual слияния нет (Р10). Два `hop node add` с одинаковой
// ссылкой дают два узла с разными id, а `hop node rm` убирает ровно один.
// Именно этим закрыт дефект C14: при слиянии два ручных узла с совпавшим ключом
// §6.16 были бы неразличимы, и удаление третьего переставило бы id у
// оставшихся.
func TestS9ManualGroupDoesNotMerge(t *testing.T) {
	gen := seqIDs("m")
	link := "vless://" + uuidA + "@a.example.com:443?type=ws&security=tls#ruchnoy"
	in := parsed(t, link).Nodes[0]

	first := Add(store.ManualGroupID, nil, in, gen)
	second := Add(store.ManualGroupID, first.Nodes, in, gen)

	if len(second.Nodes) != 2 {
		t.Fatalf("узлов %d, ожидалось 2: одинаковая ссылка не склеивается в manual", len(second.Nodes))
	}
	a, b := second.Nodes[0], second.Nodes[1]
	if a.ID == b.ID {
		t.Fatalf("оба узла получили id %q", a.ID)
	}
	if a.MergeKey != "" || b.MergeKey != "" {
		t.Errorf("ключи слияния %q и %q: в manual ключ не участвует ни в чём", a.MergeKey, b.MergeKey)
	}
	mustEqual(t, "Kept при добавлении", second.Kept, []string{a.ID})

	// Удаление по id: сосед сохраняет свой id, а не получает чужой.
	rm := Remove(second.Nodes, a.ID)
	mustEqual(t, "Removed", rm.Removed, []string{a.ID})
	mustEqual(t, "Kept", rm.Kept, []string{b.ID})
	if len(rm.Nodes) != 1 || rm.Nodes[0].ID != b.ID {
		t.Errorf("после удаления в группе %v, ожидался один узел %q", idsOf(rm.Nodes), b.ID)
	}

	// Diff в manual не применяется вовсе: состав остаётся нетронутым.
	kept := Diff(store.ManualGroupID, second.Nodes, parsed(t, link), gen)
	mustEqual(t, "состав manual после Diff", idsOf(kept.Nodes), idsOf(second.Nodes))
	if len(kept.Added) != 0 || len(kept.Removed) != 0 {
		t.Errorf("Diff тронул manual: Added %v, Removed %v", kept.Added, kept.Removed)
	}
}

// --- 5.2 Импорт не падает целиком (У2) ----------------------------------

// S13: сводка импорта сгруппирована по unsup_reason, а не одним числом (§1/С2).
// Пользователь спрашивает не «сколько», а «чего не хватает сборке», и разница
// между «пересобрать Xray» и «у провайдера битая ссылка» — это разные действия.
func TestS13ImportSummaryIsGroupedByReason(t *testing.T) {
	body := strings.Join([]string{
		"tuic://" + uuidA + "@t1.example.com:443#t1",
		"tuic://" + uuidB + "@t2.example.com:443#t2",
		"vless://" + uuidA + "@q.example.com:443?type=quic&security=tls#q",
		"vless://a.example.com:443?type=ws&security=tls#bez-uuid",
		"ne ssylka vovse",
		"vless://" + uuidA + "@ok.example.com:443?type=ws&security=tls#ok",
	}, "\n")

	p, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("импорт упал целиком: %v", err)
	}

	m := Diff("sub", nil, p, seqIDs("n"))

	want := map[store.UnsupReason]int{
		store.UnsupProtocol:  2,
		store.UnsupTransport: 1,
		store.UnsupParse:     2, // ссылка без uuid и строка, не ставшая узлом
	}
	if len(m.Unsupported) != len(want) {
		t.Fatalf("сводка %v, ожидалась %v", m.Unsupported, want)
	}
	for reason, n := range want {
		if got := m.Unsupported[reason]; got != n {
			t.Errorf("причина %v: %d, ожидалось %d (сводка %v)", reason, got, n, m.Unsupported)
		}
	}
	if m.Unsupported[store.UnsupNone] != 0 {
		t.Errorf("поддержанные узлы попали в сводку: %v", m.Unsupported)
	}
	if len(m.Nodes) != 5 {
		t.Errorf("узлов %d, ожидалось 5: неподдержанный узел всё равно узел (§6.11)", len(m.Nodes))
	}
}
