package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"time"

	"github.com/shafed/hop/internal/agent"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/policy"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/tunnel"
)

// Формирование вывода читающих команд §5.9 — одна точка на весь бинарь.
//
// Одна, а не по одной на команду. Это прямое требование S33 регистра стора
// («проверка держится на функции формирования вывода, а не на команде») и
// единственный способ закрепить схему целиком: пока точек несколько, схема
// разъезжается по одной команде за раз, и каждый такой разъезд зелен для всех
// проверок, кроме той, что смотрит именно на эту команду. Держит это не
// договорённость, а TestW58JSONHasOneFormationPoint — он разбирает AST пакета.
//
// Второе следствие той же формы: человеческий вывод и машинный собираются из
// ОДНОГО значения. Иначе они расходятся молча — в таблице поле есть, в JSON
// его забыли, — и заметить это можно только сравнив два куска кода глазами.

// view — то, что показала одна читающая команда.
//
// Text печатает человеку, encoding/json — машине, и поля у них общие по
// построению.
type view interface {
	Text(io.Writer)
}

// emit — единственная точка формирования вывода (§5.9).
//
// Отказ вместо человеческого текста при выключенной политике намеренный:
// «--json молча напечатал таблицу» — худший из ответов, потому что вызывающая
// автоматика получит нулевой код и неразбираемый вход.
func emit(out io.Writer, v view, asJSON bool) error {
	if !asJSON {
		v.Text(out)
		return nil
	}
	if !policy.JSONSchema.On() {
		return errors.New("машинный вывод выключен политикой json_schema")
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// nodesOut — вывод `hop nodes` (§1/С2).
//
// Узлы и группы берутся готовыми из store.NodeView и store.GroupView: список
// показываемых полей — явное перечисление того, что показывать МОЖНО (Р12,
// §6.14), и живёт оно в сторе, где его сторожит S33. Повторить его здесь
// значило бы завести второй экземпляр правды про секреты.
type nodesOut struct {
	Groups []groupOut `json:"groups"`
}

type groupOut struct {
	// Group и Nodes рядом, а не встроенной структурой: у GroupView есть своё
	// поле nodes — счётчик, — и встраивание молча заслонило бы его списком.
	Group store.GroupView  `json:"group"`
	Nodes []store.NodeView `json:"nodes"`
}

func (v nodesOut) Text(out io.Writer) {
	if len(v.Groups) == 0 {
		fmt.Fprintln(out, "стор пуст: добавьте подписку через `hop sub add <url>` или узел через `hop node add <ссылка>`")
		return
	}
	for _, g := range v.Groups {
		fmt.Fprintf(out, "группа %s (%d узлов)\n", g.Group.ID, g.Group.Nodes)
		for _, n := range g.Nodes {
			mark := " "
			if !n.Supported {
				mark = "×"
			}
			fmt.Fprintf(out, "  %s %-12s %-20s %s:%d  %s\n", mark, n.ID, n.Name, n.Server, n.Port, n.State)
		}
	}
}

// nodesView собирает вывод `hop nodes` из стора.
//
// Группы берутся из store.StatusView, а не собираются здесь по store.Group:
// форматирование времени и выбор показываемых полей — работа стора, и второй
// её экземпляр в cmd/hop разошёлся бы с первым молча.
func nodesView(st *store.Store) nodesOut {
	groups := st.StatusView("").Groups
	v := nodesOut{Groups: make([]groupOut, 0, len(groups))}
	for _, g := range groups {
		v.Groups = append(v.Groups, groupOut{Group: g, Nodes: st.NodesView(g.ID)})
	}
	return v
}

// statusOut — вывод `hop status` (§1/С5).
//
// Две половины, и ровно одна из них непуста: та, чей адресат ответил.
//
// Спрашивается связка (§3.3). Она знает обе фазы §2, активный узел, живость и
// кольцо событий — всё, чего у `hop status` не было, пока сокета не
// существовало. Стор она при этом уже открыла, и это второй довод, а не
// первый: стор держит эксклюзивный flock всё время жизни агента, поэтому
// команда, которая на пути к ответу открывает стор сама, отказывает ровно
// тогда, когда `status` нужнее всего — при поднятом туннеле.
//
// Сервис (§3.1) остаётся запасным адресатом для одного состояния, и оно
// названо: `orphaned` (§6.2). Там связки нет по определению — ребро в
// orphaned и есть смерть её соединения, — а туннель жив, и остаток до снятия
// знает только сервис. Двух половин сразу поэтому не бывает: пока связка
// отвечает, клиент к привилегированному сервису не ходит вовсе (§3.3).
//
// null у половины означает «этот не отвечал», а не «нечего показать». Пустое
// поле вместо отсутствующего знания читалось бы как «трафика нет», а это
// другое утверждение.
type statusOut struct {
	// Tunnel — то, что сказал сервис. Непусто, только когда молчит связка.
	Tunnel *tunnelOut `json:"tunnel"`
	// Agent — то, что сказала связка. Схема — `agent.ClientStatus`: второй
	// экземпляр той же структуры здесь разошёлся бы с первым молча, ровно как
	// перечень полей узла, который `hop nodes` берёт готовым из store.NodeView.
	Agent *agent.ClientStatus `json:"agent"`
}

type tunnelOut struct {
	Phase        string `json:"phase"`
	Device       string `json:"device,omitempty"`
	DetachReason string `json:"detach_reason,omitempty"`
	// OrphanLeft строкой, а не наносекундами: число секунд в JSON пришлось бы
	// сопровождать единицей измерения где-то ещё, а «12s» несёт её сам.
	OrphanLeft string `json:"orphan_left"`
}

func (v statusOut) Text(out io.Writer) {
	if v.Agent == nil {
		v.textFromService(out)
		return
	}
	a := v.Agent
	fmt.Fprintf(out, "туннель: %s\n", a.Tunnel)
	fmt.Fprintf(out, "трафик:  %s\n", trafficLine(a.Traffic))
	if a.Active == "" {
		fmt.Fprintln(out, "активного узла нет")
	} else {
		fmt.Fprintf(out, "активный узел: %s (%s", a.Active, a.ActiveState)
		if a.ActiveRTTMs > 0 {
			fmt.Fprintf(out, ", %d мс", a.ActiveRTTMs)
		}
		fmt.Fprintln(out, ")")
	}
	fmt.Fprintf(out, "живых узлов: %d из %d\n", a.Alive, a.Nodes)

	// Фиксация — отдельной строкой, потому что §1/С3 буквальна:
	// зафиксированный узел не заменяется, даже когда умирает.
	if a.Pinned != "" {
		fmt.Fprintf(out, "узел зафиксирован: %s — он не будет заменён, даже если умрёт (§1/С3)\n", a.Pinned)
	} else if !a.Auto {
		fmt.Fprintln(out, "автопереключение выключено")
	}
	if a.Last != nil {
		fmt.Fprintf(out, "последнее переключение: %s → %s, причина %s, порвано соединений %d, %s\n",
			orNone(a.Last.From), a.Last.To, a.Last.Reason, a.Last.Interrupted,
			a.Last.At.Format(time.RFC3339))
	}
	if a.Detached != "" {
		fmt.Fprintf(out, "связи с сервисом нет: %s\n", a.Detached)
	}
}

// textFromService — картина, которую видно без связки.
//
// Она заведомо неполная, и команда говорит об этом словами: поле, которого
// нет, честнее пустого поля, которое читается как «трафика нет».
func (v statusOut) textFromService(out io.Writer) {
	if v.Tunnel == nil {
		fmt.Fprintln(out, "ни связка, ни сервис не ответили")
		return
	}
	fmt.Fprintf(out, "туннель: %s", v.Tunnel.Phase)
	if v.Tunnel.Device != "" {
		fmt.Fprintf(out, ", устройство %s", v.Tunnel.Device)
	}
	if v.Tunnel.DetachReason != "" {
		fmt.Fprintf(out, ", причина отсоединения %s, до снятия %s",
			v.Tunnel.DetachReason, v.Tunnel.OrphanLeft)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "отвечал сервис, а не связка: фаза трафика, активный узел и")
	fmt.Fprintln(out, "автоматика ему неизвестны (§3.1) — их знает `hop agent`, а он не отвечает")
}

// trafficLine — фаза трафика словами. Значения §2 машинам понятны, человеку —
// не сами по себе: `failing` и `waiting` различаются знанием, а не буквами.
func trafficLine(p string) string {
	switch p {
	case string(agent.PhaseProxied):
		return "proxied — идёт через активный узел"
	case string(agent.PhaseWaiting):
		return "waiting — узлы ещё не проверены, трафик ждёт (стартовый бюджет §5.6)"
	case string(agent.PhaseFailing):
		return "failing — живых узлов нет, трафик заблокирован (fail-close §5.6)"
	case string(agent.PhaseBypass):
		return "bypass — выпущен мимо туннеля осознанно (§1/С6)"
	case "":
		return "неизвестна"
	default:
		return p
	}
}

func tunnelView(st tunnel.State) tunnelOut {
	return tunnelOut{
		Phase:        string(st.Phase),
		Device:       st.Device,
		DetachReason: string(st.DetachReason),
		OrphanLeft:   st.OrphanLeft.String(),
	}
}

// eventsOut — вывод `hop events` (§1/С5).
//
// Журнал одним значением; поток `--follow` печатается по событию (eventOut),
// потому что конца у него нет и срезом он невыразим. Схема при этом одна: то
// же значение, та же единственная точка формирования.
type eventsOut struct {
	Events []agent.ClientEvent `json:"events"`
}

func (v eventsOut) Text(out io.Writer) {
	if len(v.Events) == 0 {
		fmt.Fprintln(out, "переключений не было")
		return
	}
	for _, ev := range v.Events {
		eventOut{ev}.Text(out)
	}
}

// eventOut — одно событие потока.
type eventOut struct {
	agent.ClientEvent
}

func (v eventOut) Text(out io.Writer) {
	fmt.Fprintf(out, "%s  %s → %s  причина %s, порвано соединений %d\n",
		v.At.Format(time.RFC3339), orNone(v.From), v.To, v.Reason, v.Interrupted)
}

// probeOut — вывод `hop probe` (§5.4, §6.7).
type probeOut struct {
	Nodes []probeNodeOut `json:"nodes"`
	// Alive — сколько узлов ответило. Ноль — это код возврата 3, а не ошибка
	// команды: см. errNoLiveNodes.
	Alive int `json:"alive"`
}

type probeNodeOut struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Server string `json:"server"`
	Port   int    `json:"port"`
	Alive  bool   `json:"alive"`
	RTTMs  int64  `json:"rtt_ms,omitempty"`
	Error  string `json:"error,omitempty"`
}

func (v probeOut) Text(out io.Writer) {
	for _, n := range v.Nodes {
		name := n.Name
		if name == "" {
			name = n.ID[:min(8, len(n.ID))]
		}
		if !n.Alive {
			fmt.Fprintf(out, "✗ %-20s %s:%d — %s\n", name, n.Server, n.Port, n.Error)
			continue
		}
		fmt.Fprintf(out, "✓ %-20s %s:%d — %d мс\n", name, n.Server, n.Port, n.RTTMs)
	}
}

// routingOut — вывод `hop routing` (§6.10, §5.7).
//
// Показывается не файл, а то, что из файла следует, и двумя половинами:
// слияние конфигурации с исключениями §5.6 живёт в netstack (resolveRouting) и
// наружу не вынесено, а переписать его здесь значило бы завести второй
// экземпляр правды — тот самый, который расходится молча.
type routingOut struct {
	File string `json:"file"`
	// Defaults — настоящие netstack.DefaultRouting(), а не список, переписанный
	// сюда руками.
	Defaults listsOut `json:"defaults"`
	// Configured — nil означает «раздела routing в файле нет», и это не то же
	// самое, что пустые списки: пустые означают, что пользователь убрал
	// обнаружение служб сознательно (§6.10). Поэтому omitempty здесь нет —
	// null в выводе несёт смысл.
	Configured   *listsOut `json:"configured"`
	DNSUpstreams []string  `json:"dns_upstreams"`
}

type listsOut struct {
	Bypass []ruleOut `json:"bypass"`
	Block  []ruleOut `json:"block"`
}

// ruleOut — правило §6.10 в той же форме, в какой оно лежит в settings.json.
//
// Отсутствующее поле значит «любой», ровно как во входном файле: вторая
// договорённость про то же самое разошлась бы с первой. Человеческий вывод при
// этом печатает звёздочку — там отсутствие поля не выразить.
type ruleOut struct {
	Prefix string `json:"prefix,omitempty"`
	Proto  string `json:"proto,omitempty"`
	Port   uint16 `json:"port,omitempty"`
}

func (v routingOut) Text(out io.Writer) {
	fmt.Fprintf(out, "файл настроек: %s\n", v.File)

	fmt.Fprintln(out, "\nумолчания §6.10 — то, что действует, когда раздела routing в файле нет:")
	printRules(out, "bypass", v.Defaults.Bypass)
	printRules(out, "block", v.Defaults.Block)

	fmt.Fprintln(out)
	if v.Configured == nil {
		fmt.Fprintln(out, "раздела routing в файле нет: действуют умолчания выше.")
	} else {
		fmt.Fprintln(out, "раздел routing в файле есть, в нём:")
		printRules(out, "bypass", v.Configured.Bypass)
		printRules(out, "block", v.Configured.Block)
		fmt.Fprintln(out, "\nчто стек сделает с этим списком:")
		fmt.Fprintln(out, "  исключения §5.6 — локальные сети, DHCP, NTP — подмешиваются к bypass всегда")
		fmt.Fprintln(out, "  и конфигурацией не убираются: «разрешены всегда» относится и к неудачному конфигу;")
		fmt.Fprintln(out, "  обнаружение служб (mDNS 224.0.0.251:5353, SSDP 239.255.255.250:1900) — наоборот,")
		fmt.Fprintln(out, "  умолчание, а не пол: раз раздел routing задан, оно действует только если выписано")
		fmt.Fprintln(out, "  в bypass явно.")
	}

	fmt.Fprintln(out)
	if len(v.DNSUpstreams) == 0 {
		fmt.Fprintln(out, "раздела dns_upstreams в файле нет: действуют стартовые апстримы §5.7.")
	} else {
		fmt.Fprintln(out, "апстримы §5.7 из файла:")
		for _, up := range v.DNSUpstreams {
			fmt.Fprintf(out, "  %s\n", up)
		}
	}
}

// settingsView собирает вывод `hop routing` из стора.
func settingsView(st *store.Store, path string) routingOut {
	set := st.Settings()
	v := routingOut{
		File:         path,
		Defaults:     rulesView(netstack.DefaultRouting()),
		DNSUpstreams: []string{},
	}
	for _, up := range set.DNSUpstreams {
		v.DNSUpstreams = append(v.DNSUpstreams, up.String())
	}
	if set.Routing != nil {
		lists := rulesView(set.Routing)
		v.Configured = &lists
	}
	return v
}

func rulesView(r *netstack.Routing) listsOut {
	return listsOut{Bypass: ruleList(r.Bypass), Block: ruleList(r.Block)}
}

func ruleList(rules []netstack.Rule) []ruleOut {
	out := make([]ruleOut, 0, len(rules))
	for _, r := range rules {
		o := ruleOut{Port: r.Port}
		if r.Prefix.IsValid() {
			o.Prefix = r.Prefix.String()
		}
		switch r.Proto {
		case netstack.ProtoTCP:
			o.Proto = "tcp"
		case netstack.ProtoUDP:
			o.Proto = "udp"
		}
		out = append(out, o)
	}
	return out
}

func printRules(out io.Writer, list string, rules []ruleOut) {
	if len(rules) == 0 {
		fmt.Fprintf(out, "  %s: пусто\n", list)
		return
	}
	fmt.Fprintf(out, "  %s:\n", list)
	for _, r := range rules {
		fmt.Fprintf(out, "    %s\n", ruleLine(r))
	}
}

// ruleLine — правило одной строкой. Ноль печатается звёздочкой, а не
// опускается: «любой порт» и «порт забыли» обязаны выглядеть по-разному.
func ruleLine(r ruleOut) string {
	prefix, proto, port := r.Prefix, r.Proto, "*"
	if prefix == "" {
		prefix = "*"
	}
	if proto == "" {
		proto = "*"
	}
	if r.Port != 0 {
		port = fmt.Sprint(r.Port)
	}
	return fmt.Sprintf("%-18s %-4s порт %s", prefix, proto, port)
}
