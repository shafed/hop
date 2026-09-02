package agent

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/ipc"
)

// Граница «клиенты ↔ агент» (§3.3) — W60–W62.
//
// Проверяется на настоящем сокете, а не на подставленном соединении: форма
// границы и есть предмет проверки. Прав для этого не нужно — unix-сокет в
// каталоге теста, — и в этом же весь довод против TCP (§6.1): право «мой и
// больше ничей» здесь даёт файловая система.

// serveClients поднимает сервер §3.3 на сокете во временном каталоге.
func serveClients(t *testing.T, api ClientAPI) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "agent.sock")
	l, err := ipc.Listen(path, -1)
	if err != nil {
		t.Fatalf("сокет клиентов не открылся: %v", err)
	}
	srv := NewClientServer(api, nil)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() {
		_ = l.Close()
		srv.Close()
	})
	return path
}

// sub — клиент, подписанный на поток событий.
type sub struct {
	name string
	cl   *Client
	ev   chan ClientEvent
}

func newSub(t *testing.T, name, path string) *sub {
	t.Helper()

	cl, err := DialClient(path)
	if err != nil {
		t.Fatalf("%s не подключился: %v", name, err)
	}
	t.Cleanup(func() { _ = cl.Close() })

	s := &sub{name: name, cl: cl, ev: make(chan ClientEvent, 16)}
	go func() {
		_ = cl.Events(true, func(e ClientEvent) error {
			s.ev <- e
			return nil
		})
	}()
	return s
}

// waitEvent ждёт событие с потолком: без потолка невыполненное обещание
// вешает прогон вместо того, чтобы покраснеть.
func (s *sub) waitEvent(t *testing.T, what string) ClientEvent {
	t.Helper()
	select {
	case e := <-s.ev:
		return e
	case <-time.After(watchdog): //hop:realtime
		t.Fatalf("%s не получил %s", s.name, what)
		return ClientEvent{}
	}
}

// TestW60EventReachesEverySubscriber — событие переключения доходит до ВСЕХ
// подписчиков сокета §3.3, а не до одного.
//
// §3.3 требует этого прямо и с первого дня: «в v1 это один CLI, но позже к
// нему подключатся GUI и трей одновременно. События рассылаются всем
// подписчикам, а не одному». Проверять это потом нельзя: сокет, написанный на
// одного клиента, отличается от сокета на многих не строчкой, а формой —
// подпиской, которая живёт на сервере вместо соединения.
//
// Подписка каждого клиента подтверждается накопленным событием ДО того, как
// появится проверяемое: иначе тест сравнивал бы не рассылку, а то, кто успел
// подписаться первым.
//
// Краснеет без event_broadcast: живая подписка остаётся одна, и второй клиент
// получает историю и молчание.
func TestW60EventReachesEverySubscriber(t *testing.T) {
	r := newRig(t, "a", "b")
	r.start()

	// Стартовый выбор — первое событие; оно же подтвердит подписку.
	first := r.a.Snapshot().Active
	if first == "" {
		t.Fatal("стартовый раунд не выбрал узла: проверять рассылку нечем")
	}
	path := serveClients(t, r.a)

	one := newSub(t, "первый клиент", path)
	if ev := one.waitEvent(t, "накопленного события"); ev.To != first {
		t.Fatalf("первый клиент получил историю про %q, а активен %q", ev.To, first)
	}
	two := newSub(t, "второй клиент", path)
	if ev := two.waitEvent(t, "накопленного события"); ev.To != first {
		t.Fatalf("второй клиент получил историю про %q, а активен %q", ev.To, first)
	}

	// Переключение: фиксация другого узла (§1/С3) — единственное событие,
	// которое можно вызвать без сдвига часов и без смерти узла.
	other := "a"
	if first == "a" {
		other = "b"
	}
	if err := r.a.Pin(other); err != nil {
		t.Fatalf("узел не зафиксировался: %v", err)
	}

	for _, s := range []*sub{one, two} {
		ev := s.waitEvent(t, "события переключения")
		if ev.To != other {
			t.Errorf("%s получил переключение на %q, а фиксировался %q", s.name, ev.To, other)
		}
		if ev.Reason != health.ReasonManual.String() {
			t.Errorf("%s получил причину %q, а фиксация — manual", s.name, ev.Reason)
		}
	}
}

// TestW61StatusCarriesBothPhasesAndPin — снимок §3.3 несёт всю картину §1/С5.
//
// Ровно то, чего у `hop status` не было до сокета: фазу трафика, активный узел
// с латентностью, счётчик живых, состояние автоматики и фиксацию. Каждое поле
// проверяется на значении, а не на присутствии: пустое поле — это ответ
// «трафика нет», и от «не знаю» его в выводе не отличить.
func TestW61StatusCarriesBothPhasesAndPin(t *testing.T) {
	r := newRig(t, "a", "b")
	r.start()
	if err := r.a.Up(); err != nil {
		t.Fatalf("туннель не поднялся: %v", err)
	}

	cl, err := DialClient(serveClients(t, r.a))
	if err != nil {
		t.Fatalf("клиент не подключился: %v", err)
	}
	defer cl.Close()

	st, err := cl.Status()
	if err != nil {
		t.Fatalf("состояние не пришло: %v", err)
	}
	if st.Tunnel != "up" {
		t.Errorf("фаза туннеля %q, ожидалась up", st.Tunnel)
	}
	if st.Traffic != string(PhaseProxied) {
		t.Errorf("фаза трафика %q, ожидалась %q", st.Traffic, PhaseProxied)
	}
	if st.Active == "" {
		t.Fatal("активного узла нет, хотя раунд прошёл и узлы живы")
	}
	if st.ActiveState != health.Alive.String() {
		t.Errorf("живость активного узла %q, ожидалась alive", st.ActiveState)
	}
	if st.Alive != 2 || st.Nodes != 2 {
		t.Errorf("живых %d из %d, ожидалось 2 из 2", st.Alive, st.Nodes)
	}
	if !st.Auto {
		t.Error("автопереключение выключено, хотя его никто не выключал")
	}
	if st.Pinned != "" {
		t.Errorf("узел %q зафиксирован, хотя фиксации не было", st.Pinned)
	}
	if st.Last == nil || st.Last.To != st.Active {
		t.Errorf("последнее переключение %+v не сходится с активным узлом %q", st.Last, st.Active)
	}

	// Фиксация §1/С3: автоматика выключается, и снимок обязан назвать узел
	// отдельно — «зафиксирован» и «просто активен» требуют от человека разного.
	if err := r.a.Pin("b"); err != nil {
		t.Fatalf("узел не зафиксировался: %v", err)
	}
	st, err = cl.Status()
	if err != nil {
		t.Fatalf("состояние не пришло: %v", err)
	}
	if st.Auto {
		t.Error("после фиксации автопереключение осталось включённым")
	}
	if st.Pinned != "b" {
		t.Errorf("зафиксирован %q, ожидался b", st.Pinned)
	}
}

// TestW62ControlVerbsReachTheAgent — управляющие глаголы §5.9 доходят до
// связки и меняют её состояние.
//
// Через настоящий сокет и с проверкой по снимку связки, а не по ответу
// сервера: «ответ пришёл без ошибки» — это утверждение о протоколе, а глаголы
// §5.9 обещают действие.
func TestW62ControlVerbsReachTheAgent(t *testing.T) {
	r := newRig(t, "a", "b")
	r.start()

	cl, err := DialClient(serveClients(t, r.a))
	if err != nil {
		t.Fatalf("клиент не подключился: %v", err)
	}
	defer cl.Close()

	// up: туннель берётся у сервиса.
	if err := cl.Up(""); err != nil {
		t.Fatalf("`up` отказал: %v", err)
	}
	if acq, _ := r.tr.counts(); acq != 1 {
		t.Fatalf("после `up` туннель взят %d раз, ожидался один", acq)
	}

	// up --node: фиксация (§1/С3).
	if err := cl.Up("b"); err != nil {
		t.Fatalf("`up --node b` отказал: %v", err)
	}
	if snap := r.a.Snapshot(); snap.Active != "b" || snap.Auto {
		t.Errorf("после `up --node b` активен %q, автоматика %v", snap.Active, snap.Auto)
	}

	// auto on: автоматика возвращается.
	if err := cl.Auto(true); err != nil {
		t.Fatalf("`auto on` отказал: %v", err)
	}
	if snap := r.a.Snapshot(); !snap.Auto || snap.Pinned != "" {
		t.Errorf("после `auto on` автоматика %v, фиксация %q", snap.Auto, snap.Pinned)
	}

	// bypass on: обход снимает туннель (Р35) и меняет фазу трафика.
	if err := cl.Bypass(true); err != nil {
		t.Fatalf("`bypass on` отказал: %v", err)
	}
	if snap := r.a.Snapshot(); snap.Traffic != PhaseBypass {
		t.Errorf("после `bypass on` фаза трафика %q, ожидалась %q", snap.Traffic, PhaseBypass)
	}
	if err := cl.Bypass(false); err != nil {
		t.Fatalf("`bypass off` отказал: %v", err)
	}
	if snap := r.a.Snapshot(); snap.Traffic == PhaseBypass {
		t.Error("после `bypass off` фаза трафика осталась bypass")
	}

	// down: туннель отдан.
	if err := cl.Down(); err != nil {
		t.Fatalf("`down` отказал: %v", err)
	}
	if snap := r.a.Snapshot(); snap.Traffic == PhaseProxied {
		t.Error("после `down` трафик всё ещё идёт через узел")
	}
}

// TestW62EventsWithoutFollowEndOnTheirOwn — `hop events` без `--follow`
// кончается сам.
//
// Отдельно от W60, потому что это другое свойство: поток закрывается кадром
// «конец», а не обрывом соединения. Без него клиент не отличает «история
// кончилась» от «сервер задумался» и ждёт вечно — команда, которая не
// возвращается, ломает любой скрипт вокруг себя.
func TestW62EventsWithoutFollowEndOnTheirOwn(t *testing.T) {
	r := newRig(t, "a")
	r.start()

	cl, err := DialClient(serveClients(t, r.a))
	if err != nil {
		t.Fatalf("клиент не подключился: %v", err)
	}
	defer cl.Close()

	done := make(chan []ClientEvent, 1)
	go func() {
		var got []ClientEvent
		if err := cl.Events(false, func(e ClientEvent) error {
			got = append(got, e)
			return nil
		}); err != nil {
			t.Errorf("`events` отказал: %v", err)
		}
		done <- got
	}()

	select {
	case got := <-done:
		if len(got) == 0 {
			t.Fatal("история пуста, хотя стартовый выбор был")
		}
		if got[len(got)-1].To != r.a.Snapshot().Active {
			t.Errorf("последнее событие про %q, а активен %q", got[len(got)-1].To, r.a.Snapshot().Active)
		}
	case <-time.After(watchdog): //hop:realtime
		t.Fatal("`events` без --follow не вернулся")
	}
}

// TestW66NodesCarryLiveHealthNotTheDiskSlice — `hop nodes` через сокет §3.3
// показывает живость связки, а не срез с диска.
//
// Это и есть настоящая причина, по которой список узлов уехал за сокет, — и
// она не та, которую называл прежний HANDOFF. Замер (implementation-notes.md,
// «Замер: держит ли агент flock всю жизнь») показал, что стор читается БЕЗ
// замка и `hop nodes` при живом агенте не отказывает. Отказа нет, а вот
// устаревание есть и оно измерено: на диск живость попадает не чаще раза в
// healthDebounce и переписывается тикером healthPersistEvery — по тридцать
// секунд, — так что клиент, читающий стор напрямую, видит состояние
// получасовой давности ровно тогда, когда актуальное есть у того, кого он не
// спросил.
//
// Проверяется на настоящей связке, а не на заглушке: предмет проверки —
// откуда связка берёт живость, и заглушка отвечала бы за неё сама.
//
// Краснеет, если Agent.Nodes вернётся к живости стора: тогда обе картины
// совпадут, и «свежая» перестанет отличаться от «лежащей на диске».
func TestW66NodesCarryLiveHealthNotTheDiskSlice(t *testing.T) {
	r := newRig(t, "n1", "n2")
	r.prob.set("n1", health.Result{RTT: 42 * time.Millisecond})
	r.prob.set("n2", health.Result{RTT: 77 * time.Millisecond})
	r.start()
	// Стартовое переключение пишет живость в стор последней своей реакцией
	// (Р33, persistNow). Без этого ожидания срез ниже кладётся в гонку с ней, и
	// связка перетирает его живыми значениями: под нагрузкой тест краснел
	// «срез на диске не лёг: узел n1 = "alive", 42 мс» — то есть на СВОЁМ
	// стенде, а не на предмете проверки.
	r.waitReaction("persist")

	// На диске — срез, записанный до последних проб: узлы там мертвы, и
	// латентность у них другая. Срез кладётся руками, а не вылёживается
	// тридцать секунд фейкового времени, по той же причине, по которой стенд
	// кладёт узлы через seedStore: проверяется не тикер, а то, у КОГО связка
	// спрашивает живость. Состояние это штатное — ровно так стор и выглядит
	// весь промежуток между записями (§2, healthDebounce).
	r.st.PutHealth([]health.NodeHealth{
		{NodeID: "n1", State: health.Dead, RTT: 999 * time.Millisecond},
		{NodeID: "n2", State: health.Dead, RTT: 999 * time.Millisecond},
	})
	onDisk := map[string]string{}
	onDiskRTT := map[string]int64{}
	for _, g := range r.st.FullView(nil) {
		for _, n := range g.Nodes {
			onDisk[n.ID], onDiskRTT[n.ID] = n.State, n.RTTMs
		}
	}
	for _, id := range []string{"n1", "n2"} {
		if onDisk[id] != health.Dead.String() || onDiskRTT[id] != 999 {
			t.Fatalf("срез на диске не лёг: узел %s = %q, %d мс", id, onDisk[id], onDiskRTT[id])
		}
	}

	live := map[string]int64{}
	states := map[string]string{}
	groups := r.a.Nodes()
	if len(groups) != 1 {
		t.Fatalf("групп %d, ожидалась 1", len(groups))
	}
	for _, n := range groups[0].Nodes {
		live[n.ID] = n.RTTMs
		states[n.ID] = n.State
	}

	for id, want := range map[string]int64{"n1": 42, "n2": 77} {
		if states[id] != health.Alive.String() {
			t.Errorf("узел %s: связка отдала состояние %q, живость знает %q",
				id, states[id], health.Alive)
		}
		if live[id] != want {
			t.Errorf("узел %s: связка отдала %d мс, проба измерила %d мс", id, live[id], want)
		}
		// Вторая половина утверждения: на диске в этот момент лежит другое.
		// Без неё тест был бы зелен и тогда, когда связка читает стор, —
		// достаточно было бы стору успеть записать ту же живость.
		if onDisk[id] == states[id] {
			t.Errorf("узел %s: диск и связка говорят одно и то же (%q) — "+
				"сравнивать нечего, проверка стала пустой", id, onDisk[id])
		}
	}
}

// TestW66NodesReachTheClientThroughTheSocket — список узлов доезжает до
// клиента §3.3 целиком и в порядке Р8.
//
// Отдельно от W65 (`cmd/hop`), потому что это другая половина: там
// проверяется команда и её `--json`, здесь — что кадры потока склеиваются
// обратно в те же группы с тем же составом. Порядок принадлежит провайдеру
// (Р8), и поток, перепутавший узлы местами, был бы зелен по количеству.
func TestW66NodesReachTheClientThroughTheSocket(t *testing.T) {
	r := newRig(t, "n1", "n2", "n3")
	r.start()

	path := serveClients(t, r.a)
	cl, err := DialClient(path)
	if err != nil {
		t.Fatalf("клиент не подключился: %v", err)
	}
	defer cl.Close()

	got, err := cl.Nodes()
	if err != nil {
		t.Fatalf("список узлов не приехал: %v", err)
	}
	want := r.a.Nodes()
	if len(got) != len(want) {
		t.Fatalf("групп приехало %d, у связки %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Group != want[i].Group {
			t.Errorf("группа %d приехала другой:\nбыло:  %+v\nстало: %+v", i, want[i].Group, got[i].Group)
		}
		if len(got[i].Nodes) != len(want[i].Nodes) {
			t.Fatalf("в группе %s узлов приехало %d, у связки %d",
				want[i].Group.ID, len(got[i].Nodes), len(want[i].Nodes))
		}
		for j := range want[i].Nodes {
			if got[i].Nodes[j] != want[i].Nodes[j] {
				t.Errorf("узел %d группы %s приехал другим:\nбыло:  %+v\nстало: %+v",
					j, want[i].Group.ID, want[i].Nodes[j], got[i].Nodes[j])
			}
		}
	}
}
