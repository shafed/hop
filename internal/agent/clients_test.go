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
