package events

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/tunnel"
)

// stubAgent — агент без агента: сокет проверяется отдельно от датаплейна
// (§8.1).
type stubAgent struct {
	status Status
	nodes  []NodeInfo
	auto   bool
	bypass bool
}

func (a *stubAgent) Status() Status      { return a.status }
func (a *stubAgent) Nodes() []NodeInfo   { return a.nodes }
func (a *stubAgent) Pin(id string) error { a.status.ActiveNode = id; return nil }
func (a *stubAgent) Auto(on bool)        { a.auto = on }
func (a *stubAgent) Bypass(on bool)      { a.bypass = on }
func (a *stubAgent) Ping(id string) (NodeInfo, error) {
	return NodeInfo{ID: id, State: health.Alive}, nil
}

// Состав узлов этому двойнику не нужен: он проверяет поток событий, а не
// каталог. Отдельный catalogStub ниже отвечает за шесть команд §С2.
func (a *stubAgent) SubAdd(string, string) (SubResult, error) { return SubResult{}, nil }
func (a *stubAgent) SubUpdate(string) ([]SubResult, error)    { return nil, nil }
func (a *stubAgent) SubRemove(string) error                   { return nil }
func (a *stubAgent) SubList() []GroupInfo                     { return nil }
func (a *stubAgent) NodeAdd(string) (NodeInfo, error)         { return NodeInfo{}, nil }
func (a *stubAgent) NodeRemove(string) (string, error)        { return "", nil }

func serve(t *testing.T, a Agent) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.sock")
	srv, err := Serve(path, a, -1)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, path
}

// follow подключает клиента и вычитывает поток событий в буфер.
func follow(t *testing.T, path string) <-chan Event {
	t.Helper()
	cl, err := Dial(path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { cl.Close() })
	if err := cl.Follow(); err != nil {
		t.Fatalf("Follow: %v", err)
	}
	ch := make(chan Event, subBuffer)
	go func() {
		for {
			ev, err := cl.Next()
			if err != nil {
				close(ch)
				return
			}
			ch <- ev
		}
	}()
	return ch
}

// TestTwoClientsBothGetEvent — §3.3: подключился второй клиент, событие
// получают оба.
//
// Охраняет политику event_broadcast: при HOP_DISABLE=event_broadcast рассылка
// вырождается в одного подписчика, и второй клиент не дожидается события.
func TestTwoClientsBothGetEvent(t *testing.T) {
	srv, path := serve(t, &stubAgent{})
	first := follow(t, path)
	second := follow(t, path)

	want := Event{
		Phase:  tunnel.Up,
		Switch: &Switch{FromNode: "n1", ToNode: "n2", Reason: health.ReasonDead, InterruptedConnections: 3},
	}
	for i, ch := range []<-chan Event{first, second} {
		got := await(t, srv, ch, want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("клиент %d получил %+v, ожидалось %+v", i+1, got, want)
		}
	}
}

// await шлёт событие, пока клиент его не увидит: подписка доезжает до хаба
// асинхронно, и тест не должен зависеть от того, кто успел раньше.
func await(t *testing.T, srv *Server, ch <-chan Event, ev Event) Event {
	t.Helper()
	clk := clock.System{}
	for i := 0; i < 400; i++ {
		srv.Publish(ev)
		select {
		case got, ok := <-ch:
			if !ok {
				t.Fatal("поток событий закрылся")
			}
			return got
		case <-clk.After(5 * time.Millisecond):
		}
	}
	t.Fatal("клиент не получил событие")
	return Event{}
}

// TestSlowSubscriberIsDropped — второе свойство §3.3: медленный клиент не
// тормозит остальных и не растит память без предела.
func TestSlowSubscriberIsDropped(t *testing.T) {
	h := NewHub()
	slow := h.Subscribe()
	fast := h.Subscribe()

	ev := Event{Phase: tunnel.Up}
	for i := 0; i < subBuffer+5; i++ {
		h.Publish(ev)
		select {
		case <-fast.C():
		default:
			t.Fatalf("быстрый подписчик не получил событие %d", i)
		}
	}

	var got int
	for range slow.C() {
		got++
	}
	if got > subBuffer {
		t.Fatalf("у отставшего накопилось %d событий при буфере %d", got, subBuffer)
	}
}

// TestRequestResponse — команды §5.9 доезжают до агента.
func TestRequestResponse(t *testing.T) {
	a := &stubAgent{
		status: Status{Phase: tunnel.Up, ActiveNode: "n1"},
		nodes:  []NodeInfo{{ID: "n1", State: health.Alive, Supported: true}},
	}
	_, path := serve(t, a)

	call := func(f func(cl *Client) error) {
		t.Helper()
		cl, err := Dial(path)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer cl.Close()
		if err := f(cl); err != nil {
			t.Fatalf("вызов: %v", err)
		}
	}

	call(func(cl *Client) error {
		st, err := cl.Status()
		if err == nil && st.ActiveNode != "n1" {
			t.Fatalf("status вернул %+v", st)
		}
		return err
	})
	call(func(cl *Client) error {
		ns, err := cl.Nodes()
		if err == nil && (len(ns) != 1 || ns[0].ID != "n1") {
			t.Fatalf("nodes вернул %+v", ns)
		}
		return err
	})
	call(func(cl *Client) error { return cl.Bypass(true) })
	call(func(cl *Client) error { return cl.Auto(false) })
	if !a.bypass || a.auto {
		t.Fatalf("агент не увидел команд: bypass=%v auto=%v", a.bypass, a.auto)
	}
}

// catalogStub — агент, у которого состав узлов есть, но датаплейна нет.
type catalogStub struct {
	stubAgent
	added   string
	name    string
	updated string
	removed string
	link    string
	dropped string
	groups  []GroupInfo
}

func (a *catalogStub) SubAdd(url, name string) (SubResult, error) {
	a.added, a.name = url, name
	return SubResult{GroupID: "ee8e3a30", GroupName: "sub.example", Added: 2, Unsupported: 1}, nil
}

func (a *catalogStub) SubUpdate(id string) ([]SubResult, error) {
	a.updated = id
	return []SubResult{{GroupID: "ee8e3a30", Kept: 2}}, nil
}

func (a *catalogStub) SubRemove(id string) error { a.removed = id; return nil }
func (a *catalogStub) SubList() []GroupInfo      { return a.groups }

func (a *catalogStub) NodeAdd(link string) (NodeInfo, error) {
	a.link = link
	return NodeInfo{ID: "n9", Name: "Прага", Group: "manual", Supported: true}, nil
}

func (a *catalogStub) NodeRemove(id string) (string, error) {
	a.dropped = id
	return "ee8e3a30", nil
}

// §3.3: состав узлов правит агент, а не клиент. Шесть команд обязаны доехать по
// сокету целиком — вместе с аргументами и вместе с ответом, иначе клиенту
// пришлось бы лезть в стор, до которого он под своим UID не достаёт (§6.8).
func TestCatalogCommandsCrossTheSocket(t *testing.T) {
	a := &catalogStub{groups: []GroupInfo{{ID: "ee8e3a30", Name: "sub.example", Nodes: 2}}}
	_, path := serve(t, a)

	// Одно соединение — одна команда (шапка пакета), поэтому клиент на каждую
	// свой. Тест, переиспользовавший соединение, ловил бы broken pipe и читался
	// бы как дефект сервера.
	cl := func() *Client {
		c, err := Dial(path)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}

	res, err := cl().SubAdd("https://sub.example/list", "мои")
	if err != nil {
		t.Fatalf("SubAdd: %v", err)
	}
	if a.added != "https://sub.example/list" || a.name != "мои" {
		t.Fatalf("до агента доехало url=%q name=%q", a.added, a.name)
	}
	if res.Added != 2 || res.Unsupported != 1 || res.GroupID != "ee8e3a30" {
		t.Fatalf("сводка не доехала обратно: %+v", res)
	}

	if _, err := cl().SubUpdate("ee8e3a30"); err != nil {
		t.Fatalf("SubUpdate: %v", err)
	}
	if a.updated != "ee8e3a30" {
		t.Fatalf("id подписки не доехал: %q", a.updated)
	}

	groups, err := cl().SubList()
	if err != nil {
		t.Fatalf("SubList: %v", err)
	}
	if len(groups) != 1 || groups[0].Nodes != 2 {
		t.Fatalf("список подписок не доехал: %+v", groups)
	}

	if err := cl().SubRemove("ee8e3a30"); err != nil {
		t.Fatalf("SubRemove: %v", err)
	}
	if a.removed != "ee8e3a30" {
		t.Fatalf("id на удаление не доехал: %q", a.removed)
	}

	n, err := cl().NodeAdd("vless://x@c.example:443#Прага")
	if err != nil {
		t.Fatalf("NodeAdd: %v", err)
	}
	if a.link != "vless://x@c.example:443#Прага" || n.Name != "Прага" {
		t.Fatalf("ссылка=%q, узел=%+v", a.link, n)
	}

	from, err := cl().NodeRemove("n9")
	if err != nil {
		t.Fatalf("NodeRemove: %v", err)
	}
	if a.dropped != "n9" || from != "ee8e3a30" {
		t.Fatalf("удаление: до агента %q, обратно подписка %q", a.dropped, from)
	}
}

// Ошибка агента доезжает до клиента ошибкой, а не пустым успехом: `sub add` с
// недоступным адресом обязан быть виден как отказ.
func TestCatalogErrorReachesClient(t *testing.T) {
	_, path := serve(t, &failingCatalog{})
	cl, err := Dial(path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()

	if _, err := cl.SubAdd("https://sub.example/list", ""); err == nil ||
		!strings.Contains(err.Error(), "сеть недоступна") {
		t.Fatalf("ошибка агента не доехала: %v", err)
	}
}

type failingCatalog struct{ catalogStub }

func (a *failingCatalog) SubAdd(string, string) (SubResult, error) {
	return SubResult{}, errors.New("сеть недоступна")
}

// §3.3: сокет агента лежит не в каталоге пользователя, а на общем пути с
// правами группы `hop` — под системным пользователем (§6.8) агент до `$HOME`
// клиента не дотянется, а клиент до каталога агента.
//
// Права даёт сам сокет, а не каталог. Прежде наоборот: каталог 0700 закрывал и
// сокет, и лежащий рядом attach-token. Каталог, открытый группе, открыл бы ей
// заодно и токен, а §6.14 требует ровно обратного — членство в группе даёт
// сокет, но не ключи.
func TestSocketOpensToGroupAndNotToEveryone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("права unix-сокета: на Windows граница выражена ACL трубы")
	}
	path := filepath.Join(t.TempDir(), "agent.sock")
	// Собственная группа процесса: chown в неё не требует прав, а проверяется
	// решение — какие биты выставлены, — а не то, кому машина их выдала.
	srv, err := Serve(path, &stubAgent{}, os.Getgid())
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("сокет: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o660 {
		t.Fatalf("права сокета %04o, ожидалось 0660 — группе rw, остальным ничего", perm)
	}
}

// Без группы сокет остаётся у одного владельца: так он поднимается в отладке и
// на стенде, и лишний бит там опаснее, чем неудобство.
func TestSocketWithoutGroupStaysPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("права unix-сокета: на Windows граница выражена ACL трубы")
	}
	path := filepath.Join(t.TempDir(), "agent.sock")
	srv, err := Serve(path, &stubAgent{}, -1)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("сокет: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("права сокета %04o, ожидалось 0600", perm)
	}
}
