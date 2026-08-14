package events

import (
	"path/filepath"
	"reflect"
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

func serve(t *testing.T, a Agent) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.sock")
	srv, err := Serve(path, a)
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
