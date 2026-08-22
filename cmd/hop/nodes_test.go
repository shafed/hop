package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/store"
)

const (
	uuidA = "11111111-1111-1111-1111-111111111111"
	uuidB = "22222222-2222-2222-2222-222222222222"
)

func subBody() string {
	return strings.Join([]string{
		"vless://" + uuidA + "@a.example.com:443?type=ws&security=tls#a",
		"vless://" + uuidB + "@b.example.com:443?type=ws&security=tls#b",
	}, "\n")
}

// withTestStore направляет стор в каталог теста. Проверки обязаны идти
// параллельно и не трогать настоящий стор разработчика.
func withTestStore(t *testing.T) string {
	t.Helper()
	root := t.TempDir() + "/store"
	t.Setenv("HOP_STORE", root)
	return root
}

// TestW41SubReachesDisk — `-sub` доводит ссылку до диска.
//
// Проверяется весь конвейер этапа 7 разом — скачать, разобрать, слить,
// записать, — потому что до этапа С его не проходил ни один бинарь: пакеты
// были зелены, а вызывающего у них не было.
func TestW41SubReachesDisk(t *testing.T) {
	root := withTestStore(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, subBody())
	}))
	defer srv.Close()

	if err := withStore(func(st *store.Store) error {
		return addSubscription(context.Background(), st, srv.URL, io.Discard, srv.Client())
	}); err != nil {
		t.Fatalf("подписка не доехала: %v", err)
	}

	// Стор перечитывается заново: «доехало до диска» означает переживший
	// закрытие файл, а не поле в памяти.
	st, err := store.Open(root, clock.System{})
	if err != nil {
		t.Fatalf("стор не открылся: %v", err)
	}
	defer st.Close()

	groups := st.Groups()
	if len(groups) != 1 {
		t.Fatalf("групп %d, ожидалась 1", len(groups))
	}
	nodes := st.Nodes(groups[0].ID)
	if len(nodes) != 2 {
		t.Fatalf("узлов %d, ожидалось 2", len(nodes))
	}
	for _, n := range nodes {
		if !n.Supported {
			t.Errorf("узел %s помечен неподдержанным, а vless+ws+tls поддержан", n.ID)
		}
	}
}

// TestW41SubTwiceKeepsOneGroup — повторный `-sub` с той же ссылкой обновляет
// ту же группу, а не заводит вторую.
//
// Иначе слияние §6.16 не увидело бы прежних узлов, и каждое обновление
// подписки теряло бы всю историю проб — то самое, ради сохранения которой §5.8
// отказывается от полной замены.
func TestW41SubTwiceKeepsOneGroup(t *testing.T) {
	root := withTestStore(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, subBody())
	}))
	defer srv.Close()

	for i := 0; i < 2; i++ {
		if err := withStore(func(st *store.Store) error {
			return addSubscription(context.Background(), st, srv.URL, io.Discard, srv.Client())
		}); err != nil {
			t.Fatalf("подписка %d: %v", i+1, err)
		}
	}

	st, err := store.Open(root, clock.System{})
	if err != nil {
		t.Fatalf("стор: %v", err)
	}
	defer st.Close()

	if got := len(st.Groups()); got != 1 {
		t.Errorf("групп %d, ожидалась 1: повторная подписка завела вторую и потеряла историю проб", got)
	}
}

// TestW42FailedSubLeavesStoreAlone — недокачанная подписка стор не трогает
// (Р7, §6.16).
//
// Пустой ответ неотличим от подписки, которую провайдер опустошил по ошибке, и
// применить его значило бы удалить группу вместе с историей.
func TestW42FailedSubLeavesStoreAlone(t *testing.T) {
	root := withTestStore(t)

	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, subBody())
	}))
	defer good.Close()

	if err := withStore(func(st *store.Store) error {
		return addSubscription(context.Background(), st, good.URL, io.Discard, good.Client())
	}); err != nil {
		t.Fatalf("первая подписка: %v", err)
	}

	// Тот же адрес, но теперь сервер отдаёт пустоту.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer empty.Close()

	before := nodeIDs(t, root)
	err := withStore(func(st *store.Store) error {
		return addSubscription(context.Background(), st, empty.URL, io.Discard, empty.Client())
	})
	if err == nil {
		t.Fatal("пустая подписка принята молча: группа была бы стёрта вместе с историей проб")
	}
	if got := nodeIDs(t, root); got != before {
		t.Errorf("стор изменился после отказа: было %q, стало %q", before, got)
	}
}

// TestW43StoreRootIsPrivate — корень стора создан с правами 0700 (§6.14, Р37).
//
// Проверка на число, а не на поведение, и это намеренно: каталог с ключами
// узлов не бывает «в основном закрытым», а ошибка здесь молчалива.
func TestW43StoreRootIsPrivate(t *testing.T) {
	root := withTestStore(t)

	if err := withStore(func(st *store.Store) error { return nil }); err != nil {
		t.Fatalf("стор не открылся: %v", err)
	}

	fi, err := os.Stat(root)
	if err != nil {
		t.Fatalf("каталог стора: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Errorf("права каталога стора %04o, ожидались 0700: там лежат ключи узлов (§6.14)", perm)
	}
}

// TestAddNodeRefusesGarbage — `-node` на неразбираемой ссылке отказывает, а не
// молча кладёт пустой узел.
func TestAddNodeRefusesGarbage(t *testing.T) {
	withTestStore(t)

	err := withStore(func(st *store.Store) error {
		return addNode(st, "не-ссылка-вовсе", io.Discard)
	})
	if err == nil {
		t.Error("мусор принят молча: в сторе оказался бы узел, до которого никто не дозвонится")
	}
}

// TestAddNodeLandsInManual — одиночная ссылка ложится в группу manual (Р10).
func TestAddNodeLandsInManual(t *testing.T) {
	root := withTestStore(t)

	link := "vless://" + uuidA + "@a.example.com:443?type=ws&security=tls#ручной"
	if err := withStore(func(st *store.Store) error {
		return addNode(st, link, io.Discard)
	}); err != nil {
		t.Fatalf("узел не добавился: %v", err)
	}

	st, err := store.Open(root, clock.System{})
	if err != nil {
		t.Fatalf("стор: %v", err)
	}
	defer st.Close()

	if got := len(st.Nodes(store.ManualGroupID)); got != 1 {
		t.Errorf("в группе %s узлов %d, ожидался 1", store.ManualGroupID, got)
	}
}

// nodeIDs — состав стора одной строкой, чтобы сравнивать «до» и «после».
func nodeIDs(t *testing.T, root string) string {
	t.Helper()
	st, err := store.Open(root, clock.System{})
	if err != nil {
		t.Fatalf("стор: %v", err)
	}
	defer st.Close()

	var b strings.Builder
	for _, g := range st.Groups() {
		for _, n := range st.Nodes(g.ID) {
			b.WriteString(g.ID + "/" + n.Server + ";")
		}
	}
	return b.String()
}

// TestRemoveNodeDropsOne — `-rm` по id узла убирает его, не трогая соседей.
func TestRemoveNodeDropsOne(t *testing.T) {
	root := withTestStore(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, subBody())
	}))
	defer srv.Close()

	if err := withStore(func(st *store.Store) error {
		return addSubscription(context.Background(), st, srv.URL, io.Discard, srv.Client())
	}); err != nil {
		t.Fatalf("подписка: %v", err)
	}

	var victim, group string
	if err := withStore(func(st *store.Store) error {
		g := st.Groups()[0]
		group = g.ID
		victim = st.Nodes(g.ID)[0].ID
		return nil
	}); err != nil {
		t.Fatalf("чтение стора: %v", err)
	}

	if err := withStore(func(st *store.Store) error {
		return removeNode(st, victim, io.Discard)
	}); err != nil {
		t.Fatalf("удаление: %v", err)
	}

	st, err := store.Open(root, clock.System{})
	if err != nil {
		t.Fatalf("стор: %v", err)
	}
	defer st.Close()

	nodes := st.Nodes(group)
	if len(nodes) != 1 {
		t.Fatalf("узлов осталось %d, ожидался 1", len(nodes))
	}
	if nodes[0].ID == victim {
		t.Error("удалён не тот узел")
	}
	if _, ok := st.Node(victim); ok {
		t.Error("удалённый узел всё ещё в сторе")
	}
}

// TestRemoveGroupEmptiesIt — `-rm` по id группы убирает всю группу разом.
func TestRemoveGroupEmptiesIt(t *testing.T) {
	root := withTestStore(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, subBody())
	}))
	defer srv.Close()

	if err := withStore(func(st *store.Store) error {
		return addSubscription(context.Background(), st, srv.URL, io.Discard, srv.Client())
	}); err != nil {
		t.Fatalf("подписка: %v", err)
	}

	var group string
	if err := withStore(func(st *store.Store) error {
		group = st.Groups()[0].ID
		return nil
	}); err != nil {
		t.Fatalf("чтение стора: %v", err)
	}

	if err := withStore(func(st *store.Store) error {
		return removeNode(st, group, io.Discard)
	}); err != nil {
		t.Fatalf("удаление группы: %v", err)
	}

	st, err := store.Open(root, clock.System{})
	if err != nil {
		t.Fatalf("стор: %v", err)
	}
	defer st.Close()

	if got := len(st.Nodes(group)); got != 0 {
		t.Errorf("в группе осталось %d узлов, ожидался 0", got)
	}
}

// TestRemoveUnknownRefuses — `-rm` по чужому id отказывает, а не молчит.
func TestRemoveUnknownRefuses(t *testing.T) {
	withTestStore(t)

	err := withStore(func(st *store.Store) error {
		return removeNode(st, "такого-нет", io.Discard)
	})
	if err == nil {
		t.Error("удаление несуществующего id прошло молча: опечатка выглядела бы успехом")
	}
}
