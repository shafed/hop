package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/store"
)

// TestW67AutoconnectSettingGatesInitialUp — охрана политики autoconnect_state.
//
// shouldAutoUp — единственное место, где §6.13 встречается с run() в
// main.go: без него `hop agent` поднимал туннель безусловно, что бы ни лежало
// в settings.json (это и есть состояние продукта до этого прохода, и ровно к
// нему возвращает выключенная политика). Проверка не поднимает ни туннеля, ни
// связки — она про решение, а не про его исполнение, тем же приёмом, что
// applySettings у W52/W53.
//
// Краснеет без autoconnect_state: выключенная политика заставляет
// shouldAutoUp отвечать true всегда, и второй случай (autoconnect=off) ломается.
func TestW67AutoconnectSettingGatesInitialUp(t *testing.T) {
	root := withTestStore(t)
	st, err := store.Open(root, clock.System{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if !shouldAutoUp(st) {
		t.Fatal("свежий стор: shouldAutoUp должен быть true по умолчанию (§6.13)")
	}

	if err := st.SetAutoconnect(false); err != nil {
		t.Fatalf("SetAutoconnect(false): %v", err)
	}
	if shouldAutoUp(st) {
		t.Fatal("автоподключение выключено в сторе, а shouldAutoUp всё равно велит поднимать туннель")
	}

	if err := st.SetAutoconnect(true); err != nil {
		t.Fatalf("SetAutoconnect(true): %v", err)
	}
	if !shouldAutoUp(st) {
		t.Fatal("автоподключение включено обратно, а shouldAutoUp всё ещё против")
	}
}

// TestW67AutoconnectVerbPersists — вторая половина: настоящий глагол
// `hop autoconnect on|off`, как его вызовет пользователь, тоже доходит до
// диска и не отказывает.
func TestW67AutoconnectVerbPersists(t *testing.T) {
	root := withTestStore(t)
	var out, errOut bytes.Buffer
	c := newCLI(&out, &errOut)

	if code := c.dispatch([]string{"autoconnect", "off"}); code != 0 {
		t.Fatalf("`hop autoconnect off` code = %d, stderr = %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "выключено") {
		t.Errorf("вывод не сообщает о выключении: %q", out.String())
	}

	st, err := store.Open(root, clock.System{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.Settings().AutoconnectOn() {
		t.Fatal("`hop autoconnect off` не дошёл до settings.json")
	}
}
