package main

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/shafed/hop/internal/netstack"
)

// TestW54EveryStackCounterReachesTheLog — W54: счётчик, заведённый в
// netstack.Stats, не может остаться невидимым.
//
// Эта половина — про дрейф, а не про проводку. Счётчики стека уже один раз
// доехали до `Stack.Stats()` и там встали: показать их было некому, и заметить
// это можно было только чтением кода. Проверка сверяет **тип** с таблицей
// подписей: новое поле в `netstack.Stats` краснит её до того, как окажется, что
// продукт считает то, чего никто не видит.
//
// Числа в снимке различны намеренно: таблица, в которой две подписи смотрят на
// одно поле, выглядит правдоподобно и врёт — одинаковые значения такую
// подстановку не поймали бы.
func TestW54EveryStackCounterReachesTheLog(t *testing.T) {
	typ := reflect.TypeOf(netstack.Stats{})

	labels := map[string]string{}
	for _, c := range stackCounters {
		if _, dup := labels[c.field]; dup {
			t.Errorf("поле %s названо в таблице дважды", c.field)
		}
		if _, ok := typ.FieldByName(c.field); !ok {
			t.Errorf("таблица называет поле %s, которого в netstack.Stats нет", c.field)
		}
		labels[c.field] = c.label
	}
	for i := 0; i < typ.NumField(); i++ {
		if name := typ.Field(i).Name; labels[name] == "" {
			t.Errorf("счётчик %s не доходит до пользователя: подписи для него нет", name)
		}
	}

	// Снимок с различимыми числами: i-е поле получает значение i+1.
	v := reflect.New(typ).Elem()
	for i := 0; i < typ.NumField(); i++ {
		if !v.Field(i).CanInt() {
			t.Fatalf("поле %s не число (%s): проверку надо научить новому виду счётчика",
				typ.Field(i).Name, typ.Field(i).Type)
		}
		v.Field(i).SetInt(int64(i + 1))
	}
	st := v.Interface().(netstack.Stats)

	kv := stackLine(st)
	if len(kv)%2 != 0 {
		t.Fatalf("строка стека собрана нечётной: %d элементов", len(kv))
	}
	got := map[string]string{}
	for i := 0; i < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			t.Fatalf("ключ %d не строка: %T", i, kv[i])
		}
		got[key] = fmt.Sprint(kv[i+1])
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		label := labels[f.Name]
		if label == "" {
			continue
		}
		want := fmt.Sprint(i + 1)
		if got[label] != want {
			t.Errorf("под подписью %q напечатано %q, а поле %s держит %s",
				label, got[label], f.Name, want)
		}
	}
}
