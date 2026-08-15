// Секреты на границе «агент ↔ сервис» — docs/verification-store.md §5.5, S34.
// Проверка живёт здесь, а не в internal/store: TunnelParams объявлен в tunnel и
// уезжает через ipc, а стор про туннель не знает и знать не должен (§3.4).
package ipc

import (
	"reflect"
	"strings"
	"testing"

	"github.com/shafed/hop/internal/tunnel"
)

// TestS34TunnelParamsCarryNoNodeFields — S34: StartTunnel от агента не несёт
// сервису ни одного поля узла (§3.1). Сервис знает только параметры интерфейса
// и маршрутов; куда идёт трафик и какими ключами — он не знает.
//
// Проверка фиксирует факт, а не создаёт его: тип уже такой. Смысл в том, что
// поле, дописанное в TunnelParams однажды «на минутку», обязано ломать сборку
// проверки, а не тихо уехать через сокет.
func TestS34TunnelParamsCarryNoNodeFields(t *testing.T) {
	// Полный список полей §3.1: параметры интерфейса и маршрутов, и ничего
	// больше. Список закрыт намеренно — новое поле обязано попасть сюда через
	// ревью, а не мимо него.
	want := map[string]bool{
		"Name": true, "MTU": true, "Addr": true, "Table": true, "AgentUID": true,
	}
	rt := reflect.TypeOf(tunnel.Params{})
	got := make(map[string]bool, rt.NumField())
	for i := range rt.NumField() {
		f := rt.Field(i)
		got[f.Name] = true
		if !want[f.Name] {
			t.Errorf("в TunnelParams появилось поле %s %s: §3.1 разрешает только параметры интерфейса и маршрутов",
				f.Name, f.Type)
		}
		// Проверка имён смотрит на поверхность, поэтому вторым условием — вид
		// типа: строки и числа. Вложенная структура или карта пронесла бы узел
		// целиком под безобидным именем, и список полей этого бы не заметил.
		switch f.Type.Kind() {
		case reflect.String, reflect.Int:
		default:
			t.Errorf("поле %s имеет составной тип %s: через него узел уедет сервису целиком (§3.1)", f.Name, f.Type)
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("из TunnelParams исчезло поле %s — проверку надо пересмотреть, а не подогнать", name)
		}
	}
}

// TestS34StartRequestCarriesNoNodeFields — то же на проводе: кадр StartTunnel
// целиком, каким его увидит сервис.
func TestS34StartRequestCarriesNoNodeFields(t *testing.T) {
	raw, err := encode(Request{
		Op: OpStart,
		Params: &tunnel.Params{
			Name: "hop0", MTU: 1420, Addr: "10.255.0.1/24", Table: 1042, AgentUID: 1000,
		},
	})
	if err != nil {
		t.Fatalf("кадр не собрался: %v", err)
	}
	body := strings.ToLower(string(raw))
	for _, w := range []string{"node", "server", "protocol", "uuid", "password", "pbk", "raw_link", "vless"} {
		if strings.Contains(body, w) {
			t.Errorf("в кадре StartTunnel есть %q: сервис не должен знать, куда идёт трафик (§3.1)\n%s", w, raw)
		}
	}
}
