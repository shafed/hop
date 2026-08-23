// Секреты — docs/verification-store.md §5.5, шаг 7 регистра. S31–S33.
// S34 (граница «агент ↔ сервис») живёт в internal/ipc: TunnelParams объявлен
// там, и проверять его из стора значило бы тянуть в стор импорт туннеля.
package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time" //hop:realtime — метки фейковых часов, обращений к настоящему времени нет

	"github.com/shafed/hop/internal/health"
)

// Секреты подставного узла. Каждый — то, что §6.14 запрещает выпускать наружу:
// ключ доступа, пароль, публичный ключ REALITY и ссылка целиком.
const (
	secretUUID     = "9f8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"
	secretPassword = "пароль-которого-не-должно-быть-в-логе"
	secretPBK      = "vLpKQ0Zg7bV1sJ2mX9nY8cD3fH4kL6pR7tU8wZ0aB1c"
	secretHeader   = "X-Auth: очень-секретный-заголовок"
)

// secretNode — узел, у которого секретно всё, что бывает секретным.
func secretNode() Node {
	n := Node{
		ID:        "n1",
		GroupID:   "g",
		MergeKey:  "vless|a.example|443|" + secretUUID,
		Name:      "Токио 01",
		Protocol:  "vless",
		Server:    "a.example",
		Port:      443,
		Transport: "ws",
		Security:  "reality",
		Params: map[string]string{
			"uuid":       secretUUID,
			"password":   secretPassword,
			"pbk":        secretPBK,
			secretHeader: "1",
			"sni":        "www.example",
		},
		Supported: true,
		RawLink:   "vless://" + secretUUID + "@a.example:443?pbk=" + secretPBK + "#Токио%2001",
	}
	return n
}

// secrets — всё, чего не должно быть ни в одном выводе.
func secrets() []string {
	return []string{secretUUID, secretPassword, secretPBK, secretHeader}
}

func mustNotLeak(t *testing.T, what, out string) {
	t.Helper()
	for _, s := range secrets() {
		if strings.Contains(out, s) {
			t.Errorf("%s выдал секрет %q:\n%s", what, s, out)
		}
	}
}

// TestS31NodeNeverFormats — S31: Node печатается %v, %+v, %#v и внутри
// объемлющей структуры — ключей нет ни в одном выводе (Р12).
func TestS31NodeNeverFormats(t *testing.T) {
	n := secretNode()
	type wrapper struct {
		Why  string
		Node Node
		List []Node
		ByID map[string]Node
	}
	w := wrapper{Why: "лог отладки", Node: n, List: []Node{n}, ByID: map[string]Node{"n1": n}}

	for what, out := range map[string]string{
		"%v":                    fmt.Sprintf("%v", n),
		"%s":                    fmt.Sprintf("%s", n),
		"%q":                    fmt.Sprintf("%q", n),
		"%+v":                   fmt.Sprintf("%+v", n),
		"%#v":                   fmt.Sprintf("%#v", n),
		"%v по указателю":       fmt.Sprintf("%v", &n),
		"%+v по объемлющей":     fmt.Sprintf("%+v", w),
		"%#v по объемлющей":     fmt.Sprintf("%#v", w),
		"%v по срезу":           fmt.Sprintf("%v", []Node{n}),
		"%v по карте":           fmt.Sprintf("%v", map[string]Node{"n1": n}),
		"%v по составу слияния": fmt.Sprintf("%v", Merged{Nodes: []Node{n}, Kept: []string{"n1"}}),
	} {
		mustNotLeak(t, what, out)
	}

	// Заглушка обязана остаться полезной: §6.14 запрещает попадание ключей в
	// лог, а не отладку вообще. Узел, свёрнутый до «<node>», сделал бы в логе
	// неотличимыми двести узлов подписки.
	out := fmt.Sprintf("%v", n)
	for _, want := range []string{"n1", "Токио 01", "a.example", "443", "vless"} {
		if !strings.Contains(out, want) {
			t.Errorf("заглушка спрятала опознавательный признак %q: %s", want, out)
		}
	}
}

// TestS32DebugLogCarriesNoKeys — S32: лог на уровне debug при импорте и слиянии.
// Логгер настоящий, уровень отладочный, значения — те же, что уехали бы в него
// из кода импорта.
func TestS32DebugLogCarriesNoKeys(t *testing.T) {
	n := secretNode()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	log.Debug("узел импортирован", "node", n)
	log.Debug("состав группы слит", "merged", Merged{
		Added: []string{"n1"},
		Nodes: []Node{n},
		Order: []string{"n1"},
	})
	log.Debug("узел отдан наружу", "nodes", map[string]Node{"n1": n})

	mustNotLeak(t, "лог уровня debug", buf.String())
	if !strings.Contains(buf.String(), "n1") {
		t.Errorf("в логе не осталось даже id узла — отлаживать нечем:\n%s", buf.String())
	}
}

// TestS33JSONOutputHasNoKeys — S33: `hop nodes --json` и `hop status --json`.
// Команд ещё нет (этап 9), поэтому проверяется функция формирования вывода —
// то, из чего они будут собраны (шаг 7 регистра).
func TestS33JSONOutputHasNoKeys(t *testing.T) {
	s, _, _ := newTimedStore(t)
	n := secretNode()
	seed(t, s, Group{ID: "g", Name: "подписка", SourceURL: "https://example.invalid/sub?token=" + secretUUID}, n)
	s.PutHealth([]health.NodeHealth{{
		NodeID:      "n1",
		State:       health.Alive,
		RTT:         42 * time.Millisecond,
		LastProbeAt: testEpoch,
	}})

	nodes, err := json.Marshal(s.NodesView("g"))
	if err != nil {
		t.Fatalf("вывод nodes не сериализуется: %v", err)
	}
	status, err := json.Marshal(s.StatusView("n1"))
	if err != nil {
		t.Fatalf("вывод status не сериализуется: %v", err)
	}
	mustNotLeak(t, "hop nodes --json", string(nodes))
	mustNotLeak(t, "hop status --json", string(status))

	// Вывод при этом остаётся выводом: узел опознаётся, живость видна.
	for _, want := range []string{`"id":"n1"`, `"server":"a.example"`, `"state":"alive"`, `"rtt_ms":42`} {
		if !strings.Contains(string(nodes), want) {
			t.Errorf("в выводе нет %s:\n%s", want, nodes)
		}
	}
	if !strings.Contains(string(status), `"active"`) {
		t.Errorf("в status нет активного узла:\n%s", status)
	}

	// Отдельно — то, что секретно не по §6.14, а по смыслу: URL подписки
	// отдаёт её тело любому, кто его знает.
	if strings.Contains(string(status), "example.invalid") {
		t.Errorf("source_url подписки уехал в вывод:\n%s", status)
	}
}

// TestS33ViewSurvivesEmptyStore — вывод пустого стора существует и не разваливается:
// `hop status --json` вызывается и до первого выбора узла (§5.5).
func TestS33ViewSurvivesEmptyStore(t *testing.T) {
	s, _, _ := newTimedStore(t)
	v := s.StatusView("")
	if v.Active != nil {
		t.Errorf("в пустом сторе нашёлся активный узел: %+v", v.Active)
	}
	if got, err := json.Marshal(v); err != nil {
		t.Fatalf("пустой status не сериализуется: %v", err)
	} else if !strings.Contains(string(got), `"groups"`) {
		t.Errorf("в пустом status нет списка групп: %s", got)
	}
}
