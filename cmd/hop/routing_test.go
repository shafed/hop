package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shafed/hop/internal/agent"
	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/store"
)

// withSettings кладёт settings.json в стор теста и открывает стор.
func withSettings(t *testing.T, body string) *store.Store {
	t.Helper()
	root := withTestStore(t)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "settings.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(root, clock.System{})
	if err != nil {
		t.Fatalf("стор не открылся: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestW52SettingsReachAgentRouting — списки §6.10 с диска доходят до
// конфигурации связки.
//
// Проброс, а не поведение, и потому проверяется отдельно: agent.Config.Routing
// необязателен, nil означает умолчания, и забытая строка сборки не ломает ни
// компиляцию, ни один модульный тест netstack — она просто оставляет
// конфигурацию пользователя лежать на диске без всякого действия. Ровно та же
// молчаливость, из-за которой W47 существует отдельно от модульной проверки
// bypass_rebind.
//
// Краснеет без settings_file: с выключенной политикой стор не читает файл, и
// Config.Routing остаётся пустым.
func TestW52SettingsReachAgentRouting(t *testing.T) {
	st := withSettings(t, `{
  "version": 1,
  "routing": {
    "bypass": [{"prefix": "192.168.10.7/32", "proto": "tcp", "port": 9100}],
    "block":  [{"proto": "udp", "port": 137}]
  }
}
`)

	var cfg agent.Config
	applySettings(&cfg, st)

	if cfg.Routing == nil {
		t.Fatal("settings.json не дошёл до agent.Config.Routing: списки §6.10 остались на диске")
	}
	wantBypass := netstack.Rule{
		Prefix: netip.MustParsePrefix("192.168.10.7/32"),
		Proto:  netstack.ProtoTCP,
		Port:   9100,
	}
	if len(cfg.Routing.Bypass) != 1 || cfg.Routing.Bypass[0] != wantBypass {
		t.Fatalf("Config.Routing.Bypass = %+v, ожидалось [%+v]", cfg.Routing.Bypass, wantBypass)
	}
	wantBlock := netstack.Rule{Proto: netstack.ProtoUDP, Port: 137}
	if len(cfg.Routing.Block) != 1 || cfg.Routing.Block[0] != wantBlock {
		t.Fatalf("Config.Routing.Block = %+v, ожидалось [%+v]", cfg.Routing.Block, wantBlock)
	}
}

// TestW53SettingsReachAgentDNSUpstreams — вторая половина той же формы.
//
// Отдельная строка регистра, а не ветка предыдущей: поля разные, путь до
// продукта разный (одно уходит в netstack.Config, другое в resolver.Config), и
// забыть их можно по отдельности. Краснеет без settings_file по той же причине.
func TestW53SettingsReachAgentDNSUpstreams(t *testing.T) {
	st := withSettings(t, `{"version": 1, "dns_upstreams": ["9.9.9.9:53"]}`)

	var cfg agent.Config
	applySettings(&cfg, st)

	want := netip.MustParseAddrPort("9.9.9.9:53")
	if len(cfg.DNSUpstreams) != 1 || cfg.DNSUpstreams[0] != want {
		t.Fatalf("Config.DNSUpstreams = %v, ожидалось [%v]", cfg.DNSUpstreams, want)
	}
}

// TestRoutingShowsEffectiveListsAndTheirSource — `-routing` печатает не файл, а
// то, что из него следует.
//
// Проверяется самое неочевидное свойство §6.10: раз в файле есть раздел
// routing, обнаружение служб перестаёт действовать само собой (оно умолчание, а
// не пол), а исключения §5.6 продолжают действовать всегда. Оба факта не видны
// из файла ни при каком его чтении глазами, поэтому обязаны быть в выводе.
func TestRoutingShowsEffectiveListsAndTheirSource(t *testing.T) {
	st := withSettings(t, `{"version":1,"routing":{"bypass":[{"prefix":"192.168.10.0/24"}]}}`)

	var out bytes.Buffer
	if err := showSettings(st, "/тест/settings.json", &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"/тест/settings.json",
		"192.168.10.0/24",
		"5353",       // обнаружение служб названо
		"10.0.0.0/8", // исключения §5.6 названы
	} {
		if !strings.Contains(got, want) {
			t.Errorf("в выводе -routing нет %q:\n%s", want, got)
		}
	}
}

// TestRoutingWithoutFileShowsDefaults — файла нет: вывод обязан показать
// умолчания §6.10, а не пустоту. Пустой вывод читается как «правил нет», а
// правила есть — они в коде.
func TestRoutingWithoutFileShowsDefaults(t *testing.T) {
	root := withTestStore(t)
	st, err := store.Open(root, clock.System{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var out bytes.Buffer
	if err := showSettings(st, filepath.Join(root, "settings.json"), &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"умолчания", "224.0.0.251", "§5.7"} {
		if !strings.Contains(got, want) {
			t.Errorf("в выводе -routing без файла нет %q:\n%s", want, got)
		}
	}
}
