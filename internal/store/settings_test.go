package store

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/netstack"
)

// writeSettings кладёт настройки в каталог стора до его открытия: файл
// принадлежит человеку, а не стору, и появляется там же, где nodes.json.
func writeSettings(t *testing.T, root, body string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "settings.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func openSettings(t *testing.T, body string) Settings {
	t.Helper()
	root := t.TempDir()
	writeSettings(t, root, body)
	st, err := Open(root, clock.System{})
	if err != nil {
		t.Fatalf("стор не открылся на годном settings.json: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st.Settings()
}

// refuseSettings — общий стенд для §5.6: кривой файл обязан дать отказ, а не
// умолчания. Возвращает текст отказа, чтобы проверить, что в нём названа
// причина, а не «не удалось разобрать».
func refuseSettings(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	writeSettings(t, root, body)
	st, err := Open(root, clock.System{})
	if err == nil {
		st.Close()
		t.Fatalf("стор открылся на негодном settings.json, настройки: %+v", st.Settings())
	}
	raw, rerr := os.ReadFile(filepath.Join(root, "settings.json"))
	if rerr != nil {
		t.Fatalf("отказ унёс с собой файл настроек: %v", rerr)
	}
	if string(raw) != body {
		t.Fatalf("отказ переписал файл настроек:\n%s", raw)
	}
	return err.Error()
}

// S40 — списки §6.10 приезжают с диска. Краснеет без settings_file: с
// выключенной политикой файл не читается вовсе, и Settings отдаёт пустое.
func TestS40SettingsCarryRoutingListsFromDisk(t *testing.T) {
	set := openSettings(t, `{
  "version": 1,
  "routing": {
    "bypass": [
      {"prefix": "192.168.10.0/24"},
      {"prefix": "224.0.0.251/32", "proto": "udp", "port": 5353}
    ],
    "block": [
      {"proto": "udp", "port": 137}
    ]
  }
}
`)
	if set.Routing == nil {
		t.Fatal("routing с диска не приехал: Settings().Routing пуст")
	}
	wantBypass := []netstack.Rule{
		{Prefix: netip.MustParsePrefix("192.168.10.0/24")},
		{Prefix: netip.MustParsePrefix("224.0.0.251/32"), Proto: netstack.ProtoUDP, Port: 5353},
	}
	if len(set.Routing.Bypass) != len(wantBypass) {
		t.Fatalf("bypass с диска: %+v, ожидалось %+v", set.Routing.Bypass, wantBypass)
	}
	for i, w := range wantBypass {
		if set.Routing.Bypass[i] != w {
			t.Errorf("bypass[%d] = %+v, ожидалось %+v", i, set.Routing.Bypass[i], w)
		}
	}
	wantBlock := netstack.Rule{Proto: netstack.ProtoUDP, Port: 137}
	if len(set.Routing.Block) != 1 || set.Routing.Block[0] != wantBlock {
		t.Fatalf("block с диска: %+v, ожидалось [%+v]", set.Routing.Block, wantBlock)
	}
}

// S41 — апстримы §5.7 приезжают тем же файлом. Половина той же формы: поле
// Config.DNSUpstreams существовало ровно так же без единого заполняющего.
func TestS41SettingsCarryDNSUpstreamsFromDisk(t *testing.T) {
	set := openSettings(t, `{"version": 1, "dns_upstreams": ["9.9.9.9:53", "[2620:fe::fe]:853"]}`)
	want := []netip.AddrPort{
		netip.MustParseAddrPort("9.9.9.9:53"),
		netip.MustParseAddrPort("[2620:fe::fe]:853"),
	}
	if len(set.DNSUpstreams) != len(want) {
		t.Fatalf("апстримы с диска: %v, ожидалось %v", set.DNSUpstreams, want)
	}
	for i, w := range want {
		if set.DNSUpstreams[i] != w {
			t.Errorf("апстрим[%d] = %v, ожидался %v", i, set.DNSUpstreams[i], w)
		}
	}
}

// S42 — файла нет: настройки пусты, и это означает умолчания §6.10, а не
// пустые списки. Сам файл при этом заводится, как и три остальных: стор, у
// которого файл появляется только после первой записи, невозможно проверить
// на права (§6.14).
func TestS42MissingSettingsMeanDefaults(t *testing.T) {
	root := t.TempDir()
	st, err := Open(root, clock.System{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if set := st.Settings(); set.Routing != nil || set.DNSUpstreams != nil {
		t.Fatalf("без файла настройки не пусты: %+v", set)
	}
	fi, err := os.Stat(filepath.Join(root, "settings.json"))
	if err != nil {
		t.Fatalf("settings.json не заведён: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o644 {
		t.Errorf("права settings.json %04o, ожидались 0644: секретов в нём нет", perm)
	}
}

// S43 — «раздел есть, но пуст» и «раздела нет» — разные состояния.
//
// Разница наблюдаема: resolveRouting подмешивает исключения §5.6 к любому
// непустому конфигу, но обнаружение служб — умолчание, а не пол, и пустой
// раздел routing его убирает (§6.10). Если формат схлопнет эти два состояния в
// одно, убрать mDNS конфигурацией станет невозможно.
func TestS43EmptyRoutingSectionIsNotAbsentSection(t *testing.T) {
	set := openSettings(t, `{"version": 1, "routing": {"bypass": [], "block": []}}`)
	if set.Routing == nil {
		t.Fatal("пустой раздел routing прочитан как отсутствующий: убрать обнаружение служб конфигурацией стало нельзя")
	}
	if len(set.Routing.Bypass) != 0 || len(set.Routing.Block) != 0 {
		t.Fatalf("пустой раздел routing дал непустые списки: %+v", set.Routing)
	}
}

// S44 — кривой ввод отвергается с названной причиной, а не проглатывается.
//
// Каждая строка — свой вид кривизны, и каждая проверяет две вещи: стор не
// открылся и файл не тронут. Молчаливый откат к умолчаниям здесь запрещён
// ровно тем же §5.6, которым запрещён молчаливый дроп пакета: правило
// «блокировать 137» исчезло бы, не сказав ни слова.
func TestS44BrokenSettingsAreRefusedNotSwallowed(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"пустой файл", ``, "settings.json"},
		{"мусор вместо JSON", "не json вовсе\n", "settings.json"},
		{"версия из будущего", `{"version": 7}`, "версия"},
		{"префикс не разбирается", `{"version":1,"routing":{"bypass":[{"prefix":"192.168.0.0/33"}]}}`, "prefix"},
		{"префикс не по маске", `{"version":1,"routing":{"bypass":[{"prefix":"192.168.10.5/24"}]}}`, "192.168.10.0/24"},
		{"неизвестный протокол", `{"version":1,"routing":{"block":[{"proto":"sctp","port":9}]}}`, "proto"},
		{"порт вне диапазона", `{"version":1,"routing":{"block":[{"proto":"udp","port":70000}]}}`, "port"},
		{"порт отрицательный", `{"version":1,"routing":{"block":[{"proto":"udp","port":-1}]}}`, "port"},
		{"правило без единого поля", `{"version":1,"routing":{"bypass":[{}]}}`, "0.0.0.0/0"},
		{"апстрим без порта", `{"version":1,"dns_upstreams":["1.1.1.1"]}`, "dns_upstreams"},
		{"апстрим именем", `{"version":1,"dns_upstreams":["dns.example.com:53"]}`, "dns_upstreams"},
		{"апстрим с портом 0", `{"version":1,"dns_upstreams":["1.1.1.1:0"]}`, "dns_upstreams"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := refuseSettings(t, c.body)
			if !strings.Contains(msg, c.want) {
				t.Errorf("в отказе нет %q, а есть только: %s", c.want, msg)
			}
		})
	}
}

// S45 — «выпустить наружу вообще всё» выразимо (§6.10), но только явно.
// Пустой объект правила — опечатка, целиком нулевой префикс — решение.
func TestS45CatchAllRuleMustBeSpelledOut(t *testing.T) {
	set := openSettings(t, `{"version":1,"routing":{"bypass":[{"prefix":"0.0.0.0/0"}]}}`)
	if set.Routing == nil {
		t.Fatal("явное 0.0.0.0/0 не прочиталось: раздел routing пуст")
	}
	if len(set.Routing.Bypass) != 1 || set.Routing.Bypass[0].Prefix.Bits() != 0 {
		t.Fatalf("явное 0.0.0.0/0 не прочиталось: %+v", set.Routing)
	}
}

// S46 — отданные настройки не связаны со стором: правка копии не меняет то,
// что стор отдаст следующему. Тот же приём, что cloneNode.
func TestS46SettingsAreHandedOutAsCopy(t *testing.T) {
	root := t.TempDir()
	writeSettings(t, root, `{"version":1,"routing":{"bypass":[{"prefix":"10.1.0.0/16"}]},"dns_upstreams":["9.9.9.9:53"]}`)
	st, err := Open(root, clock.System{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	first := st.Settings()
	first.Routing.Bypass[0] = netstack.Rule{Prefix: netip.MustParsePrefix("0.0.0.0/0")}
	first.DNSUpstreams[0] = netip.MustParseAddrPort("127.0.0.1:53")

	second := st.Settings()
	if second.Routing.Bypass[0].Prefix != netip.MustParsePrefix("10.1.0.0/16") {
		t.Errorf("правка отданного списка дошла до стора: %+v", second.Routing.Bypass)
	}
	if second.DNSUpstreams[0] != netip.MustParseAddrPort("9.9.9.9:53") {
		t.Errorf("правка отданных апстримов дошла до стора: %v", second.DNSUpstreams)
	}
}
