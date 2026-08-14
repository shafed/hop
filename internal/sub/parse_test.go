package sub_test

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/shafed/hop/internal/node"
	"github.com/shafed/hop/internal/sub"
)

// Корпус ссылок и его golden-отпечаток. Каждая нормализация §6.12 проверяется
// отдельным тестом ниже по своей строке корпуса; golden ловит всё остальное —
// то, что нормализацией не названо, но меняться молча тоже не должно.
const (
	corpusPath = "testdata/corpus.txt"
	goldenPath = "testdata/corpus.golden"
)

var update = flag.Bool("update", false, "перезаписать golden-файл корпуса")

func TestGoldenCorpus(t *testing.T) {
	nodes := corpusNodes(t)

	lines := make([]string, 0, len(nodes))
	for _, n := range nodes {
		lines = append(lines, render(n))
	}
	got := strings.Join(lines, "\n") + "\n"

	if *update {
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("корпус разобран иначе, чем в golden:\nполучено:\n%s\nожидалось:\n%s", got, want)
	}
}

// TestCascadeBase64Body — первая ступень каскада §6.12: тело целиком в base64
// даёт ровно те же узлы, что и открытый текст.
func TestCascadeBase64Body(t *testing.T) {
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := sub.ParseSubscription(raw, "g")
	if err != nil {
		t.Fatalf("открытый текст: %v", err)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(raw))
	coded, err := sub.ParseSubscription(encoded, "g")
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if len(coded) != len(plain) {
		t.Fatalf("узлов из base64 %d, из текста %d", len(coded), len(plain))
	}
	for i := range plain {
		if render(coded[i]) != render(plain[i]) {
			t.Errorf("узел %d разобран иначе:\nbase64: %s\nтекст:  %s", i, render(coded[i]), render(plain[i]))
		}
	}
}

// TestCascadeClashRejected — Clash YAML распознаётся и отвергается целиком, а
// не разбирается построчно (отклонение C5): иначе на каждую строку YAML
// приходит своя бессмысленная ошибка, и настоящая причина тонет.
func TestCascadeClashRejected(t *testing.T) {
	body := []byte("proxies:\n  - name: a\n    type: vless\n")
	if _, err := sub.ParseSubscription(body, "g"); err == nil {
		t.Fatal("Clash YAML разобран, ожидался отказ")
	}
}

// TestNormalizeFragmentToName — §6.12: #fragment становится именем, с
// раскодированным процентным экранированием.
func TestNormalizeFragmentToName(t *testing.T) {
	n := byName(t, corpusNodes(t), "Токио WS")
	if n.Name != "Токио WS" {
		t.Fatalf("имя %q", n.Name)
	}
}

// TestNormalizeCase — §6.12, регистр: схема, хост и значения type/security
// приходят как попало. server входит в ключ слияния §6.16, и без приведения
// регистра один узел разъезжается на два, теряя историю.
func TestNormalizeCase(t *testing.T) {
	n := byName(t, corpusNodes(t), "Case")
	if n.Protocol != node.VLESS {
		t.Errorf("протокол %q, ожидался vless", n.Protocol)
	}
	if n.Server != "vpn.example.com" {
		t.Errorf("server %q, ожидался нижний регистр", n.Server)
	}
	if n.Transport != node.WS {
		t.Errorf("transport %q, ожидался ws", n.Transport)
	}
	if n.Security != node.SecTLS {
		t.Errorf("security %q, ожидался tls", n.Security)
	}
	if !n.Supported {
		t.Error("узел не поддержан, хотя всё в нём знакомое")
	}
}

// TestNormalizeSNIFromHostOnIPServer — §6.12: сервер задан IP, sni пуст, host
// есть → sni = host. Без этого TLS уходит без имени и узел отваливается на
// рукопожатии.
func TestNormalizeSNIFromHostOnIPServer(t *testing.T) {
	nodes := corpusNodes(t)

	ip := byName(t, nodes, "Reality IP")
	if !ip.IsIP() {
		t.Fatalf("server %q не IP, тест проверяет не то", ip.Server)
	}
	if got := ip.Param("sni"); got != "front.example.com" {
		t.Errorf("sni %q, ожидался host front.example.com", got)
	}

	// Обратная сторона правила: у доменного сервера пустой sni так и остаётся
	// пустым — подставлять host туда нельзя, имя уже есть в адресе.
	dom := byName(t, nodes, "Default transport")
	if got := dom.Param("sni"); got != "" {
		t.Errorf("доменному серверу подставлен sni %q", got)
	}
}

// TestNormalizeTransportDefaults — §6.12: транспорт по умолчанию, tcp → raw
// (переименование Xray) и h2 → http.
func TestNormalizeTransportDefaults(t *testing.T) {
	nodes := corpusNodes(t)

	if n := byName(t, nodes, "Default transport"); n.Transport != node.Raw {
		t.Errorf("транспорт без type: %q, ожидался raw", n.Transport)
	}
	if n := byName(t, nodes, "TCP none"); n.Transport != node.Raw {
		t.Errorf("type=tcp: %q, ожидался raw", n.Transport)
	}
	h2 := byName(t, nodes, "H2")
	if h2.Transport != "http" {
		t.Errorf("type=h2: %q, ожидался http", h2.Transport)
	}
	// h2 нормализован, но нашей сборкой не поддержан — §6.11: узел в списке,
	// не в ошибке.
	if h2.Supported {
		t.Error("узел с транспортом http помечен поддержанным")
	}
}

// TestNormalizeSecurityAliases — §6.12: none/0/false и 1/true — это два
// значения, записанные четырьмя способами.
func TestNormalizeSecurityAliases(t *testing.T) {
	if n := byName(t, corpusNodes(t), "TCP none"); n.Security != node.SecNone {
		t.Errorf("security=0: %q, ожидался none", n.Security)
	}

	for _, tc := range []struct {
		raw  string
		want node.Security
	}{
		{"", node.SecNone},
		{"none", node.SecNone},
		{"0", node.SecNone},
		{"false", node.SecNone},
		{"1", node.SecTLS},
		{"true", node.SecTLS},
		{"tls", node.SecTLS},
		{"reality", node.SecReality},
	} {
		link := "vless://u@h.example.com:443?security=" + tc.raw
		n, err := sub.ParseLink(link)
		if err != nil {
			t.Fatalf("security=%q: %v", tc.raw, err)
		}
		if n.Security != tc.want {
			t.Errorf("security=%q → %q, ожидалось %q", tc.raw, n.Security, tc.want)
		}
	}
}

// TestNormalizeDefaultPort — §6.12: порт по умолчанию 443.
func TestNormalizeDefaultPort(t *testing.T) {
	if n := byName(t, corpusNodes(t), "Default port"); n.Port != 443 {
		t.Errorf("порт %d, ожидался 443", n.Port)
	}
}

// TestRealityKeepsKeys — reality остаётся отдельным значением security, а не
// сводится к tls: pbk/sid/spx без него некуда девать (§2, §6.12).
func TestRealityKeepsKeys(t *testing.T) {
	n := byName(t, corpusNodes(t), "Reality IP")
	if n.Security != node.SecReality {
		t.Fatalf("security %q, ожидался reality", n.Security)
	}
	for k, want := range map[string]string{"pbk": "PBKEY", "sid": "ab12", "spx": "/"} {
		if got := n.Param(k); got != want {
			t.Errorf("%s = %q, ожидалось %q", k, got, want)
		}
	}
}

// TestUnsupportedProtocolIsNode — §6.11: TUIC и hysteria2 доезжают до списка с
// supported=false, а не роняют импорт.
func TestUnsupportedProtocolIsNode(t *testing.T) {
	nodes := corpusNodes(t)

	tuic := byName(t, nodes, "TUIC")
	if tuic.Supported {
		t.Error("tuic помечен поддержанным")
	}
	if tuic.Server != "tuic.example.com" || tuic.Port != 443 {
		t.Errorf("адрес неизвестного протокола разобран как %s", tuic.Addr())
	}
	if hy := byName(t, nodes, "Hysteria2"); hy.Supported {
		t.Error("hysteria2 помечен поддержанным")
	}
}

// TestBrokenLinkSkipped — битая строка выпадает в ошибку, остальные узлы
// разбираются дальше (§6.11).
func TestBrokenLinkSkipped(t *testing.T) {
	body := []byte(strings.Join([]string{
		"vless://aaaa@a.example.com:443#A",
		"это не ссылка",
		"vless://bbbb@b.example.com:443#B",
	}, "\n"))

	nodes, err := sub.ParseSubscription(body, "g")
	if err == nil {
		t.Fatal("битая строка не попала в ошибку")
	}
	if len(nodes) != 2 {
		t.Fatalf("узлов %d, ожидалось 2", len(nodes))
	}
	if nodes[0].Name != "A" || nodes[1].Name != "B" {
		t.Errorf("разобраны не те узлы: %q, %q", nodes[0].Name, nodes[1].Name)
	}
	// §6.14: в тексте ошибки нет ни строки подписки, ни её обрывка — там
	// лежит ключ доступа, а ошибка уезжает в лог.
	if strings.Contains(err.Error(), "не ссылка\"") || strings.Contains(err.Error(), "vless://") {
		t.Errorf("ошибка содержит саму строку: %v", err)
	}
}

// TestVMessBase64JSON — у vmess своя форма: base64 от JSON, где транспорт
// лежит в `net`, а `type` — это маскировка, а не транспорт.
func TestVMessBase64JSON(t *testing.T) {
	n := byName(t, corpusNodes(t), "VMess WS")
	if n.Protocol != node.VMess {
		t.Fatalf("протокол %q", n.Protocol)
	}
	if n.Server != "vm.example.com" || n.Port != 8080 {
		t.Errorf("адрес %s", n.Addr())
	}
	if n.UserID != "88888888-8888-8888-8888-888888888888" {
		t.Errorf("id %q", n.UserID)
	}
	if n.Transport != node.WS {
		t.Errorf("транспорт %q, ожидался ws (поле net)", n.Transport)
	}
	if n.Security != node.SecTLS {
		t.Errorf("security %q, ожидался tls", n.Security)
	}
	if n.Param("path") != "/vm" || n.Param("fp") != "chrome" {
		t.Errorf("параметры разобраны как %v", n.Params)
	}
	if !n.Supported {
		t.Error("vmess+ws+tls не поддержан")
	}
}

// TestShadowsocksBothForms — SIP002 и устаревшая форма дают одинаковый по
// смыслу узел: метод в params, пароль в user_id.
func TestShadowsocksBothForms(t *testing.T) {
	nodes := corpusNodes(t)

	sip := byName(t, nodes, "SS SIP002")
	if sip.Server != "ss.example.com" || sip.Port != 8388 {
		t.Errorf("SIP002: адрес %s", sip.Addr())
	}
	if sip.Param("method") != "aes-256-gcm" || sip.UserID != "secret" {
		t.Errorf("SIP002: метод %q, пароль %q", sip.Param("method"), sip.UserID)
	}

	legacy := byName(t, nodes, "SS legacy")
	if legacy.Server != "ss2.example.com" || legacy.Port != 9000 {
		t.Errorf("устаревшая форма: адрес %s", legacy.Addr())
	}
	if legacy.Param("method") != "chacha20-ietf-poly1305" || legacy.UserID != "pass" {
		t.Errorf("устаревшая форма: метод %q, пароль %q", legacy.Param("method"), legacy.UserID)
	}
}

// TestFetchQuotaHeader — сырой заголовок Subscription-UserInfo доезжает до
// вызывающего как есть: разбирать его §7 (вопрос 3) ещё не решил.
func TestFetchQuotaHeader(t *testing.T) {
	const quota = "upload=1024; download=2048; total=107374182400; expire=2147483647"

	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-UserInfo", quota)
		w.Write([]byte(base64.StdEncoding.EncodeToString(raw)))
	}))
	defer srv.Close()

	body, got, err := sub.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got != quota {
		t.Errorf("quota_info = %q, ожидалось %q", got, quota)
	}
	nodes, err := sub.ParseSubscription(body, "g")
	if err != nil {
		t.Fatalf("разбор загруженного тела: %v", err)
	}
	if len(nodes) == 0 {
		t.Error("загруженное тело дало пустой список узлов")
	}
}

func corpusNodes(t *testing.T) []node.Node {
	t.Helper()
	raw, err := os.ReadFile(filepath.FromSlash(corpusPath))
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := sub.ParseSubscription(raw, "g")
	if err != nil {
		t.Fatalf("корпус разобран с ошибками: %v", err)
	}
	return nodes
}

func byName(t *testing.T, nodes []node.Node, name string) node.Node {
	t.Helper()
	for _, n := range nodes {
		if n.Name == name {
			return n
		}
	}
	t.Fatalf("в корпусе нет узла %q", name)
	return node.Node{}
}

// render — одна строка golden на узел. Параметры отсортированы: порядок карты
// в отпечаток попадать не должен.
func render(n node.Node) string {
	keys := make([]string, 0, len(n.Params))
	for k := range n.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+n.Params[k])
	}
	return fmt.Sprintf("%s | %s | %s | %s | %s | user=%s | supported=%v | key=%s | %s",
		n.Name, n.Protocol, n.Addr(), n.Transport, n.Security,
		n.UserID, n.Supported, n.MergeKey, strings.Join(pairs, ","))
}
