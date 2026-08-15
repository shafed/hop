// Регистр проверок стора и подписок — docs/verification-store.md §5.
// S* — номера оттуда. Всё здесь уровня L1: чистая функция, golden-корпус в
// testdata, ни диска, ни сети.
//
// Правило корпуса — «одно правило §6.12 — один файл»: проверка нормализаций
// пачкой делает неотличимыми «работают все» и «работает первая».
package subscription

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shafed/hop/internal/store"
)

// golden читает файл корпуса и разбирает его.
func golden(t *testing.T, name string) Parsed {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("корпус %s не читается: %v", name, err)
	}
	p, err := Parse(body)
	if err != nil {
		t.Fatalf("корпус %s не разобрался: %v", name, err)
	}
	return p
}

// --- 5.2 Импорт не падает целиком (У2) ---------------------------------

// S10: сто ссылок, одна негодна — 99 узлов и одна учтённая причина, а не
// отказ целиком (§6.11).
func TestS10OneBrokenLineDoesNotKillImport(t *testing.T) {
	var b strings.Builder
	for i := range 100 {
		if i == 42 {
			b.WriteString("не ссылка вовсе, а строка от провайдера\n")
			continue
		}
		fmt.Fprintf(&b, "vless://11111111-1111-1111-1111-%012d@n%d.example.com:443?type=ws&security=tls#uzel-%d\n", i, i, i)
	}

	p, err := Parse([]byte(b.String()))
	if err != nil {
		t.Fatalf("импорт упал целиком из-за одной строки: %v", err)
	}
	if len(p.Nodes) != 99 {
		t.Errorf("узлов %d, ожидалось 99", len(p.Nodes))
	}
	if len(p.Unsupported) != 1 {
		t.Fatalf("негодных строк учтено %d, ожидалась 1", len(p.Unsupported))
	}
	if got := p.Unsupported[0].Reason; got != store.UnsupParse {
		t.Errorf("причина %v, ожидалась parse", got)
	}
}

// S11: ссылка на TUIC — узел с supported: false и причиной protocol. Узел
// есть, но в выбор не входит: пользователю нужно видеть, что провайдер его
// прислал, и чего этому узлу не хватает.
func TestS11TUICNodeIsUnsupportedByProtocol(t *testing.T) {
	p := golden(t, "s11_tuic.txt")
	if p.Format != FormatScheme {
		t.Errorf("формат %v, ожидался scheme: тело — одна ссылка", p.Format)
	}
	if len(p.Nodes) != 1 {
		t.Fatalf("узлов %d, ожидался 1", len(p.Nodes))
	}
	n := p.Nodes[0]
	if n.Protocol != "tuic" {
		t.Errorf("протокол %q, ожидался tuic", n.Protocol)
	}
	if n.Supported {
		t.Error("узел помечен поддержанным, хотя TUIC в нашей сборке Xray нет")
	}
	if n.UnsupReason != store.UnsupProtocol {
		t.Errorf("причина %v, ожидалась protocol", n.UnsupReason)
	}
}

// S12: известный протокол, неизвестный транспорт — причина transport, а не
// protocol: пересборка Xray тут ни при чём.
func TestS12UnknownTransportIsReportedAsTransport(t *testing.T) {
	p := golden(t, "s12_unknown_transport.txt")
	if len(p.Nodes) != 1 {
		t.Fatalf("узлов %d, ожидался 1", len(p.Nodes))
	}
	n := p.Nodes[0]
	if n.Supported {
		t.Error("узел помечен поддержанным, хотя транспорта quic наша сборка не умеет")
	}
	if n.UnsupReason != store.UnsupTransport {
		t.Errorf("причина %v, ожидалась transport", n.UnsupReason)
	}
}

// --- 5.3 Нормализация и каскад (У3) ------------------------------------

// S16: security приходит как none / 0 / false — нормализовано в none.
func TestS16SecurityNoneVariants(t *testing.T) {
	p := golden(t, "s16_security_none.txt")
	if len(p.Nodes) != 3 {
		t.Fatalf("узлов %d, ожидалось 3", len(p.Nodes))
	}
	for _, n := range p.Nodes {
		if n.Security != "none" {
			t.Errorf("узел %q: security %q, ожидалось none", n.Name, n.Security)
		}
		if !n.Supported {
			t.Errorf("узел %q не поддержан, причина %v", n.Name, n.UnsupReason)
		}
	}
}

// S17: security приходит как 1 / true — нормализовано в tls.
func TestS17SecurityTrueBecomesTLS(t *testing.T) {
	p := golden(t, "s17_security_true.txt")
	if len(p.Nodes) != 2 {
		t.Fatalf("узлов %d, ожидалось 2", len(p.Nodes))
	}
	for _, n := range p.Nodes {
		if n.Security != "tls" {
			t.Errorf("узел %q: security %q, ожидалось tls", n.Name, n.Security)
		}
	}
}

// S18: security=reality остаётся reality, а pbk/sid/spx сохранены (C6).
// Сведение к tls означало бы, что различать их придётся по наличию pbk в
// params, то есть восстанавливать выброшенное знание.
func TestS18RealityStaysReality(t *testing.T) {
	p := golden(t, "s18_reality.txt")
	if len(p.Nodes) != 1 {
		t.Fatalf("узлов %d, ожидался 1", len(p.Nodes))
	}
	n := p.Nodes[0]
	if n.Security != "reality" {
		t.Fatalf("security %q, ожидалось reality", n.Security)
	}
	for _, k := range []string{"pbk", "sid", "spx"} {
		if n.Param(k) == "" {
			t.Errorf("параметр %s потерян при разборе", k)
		}
	}
	if n.Param("spx") != "/" {
		t.Errorf("spx = %q, ожидалось / (percent-encoding не раскодирован)", n.Param("spx"))
	}
	if !n.Supported {
		t.Errorf("узел не поддержан, причина %v: reality с pbk наша сборка умеет", n.UnsupReason)
	}
}

// S19: h2 в транспорте нормализован в http. Такой узел наша сборка не умеет
// (§6.11, причина transport) — но нормализация обязана произойти до того, как
// это выяснится, иначе h2 и http были бы двумя разными «неизвестными».
func TestS19H2BecomesHTTP(t *testing.T) {
	p := golden(t, "s19_transport_h2.txt")
	if len(p.Nodes) != 1 {
		t.Fatalf("узлов %d, ожидался 1", len(p.Nodes))
	}
	n := p.Nodes[0]
	if n.Transport != "http" {
		t.Errorf("транспорт %q, ожидался http", n.Transport)
	}
	if n.UnsupReason != store.UnsupTransport {
		t.Errorf("причина %v, ожидалась transport", n.UnsupReason)
	}
}

// S20: сервер задан как IP, sni пуст, host есть — sni = host. У доменного
// адреса подстановки нет: там пустой sni означает «имя берётся из адреса».
func TestS20SNITakenFromHostForIPServer(t *testing.T) {
	p := golden(t, "s20_sni_from_host.txt")
	if len(p.Nodes) != 2 {
		t.Fatalf("узлов %d, ожидалось 2", len(p.Nodes))
	}
	if got := p.Nodes[0].Param("sni"); got != "cdn.example.org" {
		t.Errorf("sni у узла с IP = %q, ожидалось cdn.example.org", got)
	}
	if got := p.Nodes[1].Param("sni"); got != "" {
		t.Errorf("sni у узла с доменным адресом = %q, ожидалось пусто", got)
	}
}

// S21: порт не указан — 443. Указанный порт при этом не переписывается.
func TestS21DefaultPortIs443(t *testing.T) {
	p := golden(t, "s21_default_port.txt")
	if len(p.Nodes) != 2 {
		t.Fatalf("узлов %d, ожидалось 2", len(p.Nodes))
	}
	if p.Nodes[0].Port != 443 {
		t.Errorf("порт %d, ожидался 443 по умолчанию", p.Nodes[0].Port)
	}
	if p.Nodes[1].Port != 8443 {
		t.Errorf("порт %d, ожидался 8443 из ссылки", p.Nodes[1].Port)
	}
}

// S22: тело base64 берёт первая ступень, построчный разбор не запускается.
// Тело завёрнуто по 64 символа — построчно оно дало бы шесть бессмысленных
// строк вместо двух узлов.
//
// Охраняет parse_cascade: с выключенной политикой ступени объединяют
// результаты, развёрнутое тело уезжает в построчный разбор и узлы задваиваются.
func TestS22Base64BodyTakenByFirstStage(t *testing.T) {
	p := golden(t, "s22_base64_wrapped.txt")
	if p.Format != FormatBase64 {
		t.Errorf("формат %v, ожидался base64", p.Format)
	}
	if len(p.Nodes) != 2 {
		t.Fatalf("узлов %d, ожидалось 2: вход забирает одна ступень", len(p.Nodes))
	}
	if len(p.Unsupported) != 0 {
		t.Errorf("негодных строк %d, ожидалось 0: строки base64 разбирать нечем", len(p.Unsupported))
	}
	if p.Nodes[0].Server != "a.example.com" || p.Nodes[1].Server != "b.example.com" {
		t.Errorf("порядок или адреса узлов не те: %q, %q", p.Nodes[0].Server, p.Nodes[1].Server)
	}
}

// S23: тело с ключом proxies: распознано как Clash и отвергнуто одной внятной
// ошибкой (Р11, §4). Без этой ступени тот же файл проваливается в построчный
// разбор и даёт по бессмысленной ошибке на строку.
//
// Охраняет parse_cascade: с выключенной политикой ступени объединяют
// результаты, ошибка ступени перестаёт быть отказом, и настоящая причина тонет.
func TestS23ClashBodyRejectedWithOneError(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "s23_clash.yaml"))
	if err != nil {
		t.Fatalf("корпус не читается: %v", err)
	}

	p, err := Parse(body)
	if !errors.Is(err, ErrClashYAML) {
		t.Fatalf("ошибка %v, ожидалась ErrClashYAML", err)
	}
	if p.Format != FormatClash {
		t.Errorf("формат %v, ожидался clash: отказ обязан называть ступень, которая вход взяла", p.Format)
	}
	if len(p.Nodes) != 0 || len(p.Unsupported) != 0 {
		t.Errorf("разбор что-то вернул (%d узлов, %d негодных строк), а должен был отказать целиком",
			len(p.Nodes), len(p.Unsupported))
	}
}

// S24: base64-тело, содержимое которого разбирается и построчно, — узлы не
// задвоены: вход забрала одна ступень (§6.12).
//
// Охраняет parse_cascade: с выключенной политикой развёрнутое base64 уезжает
// дальше по каскаду и разбирается второй раз.
func TestS24Base64ContentIsNotParsedTwice(t *testing.T) {
	p := golden(t, "s24_base64_multiline.txt")
	if p.Format != FormatBase64 {
		t.Errorf("формат %v, ожидался base64", p.Format)
	}
	if len(p.Nodes) != 3 {
		t.Fatalf("узлов %d, ожидалось 3: base64-обёртка, разобравшаяся заодно построчно, даёт дубли", len(p.Nodes))
	}
	seen := map[string]bool{}
	for _, n := range p.Nodes {
		key := fmt.Sprintf("%s:%d", n.Server, n.Port)
		if seen[key] {
			t.Errorf("узел %s встретился дважды", key)
		}
		seen[key] = true
	}
}
