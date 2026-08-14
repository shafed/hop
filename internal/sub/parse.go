// Package sub — загрузка и разбор подписок (§6.12, §6.16).
//
// Разбор недоверенного текста, поэтому пакет ничего не знает ни про стор, ни
// про здоровье, ни про движок: на входе байты, на выходе []node.Node.
//
// Каскад распознавания §6.12 — по убыванию специфичности:
//
//	base64      → раскодировать и начать заново
//	Clash YAML  → по наличию `proxies:` (отклонение C5: распознаётся, но не
//	              разбирается — явный отказ вместо каши из YAML-строк)
//	построчно   → каждая строка как отдельная ссылка
//	по схеме    → vless:// vmess:// trojan:// ss:// ...
//
// Одна нераспознанная строка не роняет импорт: узел с неизвестным протоколом
// доезжает до списка с supported=false (§6.11).
//
// В текст ошибок не попадает ни строка подписки, ни её обрывок: в ссылке лежит
// ключ доступа, а ошибки уходят в лог (§6.14).
package sub

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/shafed/hop/internal/node"
	"github.com/shafed/hop/internal/policy"
)

// defaultPort — §6.12: порт по умолчанию 443.
const defaultPort = 443

// ParseLink разбирает одну ссылку.
//
// Нормализации §6.12, взятые построчно из nekoray (`fmt/Link2Bean.cpp`):
// security приходит как none/0/false/1/true; reality → tls плюс pbk/sid/spx;
// h2 → http; сервер задан IP, sni пуст, host есть → sni = host; порт по
// умолчанию 443. Список транспортов шире, чем у nekoray: там нет xhttp.
//
// Ошибка — только на нераспознаваемой строке. Неизвестный протокол ошибкой не
// является: это валидный узел с supported=false (§6.11).
func ParseLink(raw string) (node.Node, error) {
	raw = strings.TrimSpace(raw)
	scheme, body, ok := strings.Cut(raw, "://")
	if !ok || scheme == "" || body == "" {
		return node.Node{}, errors.New("sub: строка не похожа на ссылку")
	}
	scheme = strings.ToLower(scheme)

	var (
		n   node.Node
		err error
	)
	switch scheme {
	case "vless":
		n, err = parseUserAt(raw, node.VLESS)
	case "trojan":
		n, err = parseUserAt(raw, node.Trojan)
	case "vmess":
		n, err = parseVMess(body)
	case "ss":
		n, err = parseShadowsocks(body)
	default:
		// §6.11: TUIC, AnyTLS и прочее — не ошибка разбора. Адрес и имя из
		// такой ссылки читаются той же формой «user@host:port?query».
		n, err = parseUserAt(raw, node.Protocol(scheme))
	}
	if err != nil {
		return node.Node{}, err
	}
	n.RawLink = raw
	normalize(&n)
	return n, nil
}

// ParseSubscription разбирает тело подписки в узлы группы groupID, сохраняя
// порядок (§2, Group.node_order).
//
// Каждому узлу проставляется MergeKey: ключ считается здесь, потому что он
// выводится из разобранной ссылки, а стор про ссылки не знает вовсе.
//
// Ошибка возвращается вместе с узлами: битые строки перечислены в ней, а
// разобранное отдано наверх — импорт не падает целиком из-за одной строки
// (§6.11). Пустой список узлов при непустой ошибке и означает «не разобралось».
func ParseSubscription(body []byte, groupID string) ([]node.Node, error) {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return nil, errors.New("sub: пустое тело подписки")
	}
	// base64 идёт первым: провайдер, кодирующий тело, кодирует им и построчный
	// список, и Clash YAML, — что внутри, видно только после раскодирования.
	if dec, ok := decodeBody(text); ok {
		text = dec
	}
	if isClash(text) {
		return nil, errors.New("sub: тело похоже на Clash YAML, он не поддержан (отклонение C5)")
	}

	var (
		nodes []node.Node
		errs  []error
	)
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		n, err := ParseLink(line)
		if err != nil {
			errs = append(errs, fmt.Errorf("строка %d: %w", i+1, err))
			continue
		}
		n.GroupID = groupID
		n.MergeKey = MergeKey(n)
		nodes = append(nodes, n)
	}
	if len(nodes) == 0 && len(errs) == 0 {
		return nil, errors.New("sub: в теле подписки нет ссылок")
	}
	return nodes, errors.Join(errs...)
}

// MergeKey — ключ слияния §6.16: protocol + server + port + user_id.
//
// Смена транспорта, SNI или имени на том же сервере — тот же узел, история проб
// сохраняется. Смена сервера, порта или ключа — новый узел.
//
// nekoray предлагает два варианта (`ProfileFilter_ent_key`), и оба хуже:
// полный отпечаток не переживает косметическую правку у провайдера и обнуляет
// историю на ровном месте, ключ только по адресу склеивает узлы,
// различающиеся ключом доступа.
//
// Политика merge_key: при выключении ключ становится полным отпечатком, и
// смена SNI обнуляет историю — это краснит T18.
func MergeKey(n node.Node) string {
	if !policy.MergeKey.On() {
		return fingerprint(n)
	}
	return strings.Join([]string{
		string(n.Protocol), n.Server, strconv.Itoa(int(n.Port)), n.UserID,
	}, "|")
}

// fingerprint — отвергнутый §6.16 вариант ключа: в него входит всё, включая
// sni и имя. Живёт здесь только ради развилки политики.
func fingerprint(n node.Node) string {
	parts := []string{
		string(n.Protocol), n.Server, strconv.Itoa(int(n.Port)), n.UserID,
		string(n.Transport), string(n.Security), n.Name,
	}
	keys := make([]string, 0, len(n.Params))
	for k := range n.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+"="+n.Params[k])
	}
	return strings.Join(parts, "|")
}

// parseUserAt — форма «схема://userinfo@host:port?query#fragment». По ней
// устроены vless, trojan и все неизвестные нам протоколы.
func parseUserAt(raw string, proto node.Protocol) (node.Node, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return node.Node{}, fmt.Errorf("sub: %s: ссылка не разобрана", proto)
	}
	if u.Hostname() == "" {
		return node.Node{}, fmt.Errorf("sub: %s: пустой адрес", proto)
	}
	port, err := portOf(u.Port())
	if err != nil {
		return node.Node{}, fmt.Errorf("sub: %s: %w", proto, err)
	}
	q := u.Query()
	return node.Node{
		Protocol:  proto,
		Name:      u.Fragment,
		Server:    u.Hostname(),
		Port:      port,
		Transport: node.Transport(q.Get("type")),
		Security:  node.Security(q.Get("security")),
		UserID:    u.User.Username(),
		Params:    paramsOf(q),
	}, nil
}

// parseVMess — тело ссылки это base64 от JSON, а не URL: у vmess своя форма,
// и порт в ней приходит то числом, то строкой (отсюда json.Number).
func parseVMess(body string) (node.Node, error) {
	payload, _, _ := strings.Cut(body, "#")
	dec, err := decodeBase64(payload)
	if err != nil {
		return node.Node{}, errors.New("sub: vmess: тело не base64")
	}
	var v struct {
		PS   string      `json:"ps"`
		Add  string      `json:"add"`
		Port json.Number `json:"port"`
		ID   string      `json:"id"`
		Aid  json.Number `json:"aid"`
		Scy  string      `json:"scy"`
		Net  string      `json:"net"`
		Type string      `json:"type"`
		Host string      `json:"host"`
		Path string      `json:"path"`
		TLS  string      `json:"tls"`
		SNI  string      `json:"sni"`
		ALPN string      `json:"alpn"`
		FP   string      `json:"fp"`
	}
	if err := json.Unmarshal(dec, &v); err != nil {
		return node.Node{}, errors.New("sub: vmess: тело не JSON")
	}
	if v.Add == "" {
		return node.Node{}, errors.New("sub: vmess: пустой адрес")
	}
	port, err := portOf(v.Port.String())
	if err != nil {
		return node.Node{}, fmt.Errorf("sub: vmess: %w", err)
	}

	params := map[string]string{}
	put := func(k, val string) {
		if val != "" {
			params[k] = val
		}
	}
	put("aid", v.Aid.String())
	put("scy", v.Scy)
	// `type` в JSON vmess — это тип маскировки, а не транспорт: транспорт
	// лежит в `net`. Имена ключей совпадают с теми, что читает engine.
	put("headerType", v.Type)
	put("host", v.Host)
	put("path", v.Path)
	put("sni", v.SNI)
	put("alpn", v.ALPN)
	put("fp", v.FP)
	if strings.EqualFold(v.Net, "grpc") {
		// У grpc имя сервиса приезжает в поле path — так его кладёт nekoray.
		put("serviceName", v.Path)
	}

	return node.Node{
		Protocol:  node.VMess,
		Name:      v.PS,
		Server:    v.Add,
		Port:      port,
		Transport: node.Transport(v.Net),
		Security:  node.Security(v.TLS),
		UserID:    v.ID,
		Params:    params,
	}, nil
}

// parseShadowsocks — две живые формы разом: SIP002
// (`ss://base64(method:password)@host:port`) и устаревшая
// (`ss://base64(method:password@host:port)`). Различаются наличием `@` до
// раскодирования.
func parseShadowsocks(body string) (node.Node, error) {
	payload, frag, _ := strings.Cut(body, "#")
	name := unescape(frag)

	var query url.Values
	if head, tail, ok := strings.Cut(payload, "?"); ok {
		payload = head
		query, _ = url.ParseQuery(tail)
	}
	if !strings.Contains(payload, "@") {
		dec, err := decodeBase64(payload)
		if err != nil {
			return node.Node{}, errors.New("sub: ss: тело не разобрано")
		}
		payload = string(dec)
	}
	at := strings.LastIndex(payload, "@")
	if at < 0 {
		return node.Node{}, errors.New("sub: ss: нет разделителя адреса")
	}
	userinfo, hostport := payload[:at], payload[at+1:]
	// В SIP002 userinfo закодирован, в устаревшей форме — уже нет.
	if dec, err := decodeBase64(userinfo); err == nil && strings.Contains(string(dec), ":") {
		userinfo = string(dec)
	}
	method, password, ok := strings.Cut(unescape(userinfo), ":")
	if !ok || method == "" {
		return node.Node{}, errors.New("sub: ss: нет метода шифрования")
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		host, portStr = strings.Trim(hostport, "[]"), ""
	}
	if host == "" {
		return node.Node{}, errors.New("sub: ss: пустой адрес")
	}
	port, err := portOf(portStr)
	if err != nil {
		return node.Node{}, fmt.Errorf("sub: ss: %w", err)
	}

	params := paramsOf(query)
	params["method"] = method
	return node.Node{
		Protocol: node.Shadowsocks,
		Name:     name,
		Server:   host,
		Port:     port,
		UserID:   password,
		Params:   params,
	}, nil
}

// normalize — §6.12 в одном месте: то, что применяется к узлу независимо от
// формы, из которой он приехал.
func normalize(n *node.Node) {
	if n.Params == nil {
		n.Params = map[string]string{}
	}
	// Регистр. Схема, хост и значения приходят как попало (`VLESS://`,
	// `type=WS`, `security=TLS`), а server входит в ключ слияния §6.16: без
	// приведения регистра один узел после правки у провайдера разъезжается на
	// два и теряет историю.
	n.Server = strings.ToLower(n.Server)
	n.Transport = normTransport(string(n.Transport))
	n.Security = normSecurity(string(n.Security))
	if n.Port == 0 {
		n.Port = defaultPort
	}
	// §6.12: сервер задан IP, sni пуст, host есть → sni = host. Иначе TLS
	// уходит без имени, и узел отваливается на рукопожатии.
	if n.Params["sni"] == "" && n.IsIP() {
		if h := n.Params["host"]; h != "" {
			n.Params["sni"] = h
		}
	}
	n.Supported = supported(*n)
}

// normTransport — §6.12: h2 → http, плюс переименование tcp → raw, которое
// Xray сделал у себя. Незнакомое значение сохраняется как есть: оно поедет в
// supported=false, а не потеряется.
func normTransport(v string) node.Transport {
	switch v = strings.ToLower(strings.TrimSpace(v)); v {
	case "", "tcp", "raw":
		return node.Raw
	case "h2", "http":
		return "http"
	case "kcp", "mkcp":
		return node.MKCP
	default:
		return node.Transport(v)
	}
}

// normSecurity — §6.12: none/0/false и 1/true — те же два значения, записанные
// четырьмя способами. reality остаётся отдельным значением, а не сводится к
// tls: §2 перечисляет его наравне, и pbk/sid/spx без него некуда девать.
func normSecurity(v string) node.Security {
	switch v = strings.ToLower(strings.TrimSpace(v)); v {
	case "", "none", "0", "false":
		return node.SecNone
	case "1", "true", "tls":
		return node.SecTLS
	case "reality":
		return node.SecReality
	default:
		return node.Security(v)
	}
}

// supported — §6.11: умеет ли это наша сборка Xray. Ровно то перечисление,
// которое разбирает engine.buildConfig; всё прочее едет в список неживым.
func supported(n node.Node) bool {
	switch n.Protocol {
	case node.VLESS, node.VMess, node.Trojan, node.Shadowsocks:
	default:
		return false
	}
	switch n.Transport {
	case node.Raw, node.WS, node.XHTTP, node.GRPC, node.HTTPUpgrade, node.MKCP:
	default:
		return false
	}
	switch n.Security {
	case node.SecNone, node.SecTLS, node.SecReality:
	default:
		return false
	}
	return n.Server != "" && n.Port != 0 && n.UserID != ""
}

func portOf(v string) (uint16, error) {
	if v == "" {
		return defaultPort, nil
	}
	p, err := strconv.ParseUint(v, 10, 16)
	if err != nil || p == 0 {
		return 0, errors.New("порт не разобран")
	}
	return uint16(p), nil
}

// paramsOf — query как есть, без пустых значений: пустой sni обязан выглядеть
// отсутствующим, иначе подстановка sni = host не сработает.
func paramsOf(q url.Values) map[string]string {
	params := map[string]string{}
	for k, v := range q {
		if k == "type" || k == "security" {
			continue // уехали в поля Transport и Security
		}
		if len(v) > 0 && v[0] != "" {
			params[k] = v[0]
		}
	}
	return params
}

// decodeBody — тело целиком закодировано base64 (§6.12). Признак — что после
// раскодирования в нём появились ссылки: случайный текст в base64 не декодится
// вовсе, а декодированный мусор ссылок не содержит.
func decodeBody(text string) (string, bool) {
	dec, err := decodeBase64(text)
	if err != nil || !strings.Contains(string(dec), "://") {
		return "", false
	}
	return string(dec), true
}

// isClash — Clash YAML узнаётся по ключу верхнего уровня `proxies:`.
func isClash(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "proxies:") {
			return true
		}
	}
	return false
}

// decodeBase64 принимает все четыре диалекта: обычный и URL-безопасный,
// с выравниванием и без. Провайдеры пользуются всеми.
func decodeBase64(s string) ([]byte, error) {
	s = strings.Map(dropSpace, s)
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, errors.New("пусто")
	}
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("не base64")
}

func dropSpace(r rune) rune {
	switch r {
	case ' ', '\t', '\r', '\n':
		return -1
	}
	return r
}

// unescape — процентное кодирование в имени и userinfo. Неразобранное берётся
// как есть: имя узла — украшение, ронять из-за него ссылку незачем.
func unescape(s string) string {
	if v, err := url.PathUnescape(s); err == nil {
		return v
	}
	return s
}
