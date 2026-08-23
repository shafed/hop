package subscription

import (
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/shafed/hop/internal/store"
)

// defaultPort — порт по умолчанию из §6.12.
const defaultPort = 443

// Что умеет наша сборка Xray. Списки — зеркало internal/engine/config.go:
// supported и unsup_reason обязаны отражать именно её, а не общий список
// протоколов, которые бывают на свете. Правится вместе с движком: разъехавшись,
// эти два места дают либо узел, отброшенный зря, либо узел, который движок
// откажется собирать уже на подключении.
var (
	supportedProtocols = map[string]bool{
		"vless": true, "vmess": true, "trojan": true, "shadowsocks": true,
	}
	supportedTransports = map[string]bool{
		"raw": true, "ws": true, "grpc": true, "httpupgrade": true,
		"mkcp": true, "xhttp": true,
	}
	supportedSecurity = map[string]bool{
		"none": true, "tls": true, "reality": true,
	}
)

// parseLink разбирает одну ссылку. Второе значение — false, если строка не
// годится в узел вовсе: нет схемы, нет адреса, не разобралась. Такая строка
// уходит в Parsed.Unsupported с причиной parse и не рушит импорт (У2, §6.11).
//
// Разница между «строка не стала узлом» и «узел с supported: false» —
// практическая, та же, что в §6.11: во втором случае у пользователя есть узел,
// который он видит в списке и про который написано, чего не хватает; в первом
// показывать нечего, кроме самой строки.
func parseLink(link string) (Incoming, bool) {
	link = strings.TrimSpace(link)
	i := strings.Index(link, "://")
	if i <= 0 {
		return Incoming{}, false
	}
	scheme := strings.ToLower(link[:i])

	var (
		in Incoming
		ok bool
	)
	switch scheme {
	case "vmess":
		in, ok = parseVMess(link)
	case "ss", "shadowsocks":
		in, ok = parseShadowsocks(link)
	default:
		in, ok = parseURLForm(scheme, link)
	}
	if !ok || in.Server == "" {
		return Incoming{}, false
	}

	normalize(&in)
	classify(&in)
	return in, true
}

// parseURLForm — ссылки вида scheme://userinfo@host:port?query#name. Их
// подавляющее большинство: vless, trojan, стандартный vmess и все протоколы,
// которых наша сборка не умеет.
func parseURLForm(scheme, link string) (Incoming, bool) {
	u, err := url.Parse(link)
	if err != nil || u.Hostname() == "" {
		return Incoming{}, false
	}

	in := Incoming{
		RawLink: link,
		Name:    u.Fragment,
		Server:  u.Hostname(),
		Port:    portOr(u.Port(), defaultPort),
		Params:  map[string]string{},
	}
	for k, vs := range u.Query() {
		if len(vs) > 0 && vs[0] != "" {
			in.Params[k] = vs[0]
		}
	}

	switch scheme {
	case "vless":
		in.Protocol = "vless"
		set(in.Params, "uuid", u.User.Username())
	case "vmess":
		in.Protocol = "vmess"
		set(in.Params, "uuid", u.User.Username())
	case "trojan":
		in.Protocol = "trojan"
		set(in.Params, "password", u.User.Username())
	default:
		// Протокола нет в нашей сборке (§6.11). Узел всё равно строится:
		// пользователю нужно видеть, что провайдер такой узел прислал, и
		// чего этому узлу не хватает, — а не пустое место в списке.
		in.Protocol = canonicalProtocol(scheme)
	}
	return in, true
}

// parseVMess — две формы: v2rayN (base64 от JSON) и стандартная ссылка
// (XTLS/Xray-core discussions/716). Сначала пробуется первая: её тело не
// разбирается как URL и потерялось бы молча.
func parseVMess(link string) (Incoming, bool) {
	payload := link[len("vmess://"):]
	if dec, ok := decodeBase64(payload); ok {
		if in, ok := vmessFromJSON(link, dec); ok {
			return in, true
		}
	}
	return parseURLForm("vmess", link)
}

// vmessFromJSON — форма v2rayN. Поле "type" из этого JSON — headerType, а не
// транспорт; транспорт лежит в "net". Перепутать их значит выдать всем узлам
// с маскировкой под HTTP несуществующий транспорт.
func vmessFromJSON(link string, body []byte) (Incoming, bool) {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return Incoming{}, false
	}
	in := Incoming{
		RawLink:  link,
		Protocol: "vmess",
		Name:     jsonString(obj["ps"]),
		Server:   jsonString(obj["add"]),
		Port:     portOr(jsonString(obj["port"]), defaultPort),
		Params:   map[string]string{},
	}
	if in.Server == "" {
		return Incoming{}, false
	}
	set(in.Params, "uuid", jsonString(obj["id"]))
	set(in.Params, "alterId", jsonString(obj["aid"]))
	set(in.Params, "encryption", jsonString(obj["scy"]))
	set(in.Params, "host", jsonString(obj["host"]))
	set(in.Params, "path", jsonString(obj["path"]))
	set(in.Params, "sni", jsonString(obj["sni"]))
	set(in.Params, "type", jsonString(obj["net"]))
	set(in.Params, "security", jsonString(obj["tls"]))
	return in, true
}

// parseShadowsocks — три формы сразу: base64 всего тела (v2rayN), base64
// пользовательской части (традиционная) и открытый method:password (2022).
// Разбирается вручную, а не через url.Parse: в base64 обычного алфавита
// встречается «/», которого в userinfo быть не может, и url.Parse на таком
// теле отказывает.
func parseShadowsocks(link string) (Incoming, bool) {
	rest := link[strings.Index(link, "://")+3:]

	name := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		name, rest = unescape(rest[i+1:]), rest[:i]
	}
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query, rest = rest[i+1:], rest[:i]
	}

	if !strings.Contains(rest, "@") {
		// Форма v2rayN: в base64 лежит и адрес, и пользовательская часть.
		dec, ok := decodeBase64(rest)
		if !ok {
			return Incoming{}, false
		}
		rest = string(dec)
	}

	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return Incoming{}, false
	}
	host, port, ok := splitHostPort(rest[at+1:])
	if !ok {
		return Incoming{}, false
	}

	method, password := splitMethodPassword(rest[:at])
	in := Incoming{
		RawLink:  link,
		Protocol: "shadowsocks",
		Name:     name,
		Server:   host,
		Port:     port,
		Params:   map[string]string{},
	}
	set(in.Params, "method", method)
	set(in.Params, "password", password)
	if q, err := url.ParseQuery(query); err == nil {
		for k, vs := range q {
			if len(vs) > 0 && vs[0] != "" {
				in.Params[k] = vs[0]
			}
		}
	}
	return in, true
}

// splitMethodPassword — пользовательская часть ss-ссылки. Открытый вид с
// двоеточием (2022) отличается от base64 тем, что в алфавите base64 двоеточия
// нет вовсе.
func splitMethodPassword(userinfo string) (string, string) {
	userinfo = unescape(userinfo)
	if i := strings.Index(userinfo, ":"); i >= 0 {
		return userinfo[:i], userinfo[i+1:]
	}
	dec, ok := decodeBase64(userinfo)
	if !ok {
		return "", ""
	}
	if i := strings.Index(string(dec), ":"); i >= 0 {
		return string(dec[:i]), string(dec[i+1:])
	}
	return "", ""
}

// normalize — правила §6.12. Все они здесь и нигде больше: движок получает
// узел уже нормализованным, а не нормализует его заново на каждом подключении.
func normalize(in *Incoming) {
	in.Transport = normalizeTransport(in.Params["type"])
	delete(in.Params, "type")

	security := in.Params["security"]
	delete(in.Params, "security")
	if security == "" && in.Protocol == "trojan" {
		// Trojan без TLS не бывает: у него нет собственного шифрования,
		// весь протокол живёт внутри рукопожатия. Так же считает nekoray.
		security = "tls"
	}
	in.Security = normalizeSecurity(security)

	// У vmess в user.security лежит метод шифрования (auto, aes-128-gcm), а
	// не режим транспорта, и движок читает его из params под именем security.
	// Переносим уже после того, как транспортный security ушёл в своё поле, —
	// иначе одно имя означало бы две разные вещи.
	if in.Protocol == "vmess" {
		if enc := in.Params["encryption"]; enc != "" {
			in.Params["security"] = enc
			delete(in.Params, "encryption")
		}
	}

	// peer — старое имя sni; встречается в ссылках до сих пор.
	if in.Params["sni"] == "" && in.Params["peer"] != "" {
		in.Params["sni"] = in.Params["peer"]
	}
	// §6.12: сервер задан как IP, sni пуст, host есть — подставить sni = host.
	// Только для IP: у доменного адреса пустой sni означает «бери имя из
	// адреса», и подставлять туда host значит менять адресата рукопожатия.
	if in.Params["sni"] == "" && in.Params["host"] != "" && net.ParseIP(in.Server) != nil {
		in.Params["sni"] = in.Params["host"]
	}

	if in.Port <= 0 || in.Port > 65535 {
		in.Port = defaultPort
	}
}

// normalizeTransport — §6.12 плюс имена, которых у nekoray нет: xhttp и его
// синоним splithttp.
func normalizeTransport(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "tcp", "raw":
		return "raw"
	case "h2", "http":
		return "http"
	case "ws", "websocket":
		return "ws"
	case "kcp", "mkcp":
		return "mkcp"
	case "xhttp", "splithttp":
		return "xhttp"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

// normalizeSecurity — §6.12 по значениям. reality остаётся reality и не
// сводится к tls (C6, S18): §2 перечисляет security как none | tls | reality,
// движок разбирает reality отдельной веткой, и сведение означало бы
// восстанавливать выброшенное знание по наличию pbk в params.
func normalizeSecurity(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "none", "0", "false":
		return "none"
	case "1", "true":
		return "tls"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

// classify выставляет supported и unsup_reason (§6.11). Причина одна, и
// порядок проверок — это порядок ответа на вопрос «что пользователю делать».
// Протокол первым: не зная протокола, нельзя судить ни про обязательные поля,
// ни про транспорт. Затем обязательные поля: ссылка без ключа битая у
// провайдера независимо от того, поддержан ли её транспорт.
func classify(in *Incoming) {
	switch {
	case !supportedProtocols[in.Protocol]:
		reject(in, store.UnsupProtocol)
	case missingRequired(*in):
		reject(in, store.UnsupParse)
	case !supportedTransports[in.Transport]:
		reject(in, store.UnsupTransport)
	case !supportedSecurity[in.Security]:
		reject(in, store.UnsupSecurity)
	case in.Security == "reality" && in.Params["pbk"] == "":
		// reality без публичного ключа собрать нельзя: §6.11 называет этот
		// случай прямо — «reality без нужных параметров».
		reject(in, store.UnsupSecurity)
	default:
		in.Supported = true
		in.UnsupReason = store.UnsupNone
	}
}

func reject(in *Incoming, r store.UnsupReason) {
	in.Supported = false
	in.UnsupReason = r
}

// missingRequired — ссылка разобрана, но обязательного поля не хватает
// (§6.11, причина parse).
func missingRequired(in Incoming) bool {
	switch in.Protocol {
	case "vless", "vmess":
		return in.Params["uuid"] == ""
	case "trojan":
		return in.Params["password"] == ""
	case "shadowsocks":
		return in.Params["method"] == "" || in.Params["password"] == ""
	default:
		return false
	}
}

// canonicalProtocol сводит синонимы схем к одному имени, чтобы сводка импорта
// не считала hy2 и hysteria2 разными протоколами.
func canonicalProtocol(scheme string) string {
	switch scheme {
	case "hy2":
		return "hysteria2"
	case "hy":
		return "hysteria"
	case "wg":
		return "wireguard"
	default:
		return scheme
	}
}

// splitHostPort — адрес с портом или без, включая литеральный IPv6 в скобках.
func splitHostPort(s string) (string, int, bool) {
	if s == "" {
		return "", 0, false
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, false
		}
		host := s[1:end]
		rest := s[end+1:]
		if strings.HasPrefix(rest, ":") {
			return host, portOr(rest[1:], defaultPort), host != ""
		}
		return host, defaultPort, host != ""
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		return s[:i], portOr(s[i+1:], defaultPort), s[:i] != ""
	}
	return s, defaultPort, true
}

// portOr — порт по умолчанию 443 (§6.12), в том числе когда порт указан
// мусором: ссылка с непонятным портом всё равно даёт узел, и его
// работоспособность решит первая же проба.
func portOr(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 65535 {
		return def
	}
	return n
}

func set(m map[string]string, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func unescape(s string) string {
	if out, err := url.PathUnescape(s); err == nil {
		return out
	}
	return s
}

// jsonString — значение поля v2rayN-JSON как строка: провайдеры шлют port и
// aid то числом, то строкой.
func jsonString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}
