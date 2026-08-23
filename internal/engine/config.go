package engine

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/core"
)

// Node — то, что движку нужно, чтобы построить outbound. Подмножество §2:
// поля, которые не влияют на соединение (name, group_id, raw_link), сюда не
// едут — движок не знает про подписки (§3.4).
type Node struct {
	ID        string
	Protocol  string // vless | vmess | trojan | shadowsocks
	Server    string
	Port      int
	Transport string // raw/tcp | ws | grpc | httpupgrade | xhttp | mkcp
	Security  string // none | tls | reality
	Params    map[string]string
}

// Param — значение параметра узла или пусто.
func (n Node) Param(k string) string { return n.Params[k] }

// BuildConfig собирает конфиг Xray на набор узлов: по outbound на узел, тег
// `node-<id>`. Инбаундов нет вовсе — трафик приходит из netstack через
// core.Dial, а не через слушающий сокет (§5.3: граница пакетная, не SOCKS).
func BuildConfig(nodes []Node) (*core.Config, error) {
	out := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		ob, err := outboundJSON(n)
		if err != nil {
			return nil, err
		}
		out = append(out, ob)
	}

	cfg := map[string]any{
		// Логи Xray выключены: они содержат адреса узлов и запросов, а §6.14
		// запрещает такое даже на уровне debug.
		"log":       map[string]any{"loglevel": "none"},
		"outbounds": out,
	}
	b, err := jsonConfig(cfg)
	if err != nil {
		return nil, err
	}
	return loadConfig(b)
}

// outboundJSON — один узел в виде outbound'а Xray.
func outboundJSON(n Node) (map[string]any, error) {
	if n.ID == "" {
		return nil, fmt.Errorf("engine: узел без id")
	}
	if n.Server == "" || n.Port <= 0 || n.Port > 65535 {
		return nil, fmt.Errorf("engine: узел %q с негодным адресом %s:%d", n.ID, n.Server, n.Port)
	}

	settings, err := protocolSettings(n)
	if err != nil {
		return nil, err
	}
	stream, err := streamSettings(n)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"tag":            OutboundTag(n.ID),
		"protocol":       n.Protocol,
		"settings":       settings,
		"streamSettings": stream,
	}, nil
}

// protocolSettings — часть конфига, специфичная для протокола.
//
// Неподдерживаемые протоколы (§6.11) сюда не доходят: узел с
// `supported: false` не попадает ни в выбор, ни в конфиг. Ошибка здесь — это
// ошибка того, кто выставил `supported`, и она обязана быть громкой.
func protocolSettings(n Node) (map[string]any, error) {
	switch n.Protocol {
	case "vless":
		user := map[string]any{
			"id": n.Param("uuid"),
			// encryption у VLESS всегда none: шифрует транспорт, не протокол.
			"encryption": "none",
		}
		if flow := n.Param("flow"); flow != "" {
			user["flow"] = flow
		}
		return map[string]any{"vnext": []map[string]any{{
			"address": n.Server,
			"port":    n.Port,
			"users":   []map[string]any{user},
		}}}, nil

	case "vmess":
		user := map[string]any{"id": n.Param("uuid")}
		if aid := n.Param("alterId"); aid != "" {
			v, err := strconv.Atoi(aid)
			if err != nil {
				return nil, fmt.Errorf("engine: узел %q, негодный alterId %q", n.ID, aid)
			}
			user["alterId"] = v
		}
		if sec := n.Param("security"); sec != "" {
			user["security"] = sec
		}
		return map[string]any{"vnext": []map[string]any{{
			"address": n.Server,
			"port":    n.Port,
			"users":   []map[string]any{user},
		}}}, nil

	case "trojan":
		return map[string]any{"servers": []map[string]any{{
			"address":  n.Server,
			"port":     n.Port,
			"password": n.Param("password"),
		}}}, nil

	case "shadowsocks":
		return map[string]any{"servers": []map[string]any{{
			"address":  n.Server,
			"port":     n.Port,
			"method":   n.Param("method"),
			"password": n.Param("password"),
		}}}, nil

	default:
		return nil, fmt.Errorf("engine: узел %q, протокол %q не собирается этой сборкой (§6.11)", n.ID, n.Protocol)
	}
}

// streamSettings — транспорт и безопасность.
//
// Имена транспортов нормализуются здесь, а не у вызывающего: в ссылках ходит
// и `tcp`, и `raw` (§6.12), а Xray знает `raw`; `xhttp` у Xray называется
// `splithttp`. Одно место перевода — одно место, где это чинить.
func streamSettings(n Node) (map[string]any, error) {
	network := n.Transport
	switch network {
	case "", "tcp", "raw":
		network = "raw"
	case "ws", "websocket":
		network = "ws"
	case "grpc", "httpupgrade", "kcp", "mkcp":
		if network == "mkcp" {
			network = "kcp"
		}
	case "xhttp", "splithttp":
		network = "splithttp"
	default:
		return nil, fmt.Errorf("engine: узел %q, транспорт %q не собирается этой сборкой (§6.11)", n.ID, n.Transport)
	}

	stream := map[string]any{"network": network}

	switch n.Security {
	case "", "none":
		stream["security"] = "none"
	case "tls":
		stream["security"] = "tls"
		stream["tlsSettings"] = tlsSettings(n)
	case "reality":
		stream["security"] = "reality"
		rs := map[string]any{
			"serverName": n.Param("sni"),
			"publicKey":  n.Param("pbk"),
			"shortId":    n.Param("sid"),
			"spiderX":    n.Param("spx"),
		}
		if fp := n.Param("fp"); fp != "" {
			rs["fingerprint"] = fp
		}
		// pqv — постквантовая проверка REALITY. Параметр молодой: узлы без
		// него обязаны работать, узлы с ним — не терять его по дороге.
		if pqv := n.Param("pqv"); pqv != "" {
			rs["mldsa65Verify"] = pqv
		}
		stream["realitySettings"] = rs
	default:
		return nil, fmt.Errorf("engine: узел %q, security %q не собирается этой сборкой", n.ID, n.Security)
	}

	switch network {
	case "ws":
		ws := map[string]any{"path": pathOr(n, "/")}
		if host := n.Param("host"); host != "" {
			ws["host"] = host
		}
		stream["wsSettings"] = ws
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": n.Param("serviceName")}
	case "httpupgrade":
		hu := map[string]any{"path": pathOr(n, "/")}
		if host := n.Param("host"); host != "" {
			hu["host"] = host
		}
		stream["httpupgradeSettings"] = hu
	case "splithttp":
		sh := map[string]any{"path": pathOr(n, "/")}
		if host := n.Param("host"); host != "" {
			sh["host"] = host
		}
		stream["splithttpSettings"] = sh
	}

	return stream, nil
}

func tlsSettings(n Node) map[string]any {
	ts := map[string]any{}
	// §6.12: если сервер задан как IP, sni пуст, а host есть — sni берётся из
	// host. Здесь это не нормализация ссылки, а последний рубеж: без sni
	// рукопожатие уедет на IP и упрётся в чужой сертификат.
	sni := n.Param("sni")
	if sni == "" {
		sni = n.Param("host")
	}
	if sni != "" {
		ts["serverName"] = sni
	}
	if fp := n.Param("fp"); fp != "" {
		ts["fingerprint"] = fp
	}
	if alpn := n.Param("alpn"); alpn != "" {
		ts["alpn"] = strings.Split(alpn, ",")
	}
	if n.Param("allowInsecure") == "true" {
		ts["allowInsecure"] = true
	}
	return ts
}

func pathOr(n Node, def string) string {
	if p := n.Param("path"); p != "" {
		return p
	}
	return def
}
