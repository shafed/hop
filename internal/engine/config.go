// Package engine — движок Xray-core за интерфейсом netstack.Dialer (§5.1).
//
// Один экземпляр Xray на всю жизнь агента, **один outbound на узел** и
// маршрутные правила по inboundTag. Так проба идёт ровно тем же путём, что и
// трафик (§6.7), и переключение узла не пересобирает движок: меняется тег, а не
// конфиг.
//
// Классификация ошибок §6.15 живёт в classify.go и нигде больше — за этим
// следит cmd/reportlint (D10).
package engine

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/shafed/hop/internal/node"
)

// tagOf — тег outbound и одноимённого маршрутного правила для узла.
func tagOf(nodeID string) string { return "n-" + nodeID }

// DirectTag — outbound «мимо узла». Нужен bootstrap-резолверу (§5.7) и
// пробам, которым надо отличить «узел мёртв» от «сети нет вовсе».
const DirectTag = "direct"

// xrayConfig — ровно те поля конфига Xray, которые мы заполняем. Собирать
// protobuf руками не нужно: JSON-путь Xray стабилен и разбирается его же
// кодом, то есть расхождение конфигурации с движком невозможно по построению.
type xrayConfig struct {
	Log       map[string]any `json:"log"`
	Outbounds []outbound     `json:"outbounds"`
	Routing   routing        `json:"routing"`
}

type outbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings,omitempty"`
	StreamSettings *stream         `json:"streamSettings,omitempty"`
}

type routing struct {
	DomainStrategy string `json:"domainStrategy"`
	Rules          []rule `json:"rules"`
}

type rule struct {
	Type        string   `json:"type"`
	InboundTag  []string `json:"inboundTag"`
	OutboundTag string   `json:"outboundTag"`
}

type stream struct {
	Network  string `json:"network"`
	Security string `json:"security,omitempty"`

	TLSSettings     *tlsSettings     `json:"tlsSettings,omitempty"`
	RealitySettings *realitySettings `json:"realitySettings,omitempty"`

	RawSettings         *rawSettings  `json:"rawSettings,omitempty"`
	WSSettings          *wsSettings   `json:"wsSettings,omitempty"`
	GRPCSettings        *grpcSettings `json:"grpcSettings,omitempty"`
	HTTPUpgradeSettings *wsSettings   `json:"httpupgradeSettings,omitempty"`
	XHTTPSettings       *xhttpSetting `json:"xhttpSettings,omitempty"`
	KCPSettings         *kcpSettings  `json:"kcpSettings,omitempty"`

	Sockopt *sockopt `json:"sockopt,omitempty"`
}

type tlsSettings struct {
	ServerName    string   `json:"serverName,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	AllowInsecure bool     `json:"allowInsecure,omitempty"`
}

type realitySettings struct {
	ServerName  string `json:"serverName,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	ShortID     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

type rawSettings struct {
	Header json.RawMessage `json:"header,omitempty"`
}

type wsSettings struct {
	Path string            `json:"path,omitempty"`
	Host string            `json:"host,omitempty"`
	Hdr  map[string]string `json:"headers,omitempty"`
}

type grpcSettings struct {
	ServiceName string `json:"serviceName,omitempty"`
	MultiMode   bool   `json:"multiMode,omitempty"`
}

type xhttpSetting struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
	Mode string `json:"mode,omitempty"`
}

type kcpSettings struct {
	Seed   string          `json:"seed,omitempty"`
	Header json.RawMessage `json:"header,omitempty"`
}

// sockopt — защита от петли на macOS и Windows (§6.8). На Linux петлю режет
// `ip rule` с UID-диапазоном, и здесь ничего не нужно.
type sockopt struct {
	Interface string `json:"interface,omitempty"`
}

// Options — то, от чего зависит сборка конфига.
type Options struct {
	// BindInterface — имя дефолтного интерфейса для sockopt.interface (§6.8).
	// Пусто на Linux.
	BindInterface string
	// LogLevel — уровень логов Xray. Пусто = "none": секреты не должны
	// попадать в логи даже на debug (§6.14).
	LogLevel string
}

// buildConfig собирает конфиг Xray из списка узлов. Неподдерживаемые узлы
// (§6.11) в конфиг не попадают: они не участвуют в выборе, и outbound для них
// был бы мёртвым весом.
func buildConfig(nodes []node.Node, opts Options) ([]byte, error) {
	level := opts.LogLevel
	if level == "" {
		level = "none"
	}

	cfg := xrayConfig{
		Log:     map[string]any{"loglevel": level},
		Routing: routing{DomainStrategy: "AsIs"},
	}

	for _, n := range nodes {
		if !n.Supported {
			continue
		}
		if err := n.Validate(); err != nil {
			return nil, err
		}
		ob, err := outboundOf(n, opts)
		if err != nil {
			return nil, err
		}
		cfg.Outbounds = append(cfg.Outbounds, ob)
		cfg.Routing.Rules = append(cfg.Routing.Rules, rule{
			Type:        "field",
			InboundTag:  []string{tagOf(n.ID)},
			OutboundTag: tagOf(n.ID),
		})
	}

	// direct идёт последним и не имеет правила: попасть в него можно только
	// по явному тегу. Дефолтом маршрутизации он не станет — иначе промах по
	// правилу молча выпускал бы трафик мимо туннеля, ровно то fail-open,
	// которое запрещает §5.6.
	cfg.Outbounds = append(cfg.Outbounds, outbound{
		Tag:            DirectTag,
		Protocol:       "freedom",
		StreamSettings: sockoptOnly(opts),
	})
	cfg.Routing.Rules = append(cfg.Routing.Rules, rule{
		Type:        "field",
		InboundTag:  []string{DirectTag},
		OutboundTag: DirectTag,
	})

	// Промах по всем правилам обязан упереться в blackhole, а не в первый
	// outbound: первый outbound — это какой-то узел, и промах отправил бы
	// туда чужой трафик.
	cfg.Outbounds = append(cfg.Outbounds, outbound{Tag: "block", Protocol: "blackhole"})

	return json.Marshal(cfg)
}

func sockoptOnly(opts Options) *stream {
	if opts.BindInterface == "" {
		return nil
	}
	return &stream{Network: "raw", Sockopt: &sockopt{Interface: opts.BindInterface}}
}

func outboundOf(n node.Node, opts Options) (outbound, error) {
	settings, err := protoSettings(n)
	if err != nil {
		return outbound{}, err
	}
	st, err := streamOf(n, opts)
	if err != nil {
		return outbound{}, err
	}
	return outbound{
		Tag:            tagOf(n.ID),
		Protocol:       string(n.Protocol),
		Settings:       settings,
		StreamSettings: st,
	}, nil
}

func protoSettings(n node.Node) (json.RawMessage, error) {
	port := int(n.Port)
	switch n.Protocol {
	case node.VLESS:
		user := map[string]any{"id": n.UserID, "encryption": "none"}
		if f := n.Param("flow"); f != "" {
			user["flow"] = f
		}
		return json.Marshal(map[string]any{
			"vnext": []any{map[string]any{
				"address": n.Server, "port": port, "users": []any{user},
			}},
		})
	case node.VMess:
		user := map[string]any{"id": n.UserID, "security": "auto"}
		if s := n.Param("scy"); s != "" {
			user["security"] = s
		}
		if a := n.Param("aid"); a != "" {
			aid, err := strconv.Atoi(a)
			if err != nil {
				return nil, fmt.Errorf("node %s: alterId %q: %w", n.ID, a, err)
			}
			user["alterId"] = aid
		}
		return json.Marshal(map[string]any{
			"vnext": []any{map[string]any{
				"address": n.Server, "port": port, "users": []any{user},
			}},
		})
	case node.Trojan:
		return json.Marshal(map[string]any{
			"servers": []any{map[string]any{
				"address": n.Server, "port": port, "password": n.UserID,
			}},
		})
	case node.Shadowsocks:
		return json.Marshal(map[string]any{
			"servers": []any{map[string]any{
				"address": n.Server, "port": port,
				"method": n.Param("method"), "password": n.UserID,
			}},
		})
	}
	return nil, fmt.Errorf("node %s: протокол %q не поддержан сборкой", n.ID, n.Protocol)
}

func streamOf(n node.Node, opts Options) (*stream, error) {
	st := &stream{Network: string(n.Transport)}
	if st.Network == "" {
		st.Network = string(node.Raw)
	}

	switch n.Transport {
	case node.Raw, "":
		if n.Param("headerType") == "http" {
			hdr, err := httpHeader(n)
			if err != nil {
				return nil, err
			}
			st.RawSettings = &rawSettings{Header: hdr}
		}
	case node.WS:
		st.WSSettings = &wsSettings{Path: n.Param("path"), Host: n.Param("host")}
	case node.HTTPUpgrade:
		st.HTTPUpgradeSettings = &wsSettings{Path: n.Param("path"), Host: n.Param("host")}
	case node.GRPC:
		st.GRPCSettings = &grpcSettings{
			ServiceName: n.Param("serviceName"),
			MultiMode:   n.Param("mode") == "multi",
		}
	case node.XHTTP:
		st.XHTTPSettings = &xhttpSetting{
			Path: n.Param("path"), Host: n.Param("host"), Mode: n.Param("mode"),
		}
	case node.MKCP:
		hdr, err := json.Marshal(map[string]any{"type": headerTypeOr(n, "none")})
		if err != nil {
			return nil, err
		}
		st.KCPSettings = &kcpSettings{Seed: n.Param("seed"), Header: hdr}
	default:
		return nil, fmt.Errorf("node %s: транспорт %q не поддержан сборкой", n.ID, n.Transport)
	}

	switch n.Security {
	case node.SecTLS:
		st.Security = "tls"
		st.TLSSettings = &tlsSettings{
			ServerName:    sni(n),
			ALPN:          splitALPN(n.Param("alpn")),
			Fingerprint:   n.Param("fp"),
			AllowInsecure: n.Param("allowInsecure") == "1",
		}
	case node.SecReality:
		st.Security = "reality"
		st.RealitySettings = &realitySettings{
			ServerName:  sni(n),
			Fingerprint: n.Param("fp"),
			PublicKey:   n.Param("pbk"),
			ShortID:     n.Param("sid"),
			SpiderX:     n.Param("spx"),
		}
	case node.SecNone, "":
	default:
		return nil, fmt.Errorf("node %s: security %q не поддержан сборкой", n.ID, n.Security)
	}

	if opts.BindInterface != "" {
		st.Sockopt = &sockopt{Interface: opts.BindInterface}
	}
	return st, nil
}

func httpHeader(n node.Node) (json.RawMessage, error) {
	req := map[string]any{}
	if h := n.Param("host"); h != "" {
		req["headers"] = map[string]any{"Host": strings.Split(h, ",")}
	}
	if p := n.Param("path"); p != "" {
		req["path"] = strings.Split(p, ",")
	}
	return json.Marshal(map[string]any{"type": "http", "request": req})
}

func headerTypeOr(n node.Node, def string) string {
	if h := n.Param("headerType"); h != "" {
		return h
	}
	return def
}

// sni — §6.12: сервер задан IP, sni пуст, host есть → sni = host.
func sni(n node.Node) string {
	if s := n.Param("sni"); s != "" {
		return s
	}
	if n.IsIP() {
		return n.Param("host")
	}
	return n.Server
}

func splitALPN(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}
