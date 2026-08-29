// Package engine — движок Xray-core: генерация конфига, один outbound на узел,
// исходящие соединения через выбранный узел (§5.1, §3.4).
//
// Пакет не знает ни про подписки, ни про TUN (§3.4). Наружу он даёт ровно две
// вещи: соединение через конкретный узел и классификацию отказа по §6.15.
//
// **Один инстанс, а не инстанс на узел.** Все узлы живут в одном
// `core.Instance` как outbound'ы с тегами `node-<id>`, а выбор узла делается
// на каждом вызове через forced outbound tag
// (`app/dispatcher/default.go:459`). Инстанс на узел был бы проще, но
// подписка в 200 узлов означала бы 200 диспетчеров, 200 менеджеров политик и
// столько же наборов горутин — при том что health опрашивает их все (§6.5).
//
// **Следствие для §6.7.** Проба и трафик идут одним и тем же вызовом с одним и
// тем же тегом. «Тот же путь» здесь не соглашение, а единственный доступный
// способ: другого пути наружу у пакета нет.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	// Регистрация обработчиков: Xray собирает их через init(). Список
	// намеренно уже, чем main/distro/all — в него не входят commander,
	// observatory, metrics, stats и reverse: мы ими не пользуемся, а каждый
	// тянет свой набор зависимостей в бинарь пользователя.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	// Разрывает цикл импорта core в transport/internet — так же, как в distro/all.
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"

	// Протоколы. freedom нужен не пользователю, а тестовой стороне сервера
	// (§8.1: настоящие инбаунды в том же процессе).
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"

	// Транспорты §2. xhttp в Xray называется splithttp.
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/kcp"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

// Engine — запущенный Xray с набором узлов.
type Engine struct {
	mu    sync.RWMutex
	inst  *core.Instance
	nodes map[string]bool // id узлов, у которых есть outbound
	hooks map[string]*nodeDialConfig
}

// Config — как поднять движок.
type Config struct {
	Nodes []Node
	// Physical возвращает текущий физический default-интерфейс для каждого
	// нового сокета к узлу (§6.8). При непустом Nodes обязателен: непривязанный
	// fallback может вернуться в туннель.
	Physical InterfaceFunc
	// OnFailure получает вердикт §6.15 по отказу соединения с узлом. Именно
	// отсюда агент зовёт health.ReportFailure — и больше ниоткуда
	// (TestReportFailureHasOneCallSite).
	OnFailure func(*DialError)
}

// InterfaceFunc определяет физический интерфейс для нового сокета.
type InterfaceFunc func() (string, error)

// New поднимает движок с этими узлами и источником физического интерфейса.
// Пустой набор допустим: движок без узлов умеет только отказывать, и это
// законное состояние (§5.6).
func New(nodes []Node, physical InterfaceFunc) (*Engine, error) {
	return NewWithConfig(Config{Nodes: nodes, Physical: physical})
}

// NewWithConfig — то же с колбэком отказов.
func NewWithConfig(c Config) (*Engine, error) {
	nodes := c.Nodes
	if len(nodes) > 0 && c.Physical == nil {
		return nil, fmt.Errorf("engine: для узлов нужен физический интерфейс (§6.8)")
	}
	installDialer()
	takeXrayLogOffStdout()

	cfg, err := BuildConfig(nodes)
	if err != nil {
		return nil, err
	}
	inst, err := core.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("engine: не собрался инстанс Xray: %w", err)
	}
	if err := inst.Start(); err != nil {
		return nil, fmt.Errorf("engine: инстанс Xray не запустился: %w", err)
	}
	e := &Engine{
		inst: inst, nodes: make(map[string]bool, len(nodes)),
		hooks: make(map[string]*nodeDialConfig, len(nodes)),
	}
	for _, n := range nodes {
		e.nodes[n.ID] = true
		e.hooks[n.ID] = watchNode(n.ID, c.OnFailure, c.Physical)
	}
	return e, nil
}

// Close останавливает движок.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inst == nil {
		return nil
	}
	for id := range e.nodes {
		unwatchNode(id, e.hooks[id])
	}
	err := e.inst.Close()
	e.inst = nil
	return err
}

// DialTCP открывает TCP-соединение к addr через узел nodeID.
//
// Ошибка уже классифицирована по §6.15: см. DialError. Это единственное место
// в продукте, где строится смертельная ошибка узла, — иначе классификация
// расползётся по коду и однажды тихо начнёт считать смертью упавший сайт.
func (e *Engine) DialTCP(ctx context.Context, nodeID, addr string) (net.Conn, error) {
	e.mu.RLock()
	inst, known := e.inst, e.nodes[nodeID]
	e.mu.RUnlock()
	if inst == nil {
		return nil, &DialError{NodeID: nodeID, Kind: KindNone, Err: errClosed}
	}
	if !known {
		return nil, &DialError{NodeID: nodeID, Kind: KindNone, Err: fmt.Errorf("engine: узел %q не собран в конфиг", nodeID)}
	}

	dest, err := parseDestination(addr)
	if err != nil {
		return nil, &DialError{NodeID: nodeID, Kind: KindNone, Err: err}
	}

	conn, err := core.Dial(withNode(ctx, nodeID), inst, dest)
	if err != nil {
		return nil, classifyDial(nodeID, err)
	}
	// Соединение отдаётся лениво, отказ узла приезжает на первом вводе-выводе
	// — см. conn.go.
	return &classifiedConn{Conn: conn, nodeID: nodeID}, nil
}

// DialUDP открывает UDP-сокет через узел nodeID (§5.3: UDP идёт тем же путём).
func (e *Engine) DialUDP(ctx context.Context, nodeID string) (net.PacketConn, error) {
	e.mu.RLock()
	inst, known := e.inst, e.nodes[nodeID]
	e.mu.RUnlock()
	if inst == nil {
		return nil, &DialError{NodeID: nodeID, Kind: KindNone, Err: errClosed}
	}
	if !known {
		return nil, &DialError{NodeID: nodeID, Kind: KindNone, Err: fmt.Errorf("engine: узел %q не собран в конфиг", nodeID)}
	}

	pc, err := core.DialUDP(withNode(ctx, nodeID), inst)
	if err != nil {
		return nil, classifyDial(nodeID, err)
	}
	return &classifiedPacketConn{PacketConn: pc, nodeID: nodeID}, nil
}

// Nodes возвращает id узлов, собранных в конфиг.
func (e *Engine) Nodes() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, 0, len(e.nodes))
	for id := range e.nodes {
		out = append(out, id)
	}
	return out
}

// withNode заставляет диспетчер взять outbound именно этого узла.
// Механизм — `session.SetForcedOutboundTagToContext`, тот же, которым Xray
// обслуживает platform detour (`app/dispatcher/default.go:459`).
func withNode(ctx context.Context, nodeID string) context.Context {
	return session.SetForcedOutboundTagToContext(ctx, OutboundTag(nodeID))
}

// OutboundTag — тег outbound'а узла. Один узел — один тег, и обратно.
func OutboundTag(nodeID string) string { return "node-" + nodeID }

// parseDestination переводит "host:port" в адресат Xray. Домен остаётся
// доменом: резолвить его здесь нельзя, иначе роутинг и SNI увидят не то, что
// просило приложение.
func parseDestination(addr string) (xnet.Destination, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return xnet.Destination{}, fmt.Errorf("engine: неразборчивый адрес %q: %w", addr, err)
	}
	port, err := xnet.PortFromString(portStr)
	if err != nil {
		return xnet.Destination{}, fmt.Errorf("engine: неразборчивый порт в %q: %w", addr, err)
	}
	return xnet.TCPDestination(xnet.ParseAddress(host), port), nil
}

// jsonConfig — конфиг Xray в том же виде, в каком его читает сам Xray.
// Генерируем JSON, а не protobuf, ровно по причине §5.1: JSON — это то, что
// умеет отладить человек, и то, на что есть документация у апстрима.
func jsonConfig(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("engine: конфиг не сериализуется: %w", err)
	}
	return b, nil
}

// loadConfig собирает *core.Config из JSON.
func loadConfig(b []byte) (*core.Config, error) {
	cfg, err := serial.LoadJSONConfig(strings.NewReader(string(b)))
	if err != nil {
		return nil, fmt.Errorf("engine: Xray не принял конфиг: %w", err)
	}
	return cfg, nil
}

var errClosed = fmt.Errorf("engine: движок закрыт")
