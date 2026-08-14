package engine

// Регистрации Xray. Протокол и транспорт попадают в экземпляр не по имени из
// конфига, а через init своего пакета: не импортированный отсюда транспорт
// разберётся в конфиге и упадёт на сборке экземпляра.
//
// Точечно, а не `main/distro/all`: тот тянет за собой CLI-команды, gRPC-API,
// загрузчик конфига по http(s) и observatory. Всё это — код, который в агенте
// не исполняется, но живёт в бинаре и расширяет поверхность.
//
// Список ровно соответствует тому, что умеет собрать config.go: протоколы
// §6.11 и транспорты §6.12. Инбаунды не нужны — SOCKS-инбаунда в системе нет
// вообще (§5.3), исходящее идёт через core.Dial.
import (
	// Обязательное ядро: диспетчер, менеджеры хендлеров, роутер по inboundTag.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"

	// Исходящие протоколы.
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"

	// Транспорты и их шифрование.
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/kcp"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"

	// Обфускация заголовка для raw и mkcp.
	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"

	// Разрывает цикл импорта core ← internet, без него outbound по тегу не
	// собирается.
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
)
