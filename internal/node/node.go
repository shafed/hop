// Package node — модель узла из §2.
//
// Узел описывает, куда и как ходить. Живость к нему не относится: NodeHealth
// живёт отдельно, потому что обновляется на порядки чаще (§2).
package node

import (
	"fmt"
	"net/netip"
	"strconv"
)

// Protocol — протокол узла. Строка, а не перечисление: подписка приносит
// протоколы, которых наша сборка не знает, и они обязаны доехать до списка с
// supported=false, а не сломать разбор (§6.11).
type Protocol string

const (
	VLESS       Protocol = "vless"
	VMess       Protocol = "vmess"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
)

// Transport — транспорт под протоколом.
type Transport string

const (
	Raw         Transport = "raw"
	WS          Transport = "ws"
	XHTTP       Transport = "xhttp"
	GRPC        Transport = "grpc"
	HTTPUpgrade Transport = "httpupgrade"
	MKCP        Transport = "mkcp"
)

// Security — шифрование транспорта.
type Security string

const (
	SecNone    Security = "none"
	SecTLS     Security = "tls"
	SecReality Security = "reality"
)

// Node — §2. Params держит всё, что специфично для протокола и транспорта:
// раскладывать это по полям пришлось бы заново на каждый новый транспорт.
type Node struct {
	ID       string
	GroupID  string
	MergeKey string
	Name     string

	Protocol  Protocol
	Server    string
	Port      uint16
	Transport Transport
	Security  Security

	// UserID — `id` для VLESS/VMess, пароль для Trojan. Часть ключа слияния
	// (§6.16), поэтому вынесен из Params.
	UserID string

	Params map[string]string

	Supported bool
	RawLink   string
}

// Addr — «хост:порт» узла.
func (n Node) Addr() string {
	return n.Server + ":" + strconv.Itoa(int(n.Port))
}

// Param возвращает значение или пустую строку.
func (n Node) Param(k string) string { return n.Params[k] }

// Validate ловит узлы, из которых нельзя собрать outbound. Не подменяет
// supported: неподдерживаемый протокол — это валидный узел, который просто не
// участвует в выборе (§6.11).
func (n Node) Validate() error {
	switch {
	case n.ID == "":
		return fmt.Errorf("node: пустой id")
	case n.Server == "":
		return fmt.Errorf("node %s: пустой server", n.ID)
	case n.Port == 0:
		return fmt.Errorf("node %s: нулевой порт", n.ID)
	}
	return nil
}

// IsIP — задан ли сервер адресом, а не именем. Нужно §6.12: при IP-сервере
// пустой sni подменяется на host.
func (n Node) IsIP() bool {
	_, err := netip.ParseAddr(n.Server)
	return err == nil
}
