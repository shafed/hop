// Package store — модели узла и группы и их персистентность (§2, §3.4).
// Регистр проверок — docs/verification-store.md.
//
// Узел здесь — источник истины: `engine` и `health` получают из него проекции
// явными функциями (§2), а не делят с ним один общий тип. Ценой двух функций
// покупаются обе границы §3.4: движок не узнаёт про группы и подписки, живость
// не получает доступа к ключам.
//
// Стор ничего не знает про слияние: `subscription` решает, что с чем слилось, и
// приносит готовый состав в Merged. Обратного импорта store → subscription нет
// и быть не должно — он замкнул бы цикл (docs/verification-store.md §2).
package store

import (
	"maps"
	"time"

	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/health"
)

// ManualGroupID — идентификатор специальной группы «ручные узлы» (§2). Он же её
// имя: подписки за ней нет, source_url пуст, и слияние в ней не работает — у
// каждого `hop node add` свой новый id (Р10, docs/verification-store.md §3).
const ManualGroupID = "manual"

// UnsupReason — почему наша сборка Xray не умеет узел (§6.11). Замкнутое
// перечисление, а не строка: по нему группируется сводка импорта (§1/С2), и
// пользователю важно не «сколько», а «чего не хватает».
//
// Нулевое значение означает «причины нет»: поле заполняется только при
// Supported == false (§2).
type UnsupReason uint8

const (
	// UnsupNone — узел поддержан, причины нет.
	UnsupNone UnsupReason = iota
	// UnsupProtocol — протокола нет в нашей сборке Xray. Пересборка могла бы
	// помочь.
	UnsupProtocol
	// UnsupTransport — протокол есть, транспорта нет.
	UnsupTransport
	// UnsupSecurity — есть оба, не поддержан режим: reality без нужных
	// параметров и подобное.
	UnsupSecurity
	// UnsupParse — ссылка разобрана, но обязательного поля не хватает. Это
	// битая ссылка у провайдера, а не наш пробел.
	UnsupParse
)

// String даёт ровно те строки, которыми §6.11 называет причины: они уезжают в
// сводку импорта и в `hop nodes`.
func (r UnsupReason) String() string {
	switch r {
	case UnsupProtocol:
		return "protocol"
	case UnsupTransport:
		return "transport"
	case UnsupSecurity:
		return "security"
	case UnsupParse:
		return "parse"
	case UnsupNone:
		return ""
	default:
		return "unknown"
	}
}

// Node — узел целиком (§2). Полный узел живёт только здесь.
type Node struct {
	// ID — стабильный идентификатор, выданный при первом появлении узла. Он
	// переживает обновление подписки: в этом всё обещание §5.8.
	ID string
	// GroupID — группа-владелец. Вместе с MergeKey образует настоящий ключ
	// слияния: он действует внутри группы, а не глобально (Р9).
	GroupID string
	// MergeKey — ключ слияния по §6.16, посчитанный один раз при импорте.
	// Хранимое поле, а не вычисляемое на лету: смена правила §6.16 обязана
	// быть явной миграцией, иначе она молча переопределяет, какие узлы «те же
	// самые», и обнуляет историю проб.
	MergeKey string
	// Name — отображаемое имя из #fragment ссылки.
	Name string
	// Protocol — vless | vmess | trojan | shadowsocks | hysteria2 | wireguard | ...
	Protocol string
	// Server — хост или IP.
	Server string
	Port   int
	// Transport — raw | ws | xhttp | grpc | httpupgrade | mkcp | hysteria.
	Transport string
	// Security — none | tls | reality.
	Security string
	// Params — всё остальное, специфичное для протокола и транспорта. Здесь
	// лежат ключи доступа (uuid, пароли, pbk), поэтому весь nodes.json — файл
	// с секретами (Р12, §6.14).
	Params map[string]string
	// Supported — умеет ли это наша сборка Xray (§6.11). Неподдержанный узел
	// попадает в список, но не участвует в выборе.
	Supported bool
	// UnsupReason — заполняется только при Supported == false (§2).
	UnsupReason UnsupReason
	// RawLink — исходная ссылка целиком, для отладки и переэкспорта.
	RawLink string
}

// Param — значение параметра узла или пусто.
func (n Node) Param(k string) string { return n.Params[k] }

// ToEngine — проекция узла для движка (§2). Поля, не влияющие на соединение
// (name, group_id, merge_key, raw_link), не едут: движок не знает про подписки
// (§3.4). Params копируются, а не отдаются той же картой, — иначе граница
// держалась бы на договорённости не писать в чужое.
func (n Node) ToEngine() engine.Node {
	return engine.Node{
		ID:        n.ID,
		Protocol:  n.Protocol,
		Server:    n.Server,
		Port:      n.Port,
		Transport: n.Transport,
		Security:  n.Security,
		Params:    maps.Clone(n.Params),
	}
}

// ToHealth — проекция узла для живости (§2). Живости хватает id и того, можно
// ли узел вообще пробовать; ключей она не получает.
func (n Node) ToHealth() health.Node {
	return health.Node{ID: n.ID, Supported: n.Supported}
}

// Group — одна подписка либо специальная группа manual (§2).
type Group struct {
	ID   string
	Name string
	// SourceURL — пусто для manual.
	SourceURL     string
	LastUpdatedAt time.Time
	// QuotaInfo — сырой заголовок Subscription-UserInfo, если пришёл. Хранится
	// как есть и не разбирается (§7, п. 3).
	QuotaInfo string
	// NodeOrder — порядок узлов как в подписке. Переписывается на каждом
	// слиянии из порядка провайдера (Р8): от него зависит выбор при равных rtt
	// (§6.4).
	NodeOrder []string
	// AutoUpdate — включено ли автообновление подписки.
	AutoUpdate bool
	// AutoUpdateInterval — с какой частотой обновлять, когда включено.
	AutoUpdateInterval time.Duration
}

// Merged — что слияние решило про группу. Тип объявлен здесь, а не в
// subscription, хотя решает его subscription: импорты в Go считаются по
// пакетам, и встречный store → subscription был бы циклом. Знание §6.16
// остаётся у подписки, общий тип лежит у того, кого импортируют.
type Merged struct {
	// Added, Kept, Removed — id узлов, а не количества. Счётчики позволили бы
	// слиянию удалить и добавить один и тот же узел, не изменив ни одного
	// числа, — а проверяется здесь именно тождество узла (У1).
	Added, Kept, Removed []string
	// Nodes — состав группы после слияния.
	Nodes []Node
	// Order — node_order из порядка входящей подписки (Р8).
	Order []string
	// Unsupported — сводка импорта, сгруппированная по причине (§1/С2, §6.11).
	Unsupported map[UnsupReason]int
}
