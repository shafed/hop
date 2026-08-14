package engine

import (
	"context"
	"strings"
	"sync"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
)

// Перехват системного диалера Xray — единственный слой, где «не дозвонились до
// узла» отличимо от «не дозвонились до сайта».
//
// **Почему без него нельзя.** Соединение Xray отдаётся лениво (conn.go), а
// когда оно рвётся, вызывающий видит `io: read/write on closed pipe`:
// диспетчер закрывает пайп, а настоящая причина остаётся внутри. Причём один и
// тот же текст приходит и когда мёртв узел, и когда целевой сайт отказал в
// соединении. §6.15 требует различать ровно эти два случая, а на уровне потока
// они неразличимы **в принципе**, а не по недосмотру.
//
// **Как различаем.** Диалер Xray вызывается с контекстом, в котором уже стоит
// тег outbound'а (`app/dispatcher/default.go:502`, `ob.Tag = handler.Tag()`).
// В нашем процессе под тегом `node-X` делается ровно одно соединение — к
// самому узлу X: до целевого хоста дозванивается freedom на той стороне, в
// чужом процессе. Значит отказ диала под этим тегом — это в точности
// «не установилось соединение с узлом» из §6.15, и приписан он узлу по
// построению, а не по совпадению адреса. Хостнейм узла при этом может
// резолвиться во что угодно — на атрибуцию это не влияет.
//
// **Чего этот слой не видит.** Рукопожатие TLS и REALITY идёт выше диалера, и
// его отказ сюда не приходит. HandshakeFailed, TLSError и ProxyRefused из
// §6.15 остаются на пробах и окне k из n — см. «Deviations» в
// implementation-notes.md.

var (
	dialerOnce sync.Once

	failuresMu sync.RWMutex
	// failures — куда сообщать вердикт по узлу. Ключ — id узла; в продукте
	// движок один, в тестах узлы разных движков обязаны называться по-разному.
	failures = map[string]func(*DialError){}
)

// installDialer подменяет системный диалер Xray один раз на процесс.
//
// `internet.InitSystemDialer` пишет dns-клиент и менеджер outbound'ов в
// пакетные переменные (`transport/internet/dialer.go:285`), а не в поля
// диалера, поэтому обёртка вокруг DefaultSystemDialer ничего не ломает: обе
// зависимости остаются на месте.
func installDialer() {
	dialerOnce.Do(func() {
		internet.UseAlternativeSystemDialer(&nodeDialer{inner: &internet.DefaultSystemDialer{}})
	})
}

// watchNode подписывает движок на отказы диала к узлу.
func watchNode(nodeID string, onFailure func(*DialError)) {
	if onFailure == nil {
		return
	}
	failuresMu.Lock()
	defer failuresMu.Unlock()
	failures[nodeID] = onFailure
}

func unwatchNode(nodeID string) {
	failuresMu.Lock()
	defer failuresMu.Unlock()
	delete(failures, nodeID)
}

func reportDialFailure(nodeID string, err error) {
	failuresMu.RLock()
	fn := failures[nodeID]
	failuresMu.RUnlock()
	if fn != nil {
		fn(classifyDial(nodeID, err))
	}
}

// nodeDialer — обёртка над системным диалером Xray.
type nodeDialer struct {
	inner internet.SystemDialer
}

func (d *nodeDialer) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (xnet.Conn, error) {
	conn, err := d.inner.Dial(ctx, src, dest, sockopt)
	if err != nil {
		if id, ok := nodeFromContext(ctx); ok {
			reportDialFailure(id, err)
		}
	}
	return conn, err
}

func (d *nodeDialer) DestIpAddress() xnet.IP { return d.inner.DestIpAddress() }

// nodeFromContext достаёт id узла из тега outbound'а.
func nodeFromContext(ctx context.Context) (string, bool) {
	obs := session.OutboundsFromContext(ctx)
	if len(obs) == 0 {
		return "", false
	}
	tag := obs[len(obs)-1].Tag
	if !strings.HasPrefix(tag, nodeTagPrefix) {
		return "", false
	}
	return strings.TrimPrefix(tag, nodeTagPrefix), true
}

const nodeTagPrefix = "node-"
