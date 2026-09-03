package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
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
	// nodeDials — как дозваниваться до узла и куда сообщать его вердикт. Ключ — id узла; в продукте
	// движок один, в тестах узлы разных движков обязаны называться по-разному.
	nodeDials = map[string]*nodeDialConfig{}
)

type nodeDialConfig struct {
	onFailure func(*DialError)
	physical  InterfaceFunc
}

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
func watchNode(nodeID string, onFailure func(*DialError), physical InterfaceFunc) *nodeDialConfig {
	cfg := &nodeDialConfig{onFailure: onFailure, physical: physical}
	failuresMu.Lock()
	defer failuresMu.Unlock()
	nodeDials[nodeID] = cfg
	return cfg
}

func unwatchNode(nodeID string, cfg *nodeDialConfig) {
	failuresMu.Lock()
	defer failuresMu.Unlock()
	if nodeDials[nodeID] == cfg {
		delete(nodeDials, nodeID)
	}
}

func reportDialFailure(nodeID string, err error) {
	failuresMu.RLock()
	cfg := nodeDials[nodeID]
	failuresMu.RUnlock()
	if cfg != nil && cfg.onFailure != nil {
		cfg.onFailure(classifyDial(nodeID, err))
	}
}

// probeKey — метка пробного дозвона (Р38).
//
// Тип неэкспортируемый и пустой, как требует контракт context: ключом служит
// сам тип, и столкнуться с чужим он не может.
type probeKey struct{}

// WithProbe помечает контекст как пробный: отказ такого дозвона не пойдёт в
// счётчик ошибок трафика.
//
// §5.4 требует двух **разных** счётчиков — окна проб и счётчика ошибок трафика.
// Проба обязана идти через outbound проверяемого узла (§6.7), то есть тем же
// путём, что трафик, и без метки один её провал засчитывался бы в оба. Узел
// умирал бы вдвое быстрее порога §6.3 — в ту сторону, которую classify.go сам
// называет худшей.
//
// Метка не отменяет классификацию: `DialTCP` по-прежнему вернёт `*DialError` с
// вердиктом. Отменяется только рассылка в `OnFailure`; вердикт получает тот,
// кто дозванивался, и решает сам. Для пробы это `health`, у которого свой счёт.
func WithProbe(ctx context.Context) context.Context {
	return context.WithValue(ctx, probeKey{}, true)
}

// IsProbe — стоит ли на контексте метка Р38.
//
// Экспортирована ради наблюдаемости: без неё «проба ушла с меткой» проверяется
// только по отсутствию рассылки, то есть по молчанию, а молчание одинаково и
// когда метка сработала, и когда дозвон вовсе не состоялся.
func IsProbe(ctx context.Context) bool {
	v, _ := ctx.Value(probeKey{}).(bool)
	return v
}

// nodeDialer — обёртка над системным диалером Xray.
type nodeDialer struct {
	inner internet.SystemDialer
}

func (d *nodeDialer) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (xnet.Conn, error) {
	id, ok := nodeFromContext(ctx)
	if !ok {
		// Альтернативный диалер общий на процесс. Тесты поднимают в нём же сервер
		// Xray с freedom-outbound; его сокет не является соединением агента с
		// узлом и не имеет атрибуции node-*. Боевые сокеты узлов всегда несут тег
		// по той же границе, на которой стоит §6.15.
		return d.inner.Dial(ctx, src, dest, sockopt)
	}

	failuresMu.RLock()
	cfg := nodeDials[id]
	failuresMu.RUnlock()
	var physical InterfaceFunc
	if cfg != nil {
		physical = cfg.physical
	}
	if physical == nil {
		err := fmt.Errorf("engine: узел %s: не задан источник физического интерфейса (§6.8)", id)
		if !IsProbe(ctx) {
			reportDialFailure(id, err)
		}
		return nil, err
	}
	iface, err := physical()
	if err != nil || iface == "" {
		if err == nil {
			err = fmt.Errorf("физический интерфейс пуст")
		}
		err = fmt.Errorf("engine: узел %s: защита от петли: %w", id, err)
		if !IsProbe(ctx) {
			reportDialFailure(id, err)
		}
		return nil, err
	}

	// Чужой SocketConfig не меняется: транспорт может переиспользовать его в
	// параллельных дозвонах. Xray сам переводит Interface в опцию нужной ОС.
	//
	// proto.Clone, а не `copy := *sockopt`. Присваивание копировало значение
	// вместе с внутренним состоянием protobuf (protoimpl.MessageState, внутри
	// — sync.Mutex и указатель на собственный адрес для быстрого пути), и
	// `go vet` называл это copylocks. Три раунда подряд эта находка числилась
	// «известной краснотой, которую не чиним», и из-за неё CI был красным на
	// каждом пуше: шаг test на macOS, l3-macos и l3-windows падали ровно на
	// ней. Чинится она в одну строку, а не подавляется: копировать
	// сообщение protobuf по значению нельзя по его же документации, и
	// подавления у vet построчного всё равно нет.
	//
	// Что копия остаётся полной и что чужой конфиг не меняется — утверждает
	// TestW36NodeDialBindsCurrentPhysicalInterface: он проверяет и что
	// original.Interface остался пустым, и что TcpKeepAliveIdle пережил
	// копирование. Различить proto.Clone и прежнее присваивание этот тест не
	// может — их различает только `go vet`, и потому vet стоит в гейте.
	if sockopt == nil {
		sockopt = &internet.SocketConfig{}
	} else {
		sockopt = proto.Clone(sockopt).(*internet.SocketConfig)
	}
	sockopt.Interface = iface

	conn, err := d.inner.Dial(ctx, src, dest, sockopt)
	if err != nil && !IsProbe(ctx) {
		reportDialFailure(id, err)
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
