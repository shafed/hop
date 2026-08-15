// Слияние состава группы (§5.8, §6.16). Регистр проверок —
// docs/verification-store.md §5.1.
//
// Diff — чистая функция: ни диска, ни сети, ни часов. Она решает, что с чем
// слилось, и возвращает готовый состав; записывает его store.Apply. Отметку
// времени (Group.LastUpdatedAt) здесь не ставит никто — время принадлежит тому,
// кто пишет на диск, а чистая функция часов не знает.

package subscription

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/shafed/hop/internal/policy"
	"github.com/shafed/hop/internal/store"
)

// Политики сняты один раз при инициализации, как firstTakerWins и поля
// health.Manager: в горячем месте дёргать On() незачем, а тестам процесс всё
// равно поднимают заново.
var (
	// mergeKeyOn — ключ считается по §6.16. Выключение переводит его в полный
	// отпечаток узла: косметическая правка у провайдера обнуляет историю (T18, S1).
	mergeKeyOn = policy.MergeKey.On()
	// mergeKeyUserIDOn — в ключ входит user_id по таблице §6.16. Выключение
	// оставляет один адрес, и узлы, различающиеся ключом доступа, склеиваются (S3).
	mergeKeyUserIDOn = policy.MergeKeyUserID.On()
)

// Diff сливает пришедшую подписку с тем, что уже лежит в группе (§5.8).
//
// Подпись отличается от той, что записана в docs/verification-store.md §2, в
// двух местах, и оба раза потому, что регистр писался до кода:
//   - groupID: результат состоит из store.Node, а у тех есть GroupID, и взять
//     его больше неоткуда. Он же — половина настоящего ключа слияния (Р9);
//   - newID: идентификатор нового узла обязан приходить снаружи, иначе тесты
//     недетерминированы, а генератор случайности прячется в глобальной переменной;
//   - Parsed вместо []Incoming: сводка импорта §1/С2 считает и строки, которые
//     узлами не стали вовсе (Unsupported с причиной parse). С одним лишь
//     []Incoming она получалась бы неполной, а собирать её в двух местах —
//     значит однажды разъехаться.
//
// Узлы чужих групп во входе игнорируются: ключ действует внутри группы (Р9), и
// две подписки от разных провайдеров законно содержат один и тот же сервер.
// Игнорируются, а не удаляются: удалять чужое слияние права не имеет.
func Diff(groupID string, existing []store.Node, p Parsed, newID func() string) store.Merged {
	m, _ := diff(groupID, existing, p, newID)
	return m
}

// diff — то же слияние, но со счётчиком элементарных шагов. Шаг — это один
// взгляд на существующий узел: индексация одного узла или один поиск по ключу.
// Линейное слияние тратит len(existing) + len(p.Nodes) шагов, наивный двойной
// цикл — их произведение, и S7 отличает одно от другого счётом, а не
// секундомером: время на загруженной машине мигает, счётчик — нет.
//
// Смысл счётчика — часть контракта: если поиск переедет в цикл по existing,
// инкремент обязан переехать внутрь цикла вместе с ним, иначе проверка станет
// пустой.
func diff(groupID string, existing []store.Node, p Parsed, newID func() string) (store.Merged, int) {
	if groupID == store.ManualGroupID {
		// Р10: в manual слияния нет вовсе. Подписки за этой группой не стоит,
		// диффать не с чем, и состав остаётся нетронутым — узлы туда приходят
		// через Add и уходят через Remove, по id. Молчаливое «ничего не
		// изменилось» здесь консервативнее отказа: вызвать Diff на manual
		// может только ошибка вызывающего, и цена ошибки не должна быть равна
		// потере ручных узлов.
		return unchanged(existing), 0
	}

	steps := 0

	// Карта ключей строится один раз — в этом вся линейность (§4 регистра).
	// used помечает и разобранные узлы, и узлы чужих групп: и те и другие не
	// имеют права попасть в Removed.
	index := make(map[string]int, len(existing))
	used := make([]bool, len(existing))
	for i, n := range existing {
		if n.GroupID != "" && n.GroupID != groupID {
			used[i] = true
			continue
		}
		steps++
		if _, dup := index[n.MergeKey]; dup {
			// Два узла с одним ключом в одной группе — след прежней ошибки или
			// правки правила §6.16. Пережить обновление может только первый:
			// второй неотличим от него и уйдёт в Removed.
			continue
		}
		index[n.MergeKey] = i
	}

	m := store.Merged{Unsupported: summarize(p)}
	for _, in := range p.Nodes {
		key := mergeKeyOf(in)
		steps++
		i, ok := index[key]

		n := nodeFrom(groupID, key, in)
		switch {
		case ok && !used[i]:
			// Тот же узел: id и, значит, история проб остаются за ним (У1).
			// Всё остальное — имя, транспорт, security, params — переписывается
			// пришедшим: провайдер прав по определению.
			used[i] = true
			n.ID = existing[i].ID
			m.Kept = append(m.Kept, n.ID)
		default:
			n.ID = newID()
			m.Added = append(m.Added, n.ID)
		}
		m.Nodes = append(m.Nodes, n)
	}

	for i, n := range existing {
		if !used[i] {
			m.Removed = append(m.Removed, n.ID)
		}
	}

	// Р8: порядок принадлежит провайдеру. node_order переписывается из порядка
	// подписки целиком — выжившие встают туда, куда их поставил провайдер.
	m.Order = orderOf(m.Nodes)
	return m, steps
}

// Add — `hop node add` в группе manual (Р10). Слияния нет: каждый вызов создаёт
// узел с новым id, даже если такая же ссылка в группе уже есть. Ключ слияния у
// ручного узла пуст и ни в чём не участвует — этим закрыт дефект C14, где два
// ручных узла с совпавшим ключом были неразличимы и удаление третьего
// переставляло id у оставшихся.
func Add(groupID string, existing []store.Node, in Incoming, newID func() string) store.Merged {
	m := unchanged(existing)

	n := nodeFrom(groupID, keyFor(groupID, in), in)
	n.ID = newID()
	m.Added = append(m.Added, n.ID)
	m.Nodes = append(m.Nodes, n)
	m.Order = orderOf(m.Nodes)
	m.Unsupported = summarize(Parsed{Nodes: []Incoming{in}})
	return m
}

// Remove — `hop node rm <id>` (Р10): удаление по id, а не по ключу слияния.
// Соседи сохраняют и id, и историю проб. Если такого узла в группе нет, состав
// возвращается нетронутым, и вызывающий видит это по пустому Removed.
func Remove(existing []store.Node, id string) store.Merged {
	m := store.Merged{Unsupported: map[store.UnsupReason]int{}}
	for _, n := range existing {
		if n.ID == id {
			m.Removed = append(m.Removed, n.ID)
			continue
		}
		m.Kept = append(m.Kept, n.ID)
		m.Nodes = append(m.Nodes, n)
	}
	m.Order = orderOf(m.Nodes)
	return m
}

// unchanged — состав группы как есть: всё сохранено, ничего не добавлено и не
// удалено.
func unchanged(existing []store.Node) store.Merged {
	m := store.Merged{
		Nodes:       slices.Clone(existing),
		Unsupported: map[store.UnsupReason]int{},
	}
	m.Kept = orderOf(m.Nodes)
	m.Order = slices.Clone(m.Kept)
	return m
}

func orderOf(nodes []store.Node) []string {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	return out
}

// nodeFrom — полный узел из разобранного, без id. Params копируются: иначе
// состав группы держал бы те же карты, что и результат разбора, и правка одного
// меняла бы другое.
func nodeFrom(groupID, key string, in Incoming) store.Node {
	return store.Node{
		GroupID:     groupID,
		MergeKey:    key,
		Name:        in.Name,
		Protocol:    in.Protocol,
		Server:      in.Server,
		Port:        in.Port,
		Transport:   in.Transport,
		Security:    in.Security,
		Params:      maps.Clone(in.Params),
		Supported:   in.Supported,
		UnsupReason: in.UnsupReason,
		RawLink:     in.RawLink,
	}
}

// summarize — сводка импорта, сгруппированная по причине (§1/С2, §6.11, S13).
// Одним числом она не годится: пользователь спрашивает не «сколько», а «чего не
// хватает». Считаются обе беды сразу — и узлы, которые наша сборка не умеет, и
// строки, которые узлами не стали вовсе.
func summarize(p Parsed) map[store.UnsupReason]int {
	out := make(map[store.UnsupReason]int)
	for _, in := range p.Nodes {
		if !in.Supported {
			out[in.UnsupReason]++
		}
	}
	for _, u := range p.Unsupported {
		out[u.Reason]++
	}
	return out
}

// keyFor — ключ узла в группе. В manual ключа нет вовсе (Р10).
func keyFor(groupID string, in Incoming) string {
	if groupID == store.ManualGroupID {
		return ""
	}
	return mergeKeyOf(in)
}

// mergeKeyOf — ключ слияния §6.16: protocol + server + port + user_id. Смена
// транспорта, SNI или имени на том же сервере — тот же узел; смена сервера,
// порта или ключа доступа — новый.
//
// Значение хранимое (§2 SPEC): оно кладётся в store.Node.MergeKey один раз при
// импорте и на лету больше не считается. Разница видна при правке самого
// правила: с хранимым полем смена §6.16 требует явной миграции стора, а с
// вычислением на лету она молча переопределяет, какие узлы «те же самые».
//
// user_id входит в ключ хэшем, а не открытым текстом: сам по себе ключ ничего
// не решает, а открытый uuid или пароль в отдельном поле — это вторая копия
// секрета там, где §6.14 и Р12 её не ждут.
func mergeKeyOf(in Incoming) string {
	if !mergeKeyOn {
		// Политика выключена: ключом становится полный отпечаток узла — тот
		// самый вариант nekoray, который §6.16 отвергает. Косметическая правка
		// у провайдера с ним даёт новый узел и обнуляет историю (T18, S1).
		return fingerprint(in)
	}
	return strings.Join([]string{
		in.Protocol,
		in.Server,
		strconv.Itoa(in.Port),
		digest(userID(in)),
	}, "|")
}

// userID — таблица §6.16. Поле с таким именем есть только у vless и vmess,
// поэтому правило задано таблицей, а не общим «взять все секретные параметры»:
// хэш от всего работал бы и для будущих протоколов, но любая косметическая
// правка любого из них обнуляла бы историю — ровно тот изъян, за который §6.16
// отвергает полный отпечаток.
//
// Пусто — законное значение: ключ вырождается в protocol + server + port. Это
// записанное известное вырождение, а не недосмотр.
func userID(in Incoming) string {
	if !mergeKeyUserIDOn {
		// Политика выключена: ключ вырождается в один адрес, и два узла,
		// различающиеся только ключом доступа, склеиваются в один (S3).
		return ""
	}
	switch in.Protocol {
	case "vless", "vmess":
		return in.Params["uuid"]
	case "trojan":
		return in.Params["password"]
	case "shadowsocks":
		// Метод + пароль: один и тот же пароль под разными шифрами — разные
		// учётные данные.
		return in.Params["method"] + "\x1f" + in.Params["password"]
	case "hysteria2":
		return in.Params["auth"]
	case "wireguard":
		// Публичный ключ пира, а не свой: свой один на всю подписку и не
		// различал бы узлы вовсе.
		return in.Params["publickey"]
	default:
		return ""
	}
}

// fingerprint — полный отпечаток узла, второй вариант nekoray
// (ProfileFilter_ent_key). В продукте не используется: он живёт здесь только
// как поведение выключенной политики merge_key.
func fingerprint(in Incoming) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%s|%d|%s|%s|%s", in.Protocol, in.Server, in.Port, in.Transport, in.Security, in.Name)
	for _, k := range slices.Sorted(maps.Keys(in.Params)) {
		fmt.Fprintf(&b, "|%s=%s", k, in.Params[k])
	}
	return "fp:" + digest(b.String())
}

// digest — короткий хэш. Пустое остаётся пустым: вырождение ключа §6.16 обязано
// быть видно в нём самом, а не прятаться за хэшем пустой строки.
func digest(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}
