package store

import (
	"fmt"
	"strconv"
	"strings"
)

// Секретная часть узла и заглушка форматирования (Р12, §6.14, шаг 7 регистра).
//
// Образец — tunnel.Token: §6.14 запрещает секретам попадать в логи «ни на
// уровне debug», а самый частый способ туда попасть — `%v` по структуре,
// которая случайно оказалась в аргументах логгера. String и GoString отдают
// заглушку, поэтому ни один формат-глагол ключей не выдаёт, включая `%#v` и
// печать объемлющей структуры.
//
// Разница с Token в том, что Token секретен целиком, а Node — нет. §6.14
// запрещает попадание **ключей** в лог, а не отладку вообще: узел, свёрнутый до
// `<node>`, сделал бы неотличимыми в логе двести узлов подписки, и первый же
// разбор жалобы «переключается не туда» упёрся бы в это. Поэтому заглушка
// показывает всё, по чему узел опознаётся, и прячет ровно три поля:
//
//   - Params — здесь лежат uuid, пароли и pbk. Прячутся и значения, и имена:
//     имена параметров приходят из недоверенного тела подписки, и провайдер,
//     положивший ключ в имя, а не в значение, не должен пробивать заглушку.
//     Остаётся счётчик — он говорит «параметры есть» и ничего не выдаёт.
//   - RawLink — исходная ссылка целиком, то есть тот же ключ открытым текстом.
//   - MergeKey — производное от ключа доступа (§6.16). user_id входит в него
//     хэшем, то есть прямой утечки нет, но отладке он ничего и не даёт:
//     protocol, server и port в нём те же, что рядом, а остаток — хэш.

// Redacted — то, что видно вместо секретной части узла в любом форматированном
// выводе.
const Redacted = "<скрыто>"

func (n Node) String() string {
	var b strings.Builder
	b.WriteString("store.Node{id:")
	b.WriteString(n.ID)
	b.WriteString(" group:")
	b.WriteString(n.GroupID)
	if n.Name != "" {
		b.WriteString(" name:")
		b.WriteString(strconv.Quote(n.Name))
	}
	b.WriteString(" server:")
	b.WriteString(n.Server)
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(n.Port))
	b.WriteString(" ")
	b.WriteString(n.Protocol)
	if n.Transport != "" {
		b.WriteString("/")
		b.WriteString(n.Transport)
	}
	if n.Security != "" {
		b.WriteString("/")
		b.WriteString(n.Security)
	}
	if !n.Supported {
		b.WriteString(" unsupported:")
		b.WriteString(n.UnsupReason.String())
	}
	// Ключи, ссылка и ключ слияния — заглушкой. Счётчик параметров без единого
	// имени: см. преамбулу файла.
	fmt.Fprintf(&b, " params:%d×%s raw_link:%s merge_key:%s}", len(n.Params), Redacted, Redacted, Redacted)
	return b.String()
}

// GoString — тот же вывод: `%#v` печатает структуру по полям, то есть выдал бы
// и Params, и RawLink.
func (n Node) GoString() string { return n.String() }
