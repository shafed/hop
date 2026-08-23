// Package subscription — разбор тела подписки в узлы (§6.11, §6.12).
// Регистр проверок — docs/verification-store.md, §5.2 и §5.3.
//
// Parse — чистая функция: ни диска, ни сети, ни стора. Из проекта пакет берёт
// только store.UnsupReason (замкнутое перечисление §6.11, оно же уезжает в
// сводку импорта) и policy — флаг каскада. Обратного импорта store →
// subscription нет и быть не должно: он замкнул бы цикл (docs/verification-store.md §2).
//
// Слияние здесь не живёт: Parse разбирает, Diff решает, что с чем слилось, а
// пишет store. Поэтому Incoming — узел без id, group_id и merge_key: их выдаёт
// слияние, а не разбор.
package subscription

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/shafed/hop/internal/policy"
	"github.com/shafed/hop/internal/store"
)

// Format — ступень каскада §6.12, забравшая вход. Наблюдаемое поле, а не
// отладочное: «не распозналось» и «распозналось не тем» — разные отказы (У3),
// и различить их снаружи можно только по формату.
type Format uint8

const (
	// FormatUnknown — ни одна ступень вход не взяла.
	FormatUnknown Format = iota
	// FormatBase64 — тело целиком в base64, внутри список ссылок.
	FormatBase64
	// FormatClash — тело с ключом proxies:. Распознаётся, но не разбирается
	// (Р11, §4).
	FormatClash
	// FormatLines — несколько ссылок, по одной на строку.
	FormatLines
	// FormatScheme — тело целиком — одна ссылка со схемой.
	FormatScheme
)

func (f Format) String() string {
	switch f {
	case FormatBase64:
		return "base64"
	case FormatClash:
		return "clash"
	case FormatLines:
		return "lines"
	case FormatScheme:
		return "scheme"
	default:
		return "unknown"
	}
}

// Incoming — разобранный узел без id, group_id и merge_key: их выдаёт слияние
// (шаг 3), а не разбор. Полный узел — store.Node.
type Incoming struct {
	// Name — отображаемое имя из #fragment.
	Name string
	// Protocol — vless | vmess | trojan | shadowsocks | ... Значение из
	// ссылки, приведённое к нижнему регистру, а не только из нашей сборки:
	// неподдержанный протокол тоже становится узлом (§6.11).
	Protocol string
	// Server — хост или IP.
	Server string
	Port   int
	// Transport — нормализован по §6.12: raw | ws | xhttp | grpc | httpupgrade
	// | mkcp | http | ...
	Transport string
	// Security — нормализован по §6.12: none | tls | reality | ... Значение
	// reality остаётся собой и не сводится к tls (C6, S18).
	Security string
	// Params — всё остальное, специфичное для протокола и транспорта. Здесь
	// лежат ключи доступа: uuid, пароли, pbk.
	Params map[string]string
	// Supported — умеет ли это наша сборка Xray (§6.11).
	Supported bool
	// UnsupReason — заполняется только при Supported == false (§2).
	UnsupReason store.UnsupReason
	// RawLink — исходная строка целиком.
	RawLink string
}

// Param — значение параметра узла или пусто.
func (in Incoming) Param(k string) string { return in.Params[k] }

// Unsupported — строка, которая не стала узлом вовсе: у неё нет схемы или нет
// адреса. Одна такая строка не рушит импорт (У2, §6.11): остальные девяносто
// девять узлов приходят как обычно, а причина учитывается здесь.
type Unsupported struct {
	Link   string
	Reason store.UnsupReason
}

// Parsed — результат разбора тела подписки.
type Parsed struct {
	// Nodes — в порядке подписки. Порядок принадлежит провайдеру (Р8), и
	// разбор не имеет права его трогать.
	Nodes []Incoming
	// Unsupported — по одной записи на негодную строку.
	Unsupported []Unsupported
	// Format — какая ступень каскада взяла вход.
	Format Format
}

// ErrClashYAML — тело распознано как Clash YAML. Одна внятная ошибка вместо
// шума из бессмысленных ошибок на каждую строку YAML (Р11, C5, §4, §6.12).
var ErrClashYAML = errors.New("subscription: тело похоже на Clash YAML (ключ proxies:), а этот формат в v1 не разбирается; нужна подписка ссылками или base64")

// ErrUnknownFormat — вход не взяла ни одна ступень каскада.
var ErrUnknownFormat = errors.New("subscription: формат тела не распознан ни одной ступенью каскада")

// stage — что ступень вынула из тела.
type stage struct {
	nodes []Incoming
	unsup []Unsupported
	// inner — тело, которое ступень развернула (base64 → содержимое).
	// Ступени после неё его не видят: вход целиком забирает первая взявшая
	// (§6.12). Поле существует ради выключенной parse_cascade, где ступени
	// объединяют результаты: развёрнутое тело уезжает дальше по каскаду и
	// разбирается второй раз, задваивая узлы (S24).
	inner []byte
}

// recognizer — одна ступень каскада §6.12: «дай входной буфер, получи узлы и
// признак, взял ли я его». Каскад — упорядоченный срез таких ступеней, а не
// функция с ветвлением: форма выбрана ради проверки, потому что каждая ступень
// тогда гоняется golden-корпусом по отдельности.
type recognizer struct {
	format Format
	take   func(body []byte) (stage, bool, error)
}

// cascade — порядок из §6.12: base64 → Clash YAML → построчно → по схеме.
var cascade = []recognizer{
	{FormatBase64, takeBase64},
	{FormatClash, takeClash},
	{FormatLines, takeLines},
	{FormatScheme, takeScheme},
}

// firstTakerWins — политика parse_cascade, снятая один раз при инициализации:
// в горячем месте дёргать On() незачем, а тестам процесс всё равно поднимают
// заново (см. internal/health/manager.go, поля tiers и forced).
var firstTakerWins = policy.ParseCascade.On()

// Parse разбирает тело подписки. Первая взявшая ступень забирает вход целиком
// (§6.12).
//
// Ноль узлов — не ошибка этой функции: правило Р7 («пустая подписка не
// применяется») принадлежит пути скачивания, который и решает, что делать с
// пустым результатом. Ошибку Parse возвращает только тогда, когда сказать про
// тело нечего вовсе: формат не распознан или распознан как неразбираемый.
func Parse(body []byte) (Parsed, error) {
	buf := body
	var acc Parsed
	taken := false

	for _, r := range cascade {
		st, ok, err := r.take(buf)
		if !ok {
			continue
		}
		if firstTakerWins {
			if err != nil {
				// Формат едет даже с ошибкой: «распозналось не тем» и «не
				// распозналось» — разные отказы (У3), и различить их снаружи
				// можно только по нему.
				return Parsed{Format: r.format}, err
			}
			return Parsed{Nodes: st.nodes, Unsupported: st.unsup, Format: r.format}, nil
		}

		// parse_cascade выключена: ступени объединяют результаты вместо
		// «первый взял». Ошибка ступени перестаёт быть отказом всего разбора
		// (S23), развёрнутое base64 уезжает дальше по каскаду и разбирается
		// второй раз (S22, S24).
		taken = true
		if err == nil {
			acc.Nodes = append(acc.Nodes, st.nodes...)
			acc.Unsupported = append(acc.Unsupported, st.unsup...)
			if acc.Format == FormatUnknown {
				acc.Format = r.format
			}
		}
		if st.inner != nil {
			buf = st.inner
		}
	}

	if !taken {
		return Parsed{}, ErrUnknownFormat
	}
	return acc, nil
}

// takeBase64 — первая ступень: тело целиком в base64. Берёт вход, только если
// декодированное похоже на список ссылок: иначе любой мусор из алфавита base64
// был бы «распознан» и настоящая причина утонула бы.
func takeBase64(body []byte) (stage, bool, error) {
	dec, ok := decodeBase64(string(body))
	if !ok || !bytes.Contains(dec, []byte("://")) {
		return stage{}, false, nil
	}
	nodes, unsup := parseLines(string(dec))
	return stage{nodes: nodes, unsup: unsup, inner: dec}, true, nil
}

// takeClash — вторая ступень: распознаёт, но не разбирает (Р11, §4). Ступень
// обязательна, а не факультативна: без неё тот же файл проваливается в
// построчный разбор и даёт по бессмысленной ошибке на каждую строку YAML.
func takeClash(body []byte) (stage, bool, error) {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(strings.TrimLeft(line, " \t"), " \t\r")
		if !strings.HasPrefix(line, "proxies") {
			continue
		}
		if rest := strings.TrimLeft(line[len("proxies"):], " \t"); strings.HasPrefix(rest, ":") {
			return stage{}, true, ErrClashYAML
		}
	}
	return stage{}, false, nil
}

// takeLines — третья ступень: список ссылок, по одной на строку.
func takeLines(body []byte) (stage, bool, error) {
	if len(nonEmptyLines(string(body))) < 2 {
		// Одна строка — работа четвёртой ступени: так «тело — это одна
		// ссылка» и «тело — это список» остаются разными случаями, а не
		// сливаются в один.
		return stage{}, false, nil
	}
	nodes, unsup := parseLines(string(body))
	return stage{nodes: nodes, unsup: unsup}, true, nil
}

// takeScheme — четвёртая ступень: тело целиком — одна ссылка со схемой.
func takeScheme(body []byte) (stage, bool, error) {
	lines := nonEmptyLines(string(body))
	if len(lines) != 1 || !strings.Contains(lines[0], "://") {
		return stage{}, false, nil
	}
	nodes, unsup := parseLines(lines[0])
	return stage{nodes: nodes, unsup: unsup}, true, nil
}

// parseLines разбирает список ссылок построчно. Негодная строка уходит в
// Unsupported и не мешает остальным (У2).
func parseLines(text string) ([]Incoming, []Unsupported) {
	var (
		nodes []Incoming
		unsup []Unsupported
	)
	for _, line := range nonEmptyLines(text) {
		in, ok := parseLink(line)
		if !ok {
			unsup = append(unsup, Unsupported{Link: line, Reason: store.UnsupParse})
			continue
		}
		nodes = append(nodes, in)
	}
	return nodes, unsup
}

func nonEmptyLines(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// decodeBase64 пробует все четыре алфавита: провайдеры шлют и обычный, и
// url-safe, и с выравниванием, и без. Пробелы и переносы строк выбрасываются —
// тело часто приходит завёрнутым по 64 или 76 символов.
func decodeBase64(s string) ([]byte, bool) {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case ' ', '\t', '\r', '\n':
		default:
			b.WriteRune(r)
		}
	}
	clean := b.String()
	if clean == "" {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if dec, err := enc.DecodeString(clean); err == nil {
			return dec, true
		}
	}
	return nil, false
}
