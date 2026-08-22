package dnsmsg

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// WithID — копия сообщения с подставленным идентификатором.
//
// Копия, а не правка на месте: буфер ответа апстрима принадлежит апстримовому
// пути и может лежать в кэше, общем для всех клиентов (Р23), а идентификатор у
// каждого клиента свой.
func WithID(msg []byte, id uint16) ([]byte, error) {
	if len(msg) < HeaderLen {
		return nil, fmt.Errorf("%w: заголовок %d байт из %d", ErrShort, len(msg), HeaderLen)
	}
	out := make([]byte, len(msg))
	copy(out, msg)
	binary.BigEndian.PutUint16(out[0:2], id)
	return out, nil
}

// Reply — ответ клиенту из ответа апстрима: всё как пришло, кроме
// идентификатора. Это одно из ровно трёх искажений, которые У6 разрешает, и
// D47 сравнивает Sections обеих сторон именно после него.
//
// Смещения переносятся без пересчёта: подстановка идентификатора длин не
// меняет, а повторный разбор той же копии стоил бы обхода мусора дважды.
func Reply(upstream Msg, id uint16) Msg {
	out := make([]byte, len(upstream.Raw))
	copy(out, upstream.Raw)
	binary.BigEndian.PutUint16(out[0:2], id)

	m := upstream
	m.Raw = out
	m.Header.ID = id
	m.Question.Name = Name(out[HeaderLen : HeaderLen+len(upstream.Question.Name)])
	return m
}

// Respond — ответ по коду из запроса: заголовок и секция вопроса байт в байт,
// QR поднят, RCODE подставлен, три счётчика обнулены, всё после вопроса
// отброшено (D8, D11, D45).
//
// Отражает запрос, а не строит ответ с нуля: резолвер клиента сверяет
// идентификатор и вопрос — включая написание имени (Р23) — и ответ с чужими
// отбросит, после чего мы получим то самое молчание, которого §5.6 велит
// избегать.
//
// Флаг RA от себя не выставляется: сегодняшняя заглушка агента его не
// выставляет, и менять форму отказа заодно с переездом кода — значит менять
// две вещи в одном месте.
func Respond(q Msg, rcode uint8) []byte {
	out := make([]byte, q.Question.End)
	copy(out, q.Raw[:q.Question.End])

	flags := q.Header.Flags | FlagResponse
	// TC поднимает только Fit, и только когда действительно урезал.
	flags &^= FlagTruncated
	flags = (flags &^ rcodeMask) | (uint16(rcode) & rcodeMask)
	binary.BigEndian.PutUint16(out[2:4], flags)

	binary.BigEndian.PutUint16(out[6:8], 0)   // ANCOUNT
	binary.BigEndian.PutUint16(out[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(out[10:12], 0) // ARCOUNT
	return out
}

// ServFail — отказ (Р15, D9–D11, D14, D15).
func ServFail(q Msg) []byte { return Respond(q, RcodeServFail) }

// NoData — пустой NOERROR. Нужен для AAAA при заблокированном IPv6 (Р19,
// D45): NXDOMAIN означал бы «имени нет вовсе», и стаб вправе распространить
// это на A-запись того же имени.
func NoData(q Msg) []byte { return Respond(q, RcodeNoError) }

// Fit — сообщение под потолком буфера клиента. Влезло — отдаётся как есть;
// не влезло — заголовок с вопросом и поднятым флагом TC (D34).
//
// Обрезать байты RRset нельзя: приложение получит мусор вместо указания
// прийти по TCP, и ошибка эта тихая — сообщение выглядит корректным до
// попытки его разобрать.
//
// Влезающее сообщение возвращается без копии: оно уже принадлежит вызывающему
// (Reply отдал ему свой буфер). truncated=true — повод увеличить TruncToClient.
func Fit(m Msg, limit int) (out []byte, truncated bool, err error) {
	if len(m.Raw) <= limit {
		return m.Raw, false, nil
	}
	if m.Question.End > limit {
		return nil, false, fmt.Errorf("%w: %d байт при потолке %d", ErrLimit, m.Question.End, limit)
	}
	out = Respond(m, m.Header.Rcode())
	binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])|FlagTruncated)
	return out, true, nil
}

// NewQuery собирает запрос: заголовок с RD, один вопрос, ничего больше.
//
// Пакету он нужен ради bootstrap (§5.7а), который резолвит имена узлов и
// строить сообщение по байтам у себя не должен: границы меток и имени —
// ровно то место, где два разных кодировщика разойдутся по-разному.
func NewQuery(id uint16, host string, qtype uint16) ([]byte, error) {
	out := make([]byte, HeaderLen, HeaderLen+len(host)+2+4)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], FlagRecursionDesired)
	binary.BigEndian.PutUint16(out[4:6], 1) // QDCOUNT
	out, err := appendName(out, host)
	if err != nil {
		return nil, err
	}
	out = binary.BigEndian.AppendUint16(out, qtype)
	out = binary.BigEndian.AppendUint16(out, ClassIN)
	return out, nil
}

// appendName кодирует имя в проводной вид. Корневая точка на конце
// необязательна, пустая метка внутри имени запрещена.
func appendName(dst []byte, host string) ([]byte, error) {
	host = strings.TrimSuffix(host, ".")
	wire := 1
	if host != "" {
		for _, label := range strings.Split(host, ".") {
			if label == "" {
				return nil, fmt.Errorf("%w: пустая метка в %q", ErrName, host)
			}
			if len(label) > MaxLabel {
				return nil, fmt.Errorf("%w: метка %d байт в %q", ErrName, len(label), host)
			}
			wire += len(label) + 1
			if wire > MaxName {
				return nil, fmt.Errorf("%w: %q длиннее %d байт", ErrName, host, MaxName)
			}
			dst = append(dst, byte(len(label)))
			dst = append(dst, label...)
		}
	}
	return append(dst, 0), nil
}
