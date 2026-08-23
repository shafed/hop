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

// ReplyTo — ответ клиенту: заголовок и все три секции от апстрима,
// идентификатор и секция вопроса — от клиента (Р23, D30, D47).
//
// Секция вопроса берётся у клиента, а не у апстрима, потому что уходит она
// обратно тому, кто её прислал: стаб с 0x20-рандомизацией сверяет написание
// имени байт в байт и ответ с чужим написанием молча отбрасывает. Кэш общий и
// ключуется именем без учёта регистра (Р23), поэтому ответ в нём несёт
// написание того клиента, который промахнулся первым, — для всех остальных
// оно чужое. Снаружи это выглядит как «DNS не работает» при полностью рабочем
// резолвере.
//
// Разная длина секций вопроса — отказ, и это не перестраховка. Указатели
// сжатия в секциях апстрима считают смещения от начала его сообщения, то есть
// поверх его секции вопроса; склейка кусков разной длины сдвинет всё, что за
// вопросом, и имена в ответе поедут — молча, потому что клиент получит
// синтаксически безупречное сообщение с неверными именами. При
// 0x20-рандомизации длины совпадают всегда (меняется регистр, не длина), так
// что расхождение здесь означает настоящую аномалию, а не штатный путь.
//
// Что ответ апстрима отвечает именно на этот вопрос, ReplyTo не проверяет:
// сверка вопроса с запросом — дело резолвера, у которого на руках оба.
//
// Смещения переносятся на копию без пересчёта: длина секции вопроса та же,
// значит всё, что за ней, лежит там же, где лежало у апстрима.
func ReplyTo(query, upstream Msg) (Msg, error) {
	if err := query.checkParsed(); err != nil {
		return Msg{}, fmt.Errorf("запрос клиента: %w", err)
	}
	if err := upstream.checkParsed(); err != nil {
		return Msg{}, fmt.Errorf("ответ апстрима: %w", err)
	}
	if query.Question.End != upstream.Question.End {
		return Msg{}, fmt.Errorf("%w: у клиента %d байт, у апстрима %d",
			ErrQuestionLen, query.Question.End-HeaderLen, upstream.Question.End-HeaderLen)
	}

	out := make([]byte, len(upstream.Raw))
	copy(out, upstream.Raw)
	copy(out[HeaderLen:query.Question.End], query.Raw[HeaderLen:query.Question.End])
	binary.BigEndian.PutUint16(out[0:2], query.Header.ID)

	m := upstream
	m.Raw = out
	m.Header.ID = query.Header.ID
	m.Question = query.Question
	m.Question.Name = Name(out[HeaderLen : HeaderLen+len(query.Question.Name)])
	return m, nil
}

// Reply — ответ клиенту из ответа апстрима: всё как пришло, кроме
// идентификатора. Это одно из ровно трёх искажений, которые У6 разрешает, и
// D47 сравнивает Sections обеих сторон именно после него.
//
// Устарела: секция вопроса приезжает клиенту апстримовая, и клиент с
// 0x20-рандомизацией такой ответ отбросит (D30). Зовите ReplyTo — она берёт
// вопрос у того, кто спрашивал. Снимается вместе с последним вызовом.
//
// Смещения переносятся без пересчёта: подстановка идентификатора длин не
// меняет, а повторный разбор той же копии стоил бы обхода мусора дважды.
func Reply(upstream Msg, id uint16) Msg {
	// Сигнатура без ошибки — наследство, снимаемое вместе с самой Reply;
	// пока она жива, неразобранный Msg отдаётся неразобранным обратно.
	// Паника здесь стоила бы туннеля: Parse при ошибке возвращает именно
	// Msg{} (D8).
	if upstream.checkParsed() != nil || HeaderLen+len(upstream.Question.Name) > len(upstream.Raw) {
		return Msg{}
	}
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
//
// Ошибка вместо паники на неразобранном запросе: сюда приезжает то, что
// вернул Parse, а при ошибке он возвращает Msg{} — и самый естественный
// обработчик «не-DNS на :53» подаёт этот Msg прямо в отказ (D8). Паника в
// горутине ответа не перехватывается нигде и снимает туннель на пакете,
// который прислал любой локальный процесс; ответить на такой пакет нечем —
// в нём нет ни идентификатора, ни вопроса, которые отказ обязан отразить.
func Respond(q Msg, rcode uint8) ([]byte, error) {
	if err := q.checkParsed(); err != nil {
		return nil, err
	}
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
	return out, nil
}

// ServFail — отказ (Р15, D9–D11, D14, D15).
func ServFail(q Msg) ([]byte, error) { return Respond(q, RcodeServFail) }

// NoData — пустой NOERROR. Нужен для AAAA при заблокированном IPv6 (Р19,
// D45): NXDOMAIN означал бы «имени нет вовсе», и стаб вправе распространить
// это на A-запись того же имени.
func NoData(q Msg) ([]byte, error) { return Respond(q, RcodeNoError) }

// Fit — сообщение под потолком буфера клиента. Влезло — отдаётся как есть;
// не влезло — заголовок с вопросом и поднятым флагом TC (D34).
//
// Обрезать байты RRset нельзя: приложение получит мусор вместо указания
// прийти по TCP, и ошибка эта тихая — сообщение выглядит корректным до
// попытки его разобрать.
//
// Псевдозапись OPT в усечённый ответ не переезжает, и это не забывчивость.
// Усечённый ответ мы не пропускаем, а сочиняем сами — а сочинённое сообщение
// обязано быть верным само по себе, и присутствие в нём OPT определяется тем,
// объявил ли EDNS0 клиент (RFC 6891 §6.1.1), которого Fit не видит: на руках у
// неё ответ апстрима, а не запрос клиента. Взять OPT из ответа значило бы
// послать EDNS0 клиенту D34, который пришёл по UDP без EDNS0 вовсе, и объявить
// ему чужой размер буфера — апстримовый. Полный ответ несёт апстримовую OPT по
// другой причине: он проходит байт в байт (У6), и это утверждение об апстриме,
// а не о нас.
//
// Цена названа и она не нулевая: клиент, объявивший EDNS0, видит ответ с TC и
// без OPT и вправе счесть нас не понимающими EDNS0 — то есть в следующих
// запросах опустить буфер до 512 и получать усечение чаще. Неверного ответа
// это не даёт никогда, а TC и так уводит его на TCP, который мы тоже
// перехватываем (§3.4). Честная правка — приписать OPT, отражающую EDNS0
// клиента, и делать это должен резолвер, у которого есть и запрос, и ответ;
// строки регистра на этот случай нет, D34 покрывает клиента без EDNS0, а D35
// до усечения не доходит.
//
// Влезающее сообщение возвращается без копии: оно уже принадлежит вызывающему
// (ReplyTo отдала ему свой буфер). truncated=true — повод увеличить
// TruncToClient.
func Fit(m Msg, limit int) (out []byte, truncated bool, err error) {
	if err := m.checkParsed(); err != nil {
		return nil, false, err
	}
	if len(m.Raw) <= limit {
		return m.Raw, false, nil
	}
	if m.Question.End > limit {
		return nil, false, fmt.Errorf("%w: %d байт при потолке %d", ErrLimit, m.Question.End, limit)
	}
	out, err = Respond(m, m.Header.Rcode())
	if err != nil {
		return nil, false, err
	}
	binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])|FlagTruncated)
	return out, true, nil
}

// AppendOPT дописывает псевдозапись OPT в ADDITIONAL: без RDATA (RFC 6891
// §6.1.2, опций нет — только объявленный размер буфера и бит DO), поднимая
// ARCOUNT на единицу.
//
// Рассчитана на то, что вызывающий сам решает, когда и с каким размером её
// приписывать (D34б: резолвер знает EDNS0 клиента, Fit — нет), и не трогает
// уже присутствующую OPT — двух OPT в одном сообщении быть не должно, и
// вызывающий обязан не звать AppendOPT на сообщении, где она уже есть.
func AppendOPT(msg []byte, udpSize uint16, do bool) ([]byte, error) {
	if len(msg) < HeaderLen {
		return nil, fmt.Errorf("%w: заголовок %d байт из %d", ErrShort, len(msg), HeaderLen)
	}
	out := make([]byte, len(msg), len(msg)+11)
	copy(out, msg)

	out = append(out, 0) // корневое имя владельца OPT
	out = binary.BigEndian.AppendUint16(out, TypeOPT)
	out = binary.BigEndian.AppendUint16(out, udpSize) // CLASS несёт буфер (RFC 6891 §6.1.2)
	var ttl uint32
	if do {
		ttl |= optDOBit
	}
	out = binary.BigEndian.AppendUint32(out, ttl)
	out = binary.BigEndian.AppendUint16(out, 0) // RDLENGTH — опций нет

	arcount := binary.BigEndian.Uint16(out[10:12])
	binary.BigEndian.PutUint16(out[10:12], arcount+1)
	return out, nil
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
