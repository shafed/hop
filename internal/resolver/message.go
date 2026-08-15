package resolver

import (
	"errors"
	"fmt"
	"math/rand/v2"

	"golang.org/x/net/dns/dnsmessage"
)

// question — вопрос клиента. Всё, что резолверу нужно от запроса: остальное в
// сообщении клиента нас не касается, а пересобирать его целиком нельзя —
// ответ обязан повторять вопрос байт в байт по имени и типу.
type question struct {
	id    uint16
	rd    bool
	name  dnsmessage.Name
	typ   dnsmessage.Type
	class dnsmessage.Class
}

// parseQuestion разбирает запрос. Ошибка с непустым id значит, что заголовок
// разобрался и клиенту есть кому ответить FORMERR.
func parseQuestion(query []byte) (question, error) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		// Заголовок не разобрался — отвечать не от чьего имени: в ответе
		// обязан стоять идентификатор запроса, а его-то и нет.
		return question{}, fmt.Errorf("%w: %v", errNoHeader, err)
	}
	q := question{id: h.ID, rd: h.RecursionDesired}
	if h.Response {
		return q, errors.New("resolver: на вход пришёл ответ, а не запрос")
	}
	dq, err := p.Question()
	if err != nil {
		return q, errNoQuestion
	}
	q.name, q.typ, q.class = dq.Name, dq.Type, dq.Class
	return q, nil
}

func (q question) key() cacheKey {
	return cacheKey{name: canonical(q.name.String()), typ: q.typ, class: q.class}
}

// wire собирает запрос к апстриму. Идентификатор свой и случайный: клиентский
// брать нельзя — тот же вопрос от двух клиентов схлопывается в один поход
// (см. fetch), и чей id тогда «правильный», ответа нет.
func (q question) wire() ([]byte, uint16, error) {
	id := uint16(rand.Uint32())
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: q.name, Type: q.typ, Class: q.class}},
	}
	b, err := m.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("resolver: запрос не собрался: %w", err)
	}
	return b, id, nil
}

// accept разбирает ответ апстрима и проверяет, что это ответ **на наш**
// вопрос.
//
// Проверка не формальность. Путь до апстрима — UDP через узел, и ответ по нему
// может прийти какой угодно; принять чужой означает положить в кэш чужую
// запись, то есть отравить резолвер всем приложениям сразу.
func (q question) accept(raw []byte, id uint16) (*dnsmessage.Message, error) {
	var m dnsmessage.Message
	if err := m.Unpack(raw); err != nil {
		return nil, fmt.Errorf("resolver: неразборчивый ответ апстрима: %w", err)
	}
	if !m.Header.Response || m.Header.ID != id {
		return nil, errors.New("resolver: ответ апстрима не на наш запрос")
	}
	if m.Header.Truncated {
		// Усечённый ответ законен, но кэшировать и сверять в нём нечего:
		// вопрос на месте, тела нет. Досылку по TCP делает ask.
		return &m, nil
	}
	if len(m.Questions) != 1 {
		return nil, errors.New("resolver: в ответе апстрима не один вопрос")
	}
	a := m.Questions[0]
	if canonical(a.Name.String()) != canonical(q.name.String()) || a.Type != q.typ || a.Class != q.class {
		return nil, errors.New("resolver: апстрим ответил на другой вопрос")
	}
	switch m.Header.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
		return &m, nil
	default:
		// SERVFAIL и REFUSED — не ответ, а отказ конкретного сервера:
		// спрашиваем следующий.
		return nil, fmt.Errorf("resolver: апстрим ответил %v", m.Header.RCode)
	}
}

// pack собирает ответ клиенту: тело от апстрима, идентификатор и вопрос — его
// собственные.
func pack(msg *dnsmessage.Message, q question) ([]byte, error) {
	out := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 q.id,
			Response:           true,
			Authoritative:      msg.Header.Authoritative,
			RecursionDesired:   q.rd,
			RecursionAvailable: true,
			RCode:              msg.Header.RCode,
		},
		Questions:   []dnsmessage.Question{{Name: q.name, Type: q.typ, Class: q.class}},
		Answers:     msg.Answers,
		Authorities: msg.Authorities,
		// Additionals не переносим: там живёт OPT апстрима (EDNS0), а его
		// параметры — договорённость апстрима с нами, не с клиентом.
	}
	b, err := out.Pack()
	if err != nil {
		return nil, fmt.Errorf("resolver: ответ не собрался: %w", err)
	}
	return b, nil
}
