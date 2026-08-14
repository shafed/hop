package dns

// Работа с самим сообщением DNS. Разбор и сборка — golang.org/x/net/dnsmessage:
// свой парсер здесь означал бы свой набор ошибок на компрессии имён и на
// границах секций, а это ровно тот код, который ломается на чужом ответе.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// cacheKey — ключ кэша. Имя регистронезависимо (RFC 4343), а тип и класс —
// часть вопроса: смешать A с AAAA значит ответить не на тот вопрос.
func cacheKey(q dnsmessage.Question) string {
	return fmt.Sprintf("%s|%d|%d", strings.ToLower(q.Name.String()), q.Type, q.Class)
}

// withID подставляет в готовый ответ идентификатор запроса: из кэша уходит
// чужой, а ответ с чужим идентификатором клиент отбросит. Копия, а не правка на
// месте, — в кэше лежит один ответ на всех спрашивающих.
func withID(msg []byte, id uint16) []byte {
	out := make([]byte, len(msg))
	copy(out, msg)
	binary.BigEndian.PutUint16(out, id)
	return out
}

// truncated — флаг TC: ответ не поместился в датаграмму.
func truncated(answer []byte) bool {
	var p dnsmessage.Parser
	h, err := p.Start(answer)
	return err == nil && h.Truncated
}

// answerWith собирает пустой ответ с заданным кодом. Отказ — это тоже ответ
// (§5.6): без него приложение ждёт таймаута своего резолвера.
func answerWith(h dnsmessage.Header, q dnsmessage.Question, rc dnsmessage.RCode) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		OpCode:             h.OpCode,
		RecursionDesired:   h.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rc,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	return b.Finish()
}

// buildQuery собирает наш собственный запрос — тот, которого не было у клиента.
func buildQuery(q dnsmessage.Question) ([]byte, uint16, error) {
	id := newID()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err := b.Question(q); err != nil {
		return nil, 0, err
	}
	msg, err := b.Finish()
	return msg, id, err
}

// newID — идентификатор запроса. Случайный, потому что bootstrap ходит мимо
// туннеля открытым UDP по локальной сети: предсказуемый идентификатор там
// подделывается кем угодно из той же сети.
func newID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// addrsOf достаёт адреса из ответа на наш запрос.
func addrsOf(answer []byte, id uint16) ([]netip.Addr, error) {
	var p dnsmessage.Parser
	h, err := p.Start(answer)
	if err != nil {
		return nil, fmt.Errorf("dns: неразбираемый ответ: %w", err)
	}
	if h.ID != id {
		return nil, errors.New("dns: ответ с чужим идентификатором")
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("dns: апстрим ответил %v", h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}

	var out []netip.Addr
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, err
		}
		if ah.Type != dnsmessage.TypeA {
			// CNAME по дороге к A нас не интересует: адрес всё равно придёт
			// A-записью в том же ответе.
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		a, err := p.AResource()
		if err != nil {
			return nil, err
		}
		out = append(out, netip.AddrFrom4(a.A))
	}
	if len(out) == 0 {
		return nil, errors.New("dns: в ответе нет адресов")
	}
	return out, nil
}

// fqdn дописывает корневую точку: dnsmessage требует имя целиком.
func fqdn(host string) string {
	if strings.HasSuffix(host, ".") {
		return host
	}
	return host + "."
}
