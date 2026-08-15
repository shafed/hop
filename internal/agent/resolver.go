package agent

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync/atomic"
)

// Resolver — то, что связка подставляет в netstack. Совпадает с
// netstack.Resolver; объявлен здесь, чтобы связка не зависела от направления
// импорта ради одного метода.
type Resolver interface {
	Query(query []byte, client, server netip.AddrPort) ([]byte, error)
}

// FlushableResolver — резолвер, умеющий сбрасывать кэш. Настоящий резолвер
// этапа 6 подписывается на события живости сам (§5.7); связка зовёт Flush
// только у того, кто это объявил, и порядок реакций Р33 держится на ней.
type FlushableResolver interface {
	Resolver
	Flush()
}

// servfailResolver — заглушка этапа С (Р31).
//
// Отвечает SERVFAIL на любой запрос, и это выбор, а не заглушка «на отвяжись».
// Молчание подвесило бы приложение до таймаута резолвера — ровно то, что
// запрещает §5.6 («закрытие — отказ, а не молчание»). Пустой NOERROR хуже
// SERVFAIL: он означает «такого имени нет», приложение кэширует отрицательный
// ответ и не повторит запрос, когда этап 6 приедет.
//
// Этап 6 заменяет только реализацию: интерфейс заморожен в netstack с этапа 3.
type servfailResolver struct {
	flushes atomic.Uint64
}

// Коды ответа DNS, RFC 1035 §4.1.1.
const (
	dnsRcodeServfail = 2
	dnsHeaderLen     = 12
	dnsFlagResponse  = 0x8000
	dnsRcodeMask     = 0x000F
)

// Query отражает заголовок запроса с выставленным QR и RCODE=SERVFAIL.
//
// Отражает, а не строит с нуля: резолвер клиента сверяет ID и вопрос, и ответ с
// чужим ID он отбросит, после чего мы получим то самое молчание, которого
// избегаем.
func (r *servfailResolver) Query(query []byte, _, _ netip.AddrPort) ([]byte, error) {
	if len(query) < dnsHeaderLen {
		return nil, fmt.Errorf("agent: DNS-запрос короче заголовка (%d байт)", len(query))
	}

	// Заголовок и секция вопроса возвращаются как есть; секции ответа,
	// полномочий и дополнений обнуляются — их у нас нет.
	out := make([]byte, len(query))
	copy(out, query)

	flags := binary.BigEndian.Uint16(out[2:4])
	flags |= dnsFlagResponse
	flags = (flags &^ dnsRcodeMask) | dnsRcodeServfail
	binary.BigEndian.PutUint16(out[2:4], flags)

	binary.BigEndian.PutUint16(out[6:8], 0)  // ANCOUNT
	binary.BigEndian.PutUint16(out[8:10], 0) // NSCOUNT
	binary.BigEndian.PutUint16(out[10:12], 0)

	// Всё, что шло после секции вопроса, отбрасывается вместе со счётчиками.
	if end, ok := questionEnd(out); ok {
		out = out[:end]
	}
	return out, nil
}

func (r *servfailResolver) Flush() { r.flushes.Add(1) }

// questionEnd — где кончается секция вопроса. Возвращает false на всём, что не
// разбирается: тогда ответ уходит целиком, и это безопаснее, чем обрезать
// наугад.
func questionEnd(msg []byte) (int, bool) {
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return 0, false
	}
	i := dnsHeaderLen
	for {
		if i >= len(msg) {
			return 0, false
		}
		l := int(msg[i])
		if l == 0 {
			i++
			break
		}
		// Сжатие имён в вопросе не встречается и разбору здесь не подлежит.
		if l&0xC0 != 0 {
			return 0, false
		}
		i += l + 1
	}
	if i+4 > len(msg) {
		return 0, false
	}
	return i + 4, true
}
