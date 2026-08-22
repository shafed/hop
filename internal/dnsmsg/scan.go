package dnsmsg

import (
	"encoding/binary"
	"fmt"
)

// Section — секция, в которой лежит запись.
type Section uint8

const (
	SectionAnswer Section = iota
	SectionAuthority
	SectionAdditional
)

func (s Section) String() string {
	switch s {
	case SectionAnswer:
		return "ANSWER"
	case SectionAuthority:
		return "AUTHORITY"
	case SectionAdditional:
		return "ADDITIONAL"
	}
	return "?"
}

// RR — границы одной записи и её поля. Имени здесь нет намеренно: сжатое имя
// пришлось бы разворачивать с аллокацией, а ни кэшу, ни сборке ответа имя
// записи не нужно — нужна секция, тип, TTL и границы, по которым запись
// копируется целиком.
type RR struct {
	Section Section
	Type    uint16
	Class   uint16
	TTL     uint32
	Start   int // первый байт записи (её имени)
	End     int // первый байт после RDATA
	RDStart int
	RDEnd   int
}

// RDLength — объявленная длина RDATA.
func (r RR) RDLength() int { return r.RDEnd - r.RDStart }

// Scanner — обход записей трёх секций по порядку, без аллокаций.
//
// Форма bufio.Scanner выбрана не ради привычности: обход обязан прерываться
// на первой же непонятной записи, и ошибка должна доехать до вызывающего
// отдельно от «записи кончились» — иначе мусор от апстрима (D15) выглядит как
// пустой ответ.
type Scanner struct {
	msg  []byte
	off  int
	left [3]int
	sec  int
	rr   RR
	err  error
}

// Scan начинает обход с первой записи после секции вопроса.
func (m Msg) Scan() *Scanner {
	return &Scanner{
		msg:  m.Raw,
		off:  m.Question.End,
		left: [3]int{int(m.Header.ANCount), int(m.Header.NSCount), int(m.Header.ARCount)},
	}
}

// Next разбирает следующую запись. false — записи кончились либо разбор
// сломался; что именно, говорит Err.
func (s *Scanner) Next() bool {
	if s.err != nil {
		return false
	}
	for s.sec < len(s.left) && s.left[s.sec] == 0 {
		s.sec++
	}
	if s.sec == len(s.left) {
		// Лишние байты за последней записью — признак того, что счётчики и
		// содержимое разошлись. D15 требует на такой ответ SERVFAIL, а не
		// молчаливое «разобралось до сюда».
		if s.off != len(s.msg) {
			s.err = fmt.Errorf("%w: %d байт", ErrTrailing, len(s.msg)-s.off)
		}
		return false
	}
	rr, next, err := parseRR(s.msg, s.off, Section(s.sec))
	if err != nil {
		s.err = err
		return false
	}
	s.left[s.sec]--
	s.off = next
	s.rr = rr
	return true
}

// RR — запись, разобранная последним успешным Next.
func (s *Scanner) RR() RR { return s.rr }

// Err — ошибка, оборвавшая обход, либо nil.
func (s *Scanner) Err() error { return s.err }

func parseRR(msg []byte, off int, sec Section) (RR, int, error) {
	start := off
	nameEnd, _, err := walkName(msg, off, true)
	if err != nil {
		return RR{}, 0, fmt.Errorf("%s: %w", sec, err)
	}
	// Тип, класс, TTL, RDLENGTH — десять байт фиксированной части.
	if nameEnd+10 > len(msg) {
		return RR{}, 0, fmt.Errorf("%s: %w: запись без фиксированной части", sec, ErrShort)
	}
	rdLen := int(binary.BigEndian.Uint16(msg[nameEnd+8 : nameEnd+10]))
	rdStart := nameEnd + 10
	if rdStart+rdLen > len(msg) {
		return RR{}, 0, fmt.Errorf("%s: %w: RDLENGTH=%d, осталось %d", sec, ErrRDLength, rdLen, len(msg)-rdStart)
	}
	return RR{
		Section: sec,
		Type:    binary.BigEndian.Uint16(msg[nameEnd : nameEnd+2]),
		Class:   binary.BigEndian.Uint16(msg[nameEnd+2 : nameEnd+4]),
		TTL:     binary.BigEndian.Uint32(msg[nameEnd+4 : nameEnd+8]),
		Start:   start,
		End:     rdStart + rdLen,
		RDStart: rdStart,
		RDEnd:   rdStart + rdLen,
	}, rdStart + rdLen, nil
}

// Facts — то, что кэшу нужно от ответа. Собирается одним проходом: разбор
// сообщения ради TTL и разбор ради SOA — это два обхода мусора из сети вместо
// одного, и две точки, где мусор ловится по-разному.
//
// Правила Р17 и Р18 (потолки, пол, умолчание 30 с) здесь не применяются: это
// политика кэша, а не свойство сообщения.
type Facts struct {
	HasAnswer  bool   // ANSWER непуста; иначе MinTTL бессмыслен
	MinTTL     uint32 // минимум TTL по ANSWER (Р17, D25)
	HasSOA     bool   // в AUTHORITY есть SOA (Р18, D26)
	SOATTL     uint32
	SOAMinimum uint32 // поле MINIMUM — последние четыре байта RDATA
}

// soaFixed — пять 32-битных полей хвоста SOA (SERIAL, REFRESH, RETRY, EXPIRE,
// MINIMUM) плюс два имени минимум по байту.
const soaFixed = 5 * 4

// Facts проходит ANSWER и AUTHORITY. ADDITIONAL тоже разбирается — ради
// проверки, что сообщение целое: класть в кэш ответ, у которого не сходится
// хвост, значит кэшировать мусор (D15).
func (m Msg) Facts() (Facts, error) {
	var f Facts
	s := m.Scan()
	for s.Next() {
		rr := s.RR()
		switch {
		case rr.Section == SectionAnswer:
			if !f.HasAnswer || rr.TTL < f.MinTTL {
				f.MinTTL = rr.TTL
			}
			f.HasAnswer = true
		case rr.Section == SectionAuthority && rr.Type == TypeSOA && !f.HasSOA:
			if rr.RDLength() < soaFixed+2 {
				return Facts{}, fmt.Errorf("%w: RDATA SOA в %d байт", ErrRDLength, rr.RDLength())
			}
			f.HasSOA = true
			f.SOATTL = rr.TTL
			f.SOAMinimum = binary.BigEndian.Uint32(m.Raw[rr.RDEnd-4 : rr.RDEnd])
		}
	}
	if err := s.Err(); err != nil {
		return Facts{}, err
	}
	return f, nil
}
