// Package dnsmsg — разбор DNS-сообщений по смещениям и сборка ответов из
// готовых кусков (§5.7, регистр docs/verification-dns.md, У6).
//
// Пакет ничего не пересобирает. Он читает сообщение и возвращает границы: где
// кончается секция вопроса, где начинается и кончается каждая запись, где
// внутри OPT лежит EDNS Client Subnet. Ответ клиенту собирается копированием
// срезов, и проверка D47 («ANSWER, AUTHORITY и ADDITIONAL совпадают с
// апстримовыми байт в байт, включая TTL») сводится к сравнению срезов, а не к
// разбору обеих сторон. У6 при таком устройстве держится по построению: чего
// мы не скопировали, того в ответе нет.
//
// Цена — потребитель работает со смещениями, а не с типизированными записями,
// и обязан помнить, что каждый возвращённый срез смотрит внутрь чужого буфера
// и живёт ровно столько, сколько живёт этот буфер.
//
// Библиотека не взята намеренно: golang.org/x/net/dns/dnsmessage смещений не
// отдаёт, и границы ECS пришлось бы считать байтами поверх неё — два разбора
// вместо одного.
//
// Сюда приезжают байты из сети. Любая функция пакета на любом входе обязана
// вернуть ошибку — не запаниковать и не зациклиться.
package dnsmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Размеры, RFC 1035 §2.3.4, §4.1.1, RFC 6891 §6.2.3.
const (
	HeaderLen = 12 // заголовок сообщения

	MaxName  = 255 // имя целиком в проводном виде
	MaxLabel = 63  // одна метка

	// MinUDPSize — сколько принимает клиент, не объявивший EDNS0. Он же —
	// пол для объявленного размера: значение меньше RFC велит считать 512.
	MinUDPSize = 512
	// MaxTCPSize — потолок сообщения по TCP, задан шириной префикса длины.
	MaxTCPSize = 65535
)

// Флаги заголовка, RFC 1035 §4.1.1.
const (
	FlagResponse           uint16 = 0x8000 // QR
	FlagAuthoritative      uint16 = 0x0400 // AA
	FlagTruncated          uint16 = 0x0200 // TC
	FlagRecursionDesired   uint16 = 0x0100 // RD
	FlagRecursionAvailable uint16 = 0x0080 // RA
	FlagAuthenticData      uint16 = 0x0020 // AD
	FlagCheckingDisabled   uint16 = 0x0010 // CD

	rcodeMask uint16 = 0x000F
)

// Коды ответа, RFC 1035 §4.1.1.
const (
	RcodeNoError  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5
)

// Типы записей — только те, о которых резолвер что-то знает. Остальные
// проходят насквозь неразобранными (D48), и заводить для них имена незачем.
const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeSOA   = 6
	TypeAAAA  = 28
	TypeOPT   = 41
	TypeHTTPS = 65
)

// ClassIN — единственный класс, который встречается на практике; в поле CLASS
// псевдозаписи OPT вместо класса лежит размер буфера (RFC 6891 §6.1.2).
const ClassIN = 1

// OptionECS — EDNS Client Subnet, RFC 7871. Вырезается из клиентского запроса
// и своя не добавляется (Р26, D49): опция сообщает апстриму подсеть, которую
// продукт как раз и прячет.
const OptionECS = 8

// optDOBit — старший бит расширенных флагов, лежащих в поле TTL псевдозаписи
// OPT (RFC 6891 §6.1.3): клиент просит DNSSEC.
const optDOBit = 1 << 15

var (
	ErrShort       = errors.New("dnsmsg: сообщение оборвано")
	ErrQDCount     = errors.New("dnsmsg: в сообщении не ровно один вопрос")
	ErrName        = errors.New("dnsmsg: непригодное имя")
	ErrCompression = errors.New("dnsmsg: указатель сжатия не ведёт назад")
	ErrRDLength    = errors.New("dnsmsg: RDLENGTH выходит за границу сообщения")
	ErrTrailing    = errors.New("dnsmsg: за последней записью остались лишние байты")
	ErrOption      = errors.New("dnsmsg: опция EDNS0 выходит за границу RDATA")
	ErrOptNotLast  = errors.New("dnsmsg: OPT не последняя запись сообщения")
	ErrLimit       = errors.New("dnsmsg: заголовок с вопросом не влезает в лимит")
)

// Header — двенадцать байт заголовка как есть. Счётчики хранятся сырыми: по
// ним идёт обход секций, и расхождение счётчика с содержимым обязано быть
// ошибкой разбора, а не молча исправленным числом.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Response — поднят ли QR.
func (h Header) Response() bool { return h.Flags&FlagResponse != 0 }

// Truncated — поднят ли TC: апстрим велит прийти по TCP (§5.7, D33).
func (h Header) Truncated() bool { return h.Flags&FlagTruncated != 0 }

// Rcode — код ответа. Расширенный код из OPT (RFC 6891 §6.1.3) сюда не
// подмешивается: своих кодов выше 15 мы не порождаем, а чужие уезжают клиенту
// байт в байт вместе с самой псевдозаписью.
func (h Header) Rcode() uint8 { return uint8(h.Flags & rcodeMask) }

// Name — имя в проводном виде: срез внутрь исходного сообщения, от первой
// метки до нулевого байта включительно.
type Name []byte

// EqualFold — сравнение без учёта регистра ASCII (Р23: EXAMPLE.com и
// example.com — одна запись кэша).
//
// Сравнение побайтовое, вместе с байтами длин, и это безопасно: длина метки не
// больше 63, а регистр меняет только диапазон 65–90, куда длины не попадают.
func (n Name) EqualFold(m Name) bool {
	if len(n) != len(m) {
		return false
	}
	for i := range n {
		if lowerASCII(n[i]) != lowerASCII(m[i]) {
			return false
		}
	}
	return true
}

// Key — имя в нижнем регистре как строка. Строка, а не срез: срез смотрит в
// буфер запроса, а ключ кэша обязан пережить этот буфер.
func (n Name) Key() string {
	b := make([]byte, len(n))
	for i := range n {
		b[i] = lowerASCII(n[i])
	}
	return string(b)
}

// String — имя в привычном виде, для логов и сообщений об ошибках. Точка и
// обратная косая экранируются, непечатное уходит в \DDD (RFC 4343).
func (n Name) String() string {
	var sb strings.Builder
	for i := 0; i < len(n); {
		l := int(n[i])
		if l == 0 {
			break
		}
		if i+1+l > len(n) {
			return sb.String() + "<обрыв>"
		}
		for _, c := range n[i+1 : i+1+l] {
			switch {
			case c == '.' || c == '\\':
				sb.WriteByte('\\')
				sb.WriteByte(c)
			case c < 0x21 || c > 0x7e:
				fmt.Fprintf(&sb, "\\%03d", c)
			default:
				sb.WriteByte(c)
			}
		}
		sb.WriteByte('.')
		i += 1 + l
	}
	if sb.Len() == 0 {
		return "."
	}
	return sb.String()
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// Question — единственная запись секции вопроса и её границы. Name хранится
// как пришло: ответ клиенту несёт написание из его запроса, иначе стаб с
// 0x20-рандомизацией отбросит наш ответ (Р23, D30).
type Question struct {
	Name  Name
	Type  uint16
	Class uint16
	End   int // первый байт после секции вопроса
}

// Key — ключ кэша (Р23): имя без учёта регистра, тип, класс.
func (q Question) Key() string {
	b := make([]byte, 0, len(q.Name)+4)
	for _, c := range q.Name {
		b = append(b, lowerASCII(c))
	}
	b = append(b, byte(q.Type>>8), byte(q.Type), byte(q.Class>>8), byte(q.Class))
	return string(b)
}

// Msg — разобранное сообщение поверх исходных байтов. Ничего не копирует:
// Raw — тот самый буфер, который пришёл из сети.
type Msg struct {
	Raw      []byte
	Header   Header
	Question Question
}

// Parse разбирает заголовок и секцию вопроса. Секции записей не трогает: на
// пути «попадание в кэш» они не нужны, а мусор в них поймает Scan там, где на
// него посмотрят.
func Parse(msg []byte) (Msg, error) {
	if len(msg) < HeaderLen {
		return Msg{}, fmt.Errorf("%w: заголовок %d байт из %d", ErrShort, len(msg), HeaderLen)
	}
	h := Header{
		ID:      binary.BigEndian.Uint16(msg[0:2]),
		Flags:   binary.BigEndian.Uint16(msg[2:4]),
		QDCount: binary.BigEndian.Uint16(msg[4:6]),
		ANCount: binary.BigEndian.Uint16(msg[6:8]),
		NSCount: binary.BigEndian.Uint16(msg[8:10]),
		ARCount: binary.BigEndian.Uint16(msg[10:12]),
	}
	// Ровно один вопрос. Ноль или два разбору не подлежат: ключ кэша, ответ
	// клиенту и сравнение вопроса с апстримовым — всё построено на одном.
	if h.QDCount != 1 {
		return Msg{}, fmt.Errorf("%w: QDCOUNT=%d", ErrQDCount, h.QDCount)
	}
	nameEnd, _, err := walkName(msg, HeaderLen, false)
	if err != nil {
		return Msg{}, err
	}
	if nameEnd+4 > len(msg) {
		return Msg{}, fmt.Errorf("%w: секция вопроса без типа и класса", ErrShort)
	}
	return Msg{
		Raw:    msg,
		Header: h,
		Question: Question{
			Name:  Name(msg[HeaderLen:nameEnd]),
			Type:  binary.BigEndian.Uint16(msg[nameEnd : nameEnd+2]),
			Class: binary.BigEndian.Uint16(msg[nameEnd+2 : nameEnd+4]),
			End:   nameEnd + 4,
		},
	}, nil
}

// QuestionBytes — заголовок и секция вопроса байт в байт (D3).
func (m Msg) QuestionBytes() []byte { return m.Raw[HeaderLen:m.Question.End] }

// Sections — всё после секции вопроса. Именно этот срез D47 сравнивает с
// апстримовым.
func (m Msg) Sections() []byte { return m.Raw[m.Question.End:] }

// Negative — отрицательный ответ: NXDOMAIN либо NOERROR с пустой ANSWER
// (NODATA), Р18. Смотрит на счётчик заголовка, а не на записи: NODATA в
// RFC 2308 определён именно счётчиком.
func (m Msg) Negative() bool {
	switch m.Header.Rcode() {
	case RcodeNXDomain:
		return true
	case RcodeNoError:
		return m.Header.ANCount == 0
	}
	return false
}

// walkName проходит имя, начинающееся в off, и возвращает первый байт после
// него. Сжатое имя **не разворачивается**: указатель и есть конец имени в
// записи, а само имя нам нигде не нужно — разворот стоил бы аллокации на
// каждую запись ради данных, которые никто не читает.
//
// Указатель обязан вести строго назад. Проверка стоит одного сравнения и
// делает петлю сжатия невозможной по построению — а петля здесь означает не
// битый ответ, а подвешенную на мусоре из сети горутину.
func walkName(msg []byte, off int, allowPtr bool) (end int, compressed bool, err error) {
	if off < HeaderLen || off >= len(msg) {
		return 0, false, fmt.Errorf("%w: имя начинается за границей", ErrShort)
	}
	wire := 0
	for {
		if off >= len(msg) {
			return 0, false, fmt.Errorf("%w: имя без корневой метки", ErrShort)
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, false, nil
		case l&0xC0 == 0xC0:
			if !allowPtr {
				// В секции вопроса сжимать нечего: имя идёт первым. Указатель
				// здесь — либо мусор, либо попытка увести разбор.
				return 0, false, fmt.Errorf("%w: сжатие в секции вопроса", ErrCompression)
			}
			if off+2 > len(msg) {
				return 0, false, fmt.Errorf("%w: указатель сжатия в один байт", ErrShort)
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) &^ 0xC000)
			if ptr >= off || ptr < HeaderLen {
				return 0, false, fmt.Errorf("%w: указатель %d при смещении %d", ErrCompression, ptr, off)
			}
			return off + 2, true, nil
		case l&0xC0 != 0:
			// 0x40 и 0x80 зарезервированы (RFC 6891 §6.1.1 отменил и последний
			// их пользователь); принимать их — значит гадать.
			return 0, false, fmt.Errorf("%w: метка с битами %#02x", ErrName, l&0xC0)
		default:
			wire += l + 1
			if wire+1 > MaxName {
				return 0, false, fmt.Errorf("%w: длиннее %d байт", ErrName, MaxName)
			}
			off += l + 1
		}
	}
}
