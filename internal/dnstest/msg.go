package dnstest

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// Типы записей и класс — только те, что нужны фикстурам этапа 6.
const (
	TypeA     = 1
	TypeCNAME = 5
	TypeSOA   = 6
	TypeTXT   = 16
	TypeAAAA  = 28
	TypeOPT   = 41
	TypeRRSIG = 46
	TypeSVCB  = 65

	ClassIN = 1
)

// Коды ответа (RCODE) — только используемые регистром.
const (
	RCodeNOERROR  = 0
	RCodeSERVFAIL = 2
	RCodeNXDOMAIN = 3
)

// DefaultEDNS0BufSize — буфер, который регистр называет как типичный при
// сборке запроса с EDNS0 (§4: «буфер EDNS0 в нашем запросе наверх — 4096»).
const DefaultEDNS0BufSize = 4096

// optECS — код опции EDNS Client Subnet (RFC 7871).
const optECS = 8

// Flags — биты заголовка DNS-сообщения (RFC 1035 §4.1.1).
type Flags struct {
	QR, AA, TC, RD, RA, AD, CD bool
	Opcode                     uint8
	RCode                      uint8
}

func (f Flags) encode() uint16 {
	var v uint16
	if f.QR {
		v |= 1 << 15
	}
	v |= uint16(f.Opcode&0xF) << 11
	if f.AA {
		v |= 1 << 10
	}
	if f.TC {
		v |= 1 << 9
	}
	if f.RD {
		v |= 1 << 8
	}
	if f.RA {
		v |= 1 << 7
	}
	if f.AD {
		v |= 1 << 5
	}
	if f.CD {
		v |= 1 << 4
	}
	v |= uint16(f.RCode & 0xF)
	return v
}

// Name кодирует доменное имя в формат меток DNS. Без сжатия указателями —
// фикстурам оно не нужно, а лишний код здесь был бы кодом, который сам
// потребовал бы проверки.
func Name(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	var buf []byte
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
		}
	}
	return append(buf, 0)
}

func putUint16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }
func putUint32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }

// ECS — опция EDNS Client Subnet клиентского запроса (RFC 7871): D49
// проверяет, что наверх она не уходит.
type ECS struct {
	Family       uint16 // 1 — IPv4, 2 — IPv6
	SourcePrefix uint8
	ScopePrefix  uint8
	Address      netip.Addr
}

func (e ECS) encode() []byte {
	addr := e.Address.AsSlice()
	n := int(e.SourcePrefix+7) / 8
	if n > len(addr) {
		n = len(addr)
	}
	var opt []byte
	opt = putUint16(opt, e.Family)
	opt = append(opt, e.SourcePrefix, e.ScopePrefix)
	opt = append(opt, addr[:n]...)

	var out []byte
	out = putUint16(out, optECS)
	out = putUint16(out, uint16(len(opt)))
	return append(out, opt...)
}

// QueryOpts — как собрать клиентский запрос.
type QueryOpts struct {
	ID   uint16
	Name string
	Type uint16

	// EDNS0 добавляет OPT-запись (RFC 6891) в ADDITIONAL. BufSize, DO и ECS
	// без EDNS0 игнорируются.
	EDNS0   bool
	BufSize uint16 // 0 при EDNS0 — берётся DefaultEDNS0BufSize
	DO      bool
	ECS     *ECS
}

// BuildQuery строит клиентский запрос: секция QUESTION и, если заказан
// EDNS0, одна запись OPT в ADDITIONAL.
func BuildQuery(o QueryOpts) []byte {
	var b []byte
	b = putUint16(b, o.ID)
	b = putUint16(b, Flags{RD: true}.encode())
	b = putUint16(b, 1) // QDCOUNT
	b = putUint16(b, 0) // ANCOUNT
	b = putUint16(b, 0) // NSCOUNT
	arcount := uint16(0)
	if o.EDNS0 {
		arcount = 1
	}
	b = putUint16(b, arcount)
	b = append(b, Name(o.Name)...)
	b = putUint16(b, o.Type)
	b = putUint16(b, ClassIN)
	if o.EDNS0 {
		bufSize := o.BufSize
		if bufSize == 0 {
			bufSize = DefaultEDNS0BufSize
		}
		b = append(b, buildOPT(bufSize, o.DO, o.ECS)...)
	}
	return b
}

func buildOPT(bufSize uint16, do bool, ecs *ECS) []byte {
	var b []byte
	b = append(b, 0) // корневое имя
	b = putUint16(b, TypeOPT)
	b = putUint16(b, bufSize) // CLASS — заявленный буфер (RFC 6891 §6.1.2)
	var ttl uint32
	if do {
		ttl |= 1 << 15 // DO — старший бит младших 16 бит TTL (RFC 3225)
	}
	b = putUint32(b, ttl)
	var rdata []byte
	if ecs != nil {
		rdata = append(rdata, ecs.encode()...)
	}
	b = putUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

// RR — одна ресурсная запись ответа. Data должна быть уже собрана вызывающим
// — стенд не пытается уметь кодировать все типы записей, только склеивать их
// в сообщение (D48: неизвестный тип проходит как есть).
type RR struct {
	Name string
	Type uint16
	TTL  uint32
	Data []byte
}

func (rr RR) encode() []byte {
	var b []byte
	b = append(b, Name(rr.Name)...)
	b = putUint16(b, rr.Type)
	b = putUint16(b, ClassIN)
	b = putUint32(b, rr.TTL)
	b = putUint16(b, uint16(len(rr.Data)))
	return append(b, rr.Data...)
}

// ResponseOpts — как собрать ответ апстрима.
type ResponseOpts struct {
	ID    uint16
	QName string
	QType uint16
	Flags Flags // QR подставляется принудительно

	Answer     []RR
	Authority  []RR
	Additional []RR
}

// BuildResponse строит ответ апстрима: секция QUESTION — копия запроса,
// дальше три секции RR как заданы. Копирование секции вопроса байт в байт —
// то же требование, которым связан настоящий резолвер (§2, требование 7,
// У6): фикстура ему следует, а не подыгрывает ему в тесте.
func BuildResponse(o ResponseOpts) []byte {
	var b []byte
	b = putUint16(b, o.ID)
	f := o.Flags
	f.QR = true
	b = putUint16(b, f.encode())
	b = putUint16(b, 1)
	b = putUint16(b, uint16(len(o.Answer)))
	b = putUint16(b, uint16(len(o.Authority)))
	b = putUint16(b, uint16(len(o.Additional)))
	b = append(b, Name(o.QName)...)
	b = putUint16(b, o.QType)
	b = putUint16(b, ClassIN)
	for _, rr := range o.Answer {
		b = append(b, rr.encode()...)
	}
	for _, rr := range o.Authority {
		b = append(b, rr.encode()...)
	}
	for _, rr := range o.Additional {
		b = append(b, rr.encode()...)
	}
	return b
}

// ResponseA — ответ на A-запрос с одной записью и заданным TTL.
func ResponseA(id uint16, qname string, ttl uint32, ip netip.Addr) []byte {
	return BuildResponse(ResponseOpts{
		ID: id, QName: qname, QType: TypeA,
		Flags:  Flags{RD: true, RA: true, RCode: RCodeNOERROR},
		Answer: []RR{{Name: qname, Type: TypeA, TTL: ttl, Data: ip.AsSlice()}},
	})
}

// ResponseAAAA — то же для AAAA. Резолвер синтезирует пустой ответ на AAAA
// сам (Р19) и апстрим об этом штатно не спрашивает; функция здесь для
// полноты стенда и для проверок поведения, если бы апстрим всё же ответил.
func ResponseAAAA(id uint16, qname string, ttl uint32, ip netip.Addr) []byte {
	return BuildResponse(ResponseOpts{
		ID: id, QName: qname, QType: TypeAAAA,
		Flags:  Flags{RD: true, RA: true, RCode: RCodeNOERROR},
		Answer: []RR{{Name: qname, Type: TypeAAAA, TTL: ttl, Data: ip.AsSlice()}},
	})
}

// ResponseCNAMEA — CNAME (TTL cnameTTL) на target и A (TTL aTTL) на target.
// С аргументами 30 и 300 — ровно фикстура D25: запись живёт по минимуму TTL
// секции ANSWER.
func ResponseCNAMEA(id uint16, qname, target string, cnameTTL, aTTL uint32, ip netip.Addr) []byte {
	return BuildResponse(ResponseOpts{
		ID: id, QName: qname, QType: TypeA,
		Flags: Flags{RD: true, RA: true, RCode: RCodeNOERROR},
		Answer: []RR{
			{Name: qname, Type: TypeCNAME, TTL: cnameTTL, Data: Name(target)},
			{Name: target, Type: TypeA, TTL: aTTL, Data: ip.AsSlice()},
		},
	})
}

// SOA — поля записи SOA, нужные для отрицательного кэша (Р18): MINIMUM и TTL
// самой записи SOA задаются раздельно, потому что D26 и D29 различают их
// (окно кэша против потолка).
type SOA struct {
	MName, RName                            string
	Serial, Refresh, Retry, Expire, Minimum uint32
}

func (s SOA) encode() []byte {
	var b []byte
	b = append(b, Name(s.MName)...)
	b = append(b, Name(s.RName)...)
	b = putUint32(b, s.Serial)
	b = putUint32(b, s.Refresh)
	b = putUint32(b, s.Retry)
	b = putUint32(b, s.Expire)
	b = putUint32(b, s.Minimum)
	return b
}

// ResponseNXDOMAIN — NXDOMAIN без секции AUTHORITY (D27: без SOA резолвер
// кэширует отрицательный ответ на умолчательные 30 с).
func ResponseNXDOMAIN(id uint16, qname string, qtype uint16) []byte {
	return BuildResponse(ResponseOpts{
		ID: id, QName: qname, QType: qtype,
		Flags: Flags{RD: true, RA: true, RCode: RCodeNXDOMAIN},
	})
}

// ResponseNXDOMAINWithSOA — NXDOMAIN с записью SOA в AUTHORITY. zone — имя
// владельца SOA (обычно апекс зоны; не обязано совпадать с qname); soaTTL —
// TTL самой записи SOA, отдельно от soa.Minimum (D26 против D29: проверка
// различает окно отрицательного кэша и потолок 300 с).
func ResponseNXDOMAINWithSOA(id uint16, qname string, qtype uint16, zone string, soaTTL uint32, soa SOA) []byte {
	return BuildResponse(ResponseOpts{
		ID: id, QName: qname, QType: qtype,
		Flags:     Flags{RD: true, RA: true, RCode: RCodeNXDOMAIN},
		Authority: []RR{{Name: zone, Type: TypeSOA, TTL: soaTTL, Data: soa.encode()}},
	})
}

// ResponseNoData — NOERROR с пустой секцией ANSWER (NODATA): D28 кэширует
// его теми же правилами, что NXDOMAIN.
func ResponseNoData(id uint16, qname string, qtype uint16) []byte {
	return BuildResponse(ResponseOpts{
		ID: id, QName: qname, QType: qtype,
		Flags: Flags{RD: true, RA: true, RCode: RCodeNOERROR},
	})
}

// ResponseNoDataWithSOA — то же, с SOA в AUTHORITY: NODATA следует тем же
// правилам отрицательного кэша, что NXDOMAIN (Р18).
func ResponseNoDataWithSOA(id uint16, qname string, qtype uint16, zone string, soaTTL uint32, soa SOA) []byte {
	return BuildResponse(ResponseOpts{
		ID: id, QName: qname, QType: qtype,
		Flags:     Flags{RD: true, RA: true, RCode: RCodeNOERROR},
		Authority: []RR{{Name: zone, Type: TypeSOA, TTL: soaTTL, Data: soa.encode()}},
	})
}

// WithTC поднимает флаг TC в уже собранном сообщении, не трогая исходный
// срез (D33).
func WithTC(msg []byte) []byte {
	out := append([]byte(nil), msg...)
	if len(out) >= 3 {
		out[2] |= 1 << 1
	}
	return out
}

// Filler — n детерминированных байт: годится как RDATA записи неизвестного
// типа (D48, D50) и как балласт, доводящий ответ до нужного размера
// (ResponseOversized).
func Filler(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*31 + 7)
	}
	return out
}

// fillerIP — не маршрутизируется (RFC 5737, TEST-NET-3): в проверках
// усечения важен только размер ответа, не адреса в нём.
var fillerIP = netip.MustParseAddr("203.0.113.1")

// ResponseOversized — A-ответ, растущий записями одного и того же имени,
// пока сообщение не достигнет minSize байт: нужен для D34/D35 (границы
// усечения к клиенту — 512 без EDNS0, 4096 с ним).
func ResponseOversized(id uint16, qname string, minSize int) []byte {
	var answer []RR
	msg := BuildResponse(ResponseOpts{ID: id, QName: qname, QType: TypeA, Flags: Flags{RD: true, RA: true}})
	for len(msg) < minSize {
		answer = append(answer, RR{Name: qname, Type: TypeA, TTL: 300, Data: fillerIP.AsSlice()})
		msg = BuildResponse(ResponseOpts{ID: id, QName: qname, QType: TypeA, Flags: Flags{RD: true, RA: true}, Answer: answer})
	}
	return msg
}

// BrokenHeader — короче 12 байт заголовка: разбор обязан отказать на длине,
// а не читать за срезом (D8, D15).
func BrokenHeader() []byte { return []byte{0x00, 0x01, 0x02} }

// TrailingGarbage дописывает к валидному сообщению мусорный хвост поверх
// объявленных секций (D15).
func TrailingGarbage(msg []byte) []byte {
	return append(append([]byte(nil), msg...), 0xDE, 0xAD, 0xBE, 0xEF)
}

// QueryID читает идентификатор запроса — первые два байта заголовка. Нужен
// Behavior.Func, чтобы вернуть ответ с тем же ID, что и в запросе, не
// разбирая всё сообщение вручную.
func QueryID(query []byte) uint16 {
	if len(query) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(query[:2])
}
