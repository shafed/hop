package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// D47, D48. Обход отдаёт границы, по которым запись копируется целиком, и не
// пытается разобрать тип, которого не знает.
func TestD47ScanBounds(t *testing.T) {
	answer := record("example.com", TypeA, ClassIN, 300, []byte{203, 0, 113, 7})
	unknown := record("example.com", 65535, ClassIN, 60, []byte{9, 9, 9, 9, 9})
	soa := record("example.com", TypeSOA, ClassIN, 900, soaRDATA(1, 60))
	opt := optRecord(4096, false)
	raw := assemble(7, FlagResponse, question("example.com", TypeA),
		[][]byte{answer, unknown}, [][]byte{soa}, [][]byte{opt})

	m, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := []struct {
		bytes   []byte
		section Section
		rtype   uint16
		ttl     uint32
	}{
		{answer, SectionAnswer, TypeA, 300},
		{unknown, SectionAnswer, 65535, 60},
		{soa, SectionAuthority, TypeSOA, 900},
		{opt, SectionAdditional, TypeOPT, 0},
	}

	var got []RR
	s := m.Scan()
	for s.Next() {
		got = append(got, s.RR())
	}
	if err := s.Err(); err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("записей %d, ожидалось %d", len(got), len(want))
	}
	for i, w := range want {
		rr := got[i]
		if !bytes.Equal(raw[rr.Start:rr.End], w.bytes) {
			t.Fatalf("запись %d: %x, ожидалась %x", i, raw[rr.Start:rr.End], w.bytes)
		}
		if rr.Section != w.section || rr.Type != w.rtype || rr.TTL != w.ttl {
			t.Fatalf("запись %d: %v/%d/%d", i, rr.Section, rr.Type, rr.TTL)
		}
		if rr.RDLength() != len(w.bytes)-(rr.RDStart-rr.Start) {
			t.Fatalf("запись %d: RDLENGTH %d не сходится с границами", i, rr.RDLength())
		}
	}
	// Ровно то сравнение, которым D47 проверяет отсутствие самодеятельности.
	if !bytes.Equal(m.Sections(), raw[m.Question.End:]) {
		t.Fatal("секции не срез исходного сообщения")
	}
}

// Сжатое имя владельца — норма в ответах апстрима, и разбор обязан его
// проходить, не разворачивая.
func TestScanCompressedOwnerName(t *testing.T) {
	// Запись, чьё имя — указатель на имя вопроса (смещение 12).
	rr := []byte{0xC0, HeaderLen}
	rr = binary.BigEndian.AppendUint16(rr, TypeA)
	rr = binary.BigEndian.AppendUint16(rr, ClassIN)
	rr = binary.BigEndian.AppendUint32(rr, 42)
	rr = binary.BigEndian.AppendUint16(rr, 4)
	rr = append(rr, 203, 0, 113, 7)

	m, err := Parse(assemble(1, FlagResponse, question("example.com", TypeA), [][]byte{rr}, nil, nil))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s := m.Scan()
	if !s.Next() {
		t.Fatalf("запись со сжатым именем не разобрана: %v", s.Err())
	}
	if s.RR().TTL != 42 || s.RR().RDLength() != 4 {
		t.Fatalf("поля записи прочитаны неверно: %+v", s.RR())
	}
	if s.Next() {
		t.Fatal("лишняя запись")
	}
	if err := s.Err(); err != nil {
		t.Fatalf("обход: %v", err)
	}
}

// D15. Мусор от апстрима обязан кончаться ошибкой, а не паникой и не
// подвешенной горутиной.
func TestD15ScanRejects(t *testing.T) {
	q := question("example.com", TypeA)
	good := record("example.com", TypeA, ClassIN, 300, []byte{203, 0, 113, 7})

	badRDLen := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(badRDLen[len(badRDLen)-6:], 4000) // RDLENGTH за границей

	selfPtr := []byte{0xC0, byte(HeaderLen + len(q))} // указатель на самого себя
	selfPtr = append(selfPtr, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0)

	fwdPtr := []byte{0xC0, 0xFF} // указатель вперёд
	fwdPtr = append(fwdPtr, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0)

	cases := []struct {
		name string
		raw  []byte
	}{
		{"RDLENGTH за границей", assemble(1, FlagResponse, q, [][]byte{badRDLen}, nil, nil)},
		{"запись обрублена на фиксированной части", assemble(1, FlagResponse, q, [][]byte{good[:len(good)-8]}, nil, nil)},
		{"RDATA обрублена", assemble(1, FlagResponse, q, [][]byte{good[:len(good)-2]}, nil, nil)},
		{"петля сжатия на себя", assemble(1, FlagResponse, q, [][]byte{selfPtr}, nil, nil)},
		{"указатель вперёд", assemble(1, FlagResponse, q, [][]byte{fwdPtr}, nil, nil)},
		{"ANCOUNT больше, чем записей", assemble(1, FlagResponse, q, [][]byte{good, good}, nil, nil)[:HeaderLen+len(q)+len(good)]},
		{"лишние байты за последней записью", append(assemble(1, FlagResponse, q, [][]byte{good}, nil, nil), 0xDE, 0xAD)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := Parse(c.raw)
			if err != nil {
				return // отвергнуто ещё на заголовке — тоже отказ
			}
			s := m.Scan()
			for s.Next() {
			}
			if s.Err() == nil {
				t.Fatal("обход принял битое сообщение")
			}
			if _, err := m.Facts(); err == nil {
				t.Fatal("Facts принял битое сообщение")
			}
		})
	}
}

// D25, Р17. Время жизни записи — минимум TTL по секции ANSWER.
func TestD25FactsMinTTL(t *testing.T) {
	cases := []struct {
		name string
		an   [][]byte
		want uint32
		has  bool
	}{
		{"одна запись", [][]byte{record("example.com", TypeA, ClassIN, 300, []byte{1, 2, 3, 4})}, 300, true},
		{
			"CNAME 30 и A 300 — минимум 30",
			[][]byte{
				record("example.com", TypeCNAME, ClassIN, 30, wireName("target.example.com")),
				record("target.example.com", TypeA, ClassIN, 300, []byte{1, 2, 3, 4}),
			},
			30, true,
		},
		{"TTL 0 виден как 0", [][]byte{record("example.com", TypeA, ClassIN, 0, []byte{1, 2, 3, 4})}, 0, true},
		{"пустая ANSWER", nil, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// TTL в AUTHORITY и ADDITIONAL меньше, чем в ANSWER: минимум
			// считается по ANSWER, а не по сообщению.
			extra := [][]byte{record("example.com", TypeNS, ClassIN, 1, wireName("ns.example.com"))}
			raw := assemble(1, FlagResponse, question("example.com", TypeA), c.an, extra, nil)
			m, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			f, err := m.Facts()
			if err != nil {
				t.Fatalf("Facts: %v", err)
			}
			if f.HasAnswer != c.has || f.MinTTL != c.want {
				t.Fatalf("HasAnswer=%v MinTTL=%d, ожидалось %v/%d", f.HasAnswer, f.MinTTL, c.has, c.want)
			}
		})
	}
}

// D26, D29, Р18. Отрицательный кэш живёт по SOA из AUTHORITY: её TTL и поле
// MINIMUM. Потолок 300 с накладывает кэш, здесь — сырые числа.
func TestD26FactsSOA(t *testing.T) {
	soa := record("example.com", TypeSOA, ClassIN, 900, soaRDATA(2026082201, 86400))
	m, err := Parse(assemble(1, FlagResponse|uint16(RcodeNXDomain),
		question("nope.example.com", TypeA), nil, [][]byte{soa}, nil))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	f, err := m.Facts()
	if err != nil {
		t.Fatalf("Facts: %v", err)
	}
	if !f.HasSOA || f.SOATTL != 900 || f.SOAMinimum != 86400 {
		t.Fatalf("SOA прочитана как %+v", f)
	}
}

// D27. NXDOMAIN без SOA: кэш обязан различить «SOA нет» и «SOA с MINIMUM 0».
func TestD27FactsWithoutSOA(t *testing.T) {
	m, _ := Parse(assemble(1, FlagResponse|uint16(RcodeNXDomain), question("nope.example.com", TypeA), nil, nil, nil))
	f, err := m.Facts()
	if err != nil {
		t.Fatalf("Facts: %v", err)
	}
	if f.HasSOA {
		t.Fatal("SOA нашлась там, где её нет")
	}
}

// Обрубленная SOA не должна читаться четырьмя байтами из чужого поля.
func TestFactsRejectsShortSOA(t *testing.T) {
	short := record("example.com", TypeSOA, ClassIN, 900, []byte{0, 0, 0, 0, 0, 0})
	m, _ := Parse(assemble(1, FlagResponse, question("example.com", TypeA), nil, [][]byte{short}, nil))
	if _, err := m.Facts(); err == nil {
		t.Fatal("Facts принял SOA без обязательных полей")
	}
}

// D26, D28, Р18. Отрицательный ответ — NXDOMAIN либо NOERROR с пустой ANSWER.
func TestD28Negative(t *testing.T) {
	an := [][]byte{record("example.com", TypeA, ClassIN, 300, []byte{1, 2, 3, 4})}
	cases := []struct {
		name  string
		rcode uint8
		an    [][]byte
		want  bool
	}{
		{"NXDOMAIN", RcodeNXDomain, nil, true},
		{"NOERROR с пустой ANSWER", RcodeNoError, nil, true},
		{"NOERROR с записями", RcodeNoError, an, false},
		{"SERVFAIL — не отрицательный, а отказ", RcodeServFail, nil, false},
		{"REFUSED", RcodeRefused, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := assemble(1, FlagResponse|uint16(c.rcode), question("example.com", TypeA), c.an, nil, nil)
			m, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := m.Negative(); got != c.want {
				t.Fatalf("Negative=%v, ожидалось %v", got, c.want)
			}
		})
	}
}
