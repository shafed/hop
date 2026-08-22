package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// D3. Ответ клиенту несёт секцию вопроса байт в байт, поэтому разбор обязан
// отдавать её точные границы и написание имени как оно пришло (Р23).
func TestD3ParseQuestionBounds(t *testing.T) {
	cases := []struct {
		name  string
		qname string
		qtype uint16
	}{
		{"обычное имя", "example.com", TypeA},
		{"смешанный регистр", "EXAMPLE.Com", TypeA},
		{"корень", "", TypeNS},
		{"одна метка", "localhost", TypeA},
		{"много меток", "a.b.c.d.e.f.example.com", TypeAAAA},
		{"метка в 63 байта", strings.Repeat("x", 63) + ".example.com", TypeHTTPS},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := question(c.qname, c.qtype)
			raw := assemble(0x1234, FlagRecursionDesired, q, nil, nil, nil)
			m, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if m.Header.ID != 0x1234 {
				t.Fatalf("ID %#x, ожидался 0x1234", m.Header.ID)
			}
			if m.Question.Type != c.qtype || m.Question.Class != ClassIN {
				t.Fatalf("тип/класс %d/%d", m.Question.Type, m.Question.Class)
			}
			if !bytes.Equal(m.QuestionBytes(), q) {
				t.Fatalf("секция вопроса %x, ожидалась %x", m.QuestionBytes(), q)
			}
			if want := wireName(c.qname); !bytes.Equal(m.Question.Name, want) {
				t.Fatalf("имя %x, ожидалось %x", m.Question.Name, want)
			}
			if len(m.Sections()) != 0 {
				t.Fatalf("после вопроса %d лишних байт", len(m.Sections()))
			}
		})
	}
}

// D8, D15. Мусор на :53 и мусор от апстрима — ошибка разбора, а не паника и не
// «разобралось до сюда».
func TestD8ParseRejects(t *testing.T) {
	valid := aQuery(1)

	withQD := func(n uint16) []byte {
		b := append([]byte(nil), valid...)
		binary.BigEndian.PutUint16(b[4:6], n)
		return b
	}
	longName := func() []byte {
		q := []byte{}
		for i := 0; i < 5; i++ {
			q = append(q, byte(63))
			q = append(q, bytes.Repeat([]byte("x"), 63)...)
		}
		q = append(q, 0, 0, 1, 0, 1)
		return assemble(1, 0, q, nil, nil, nil)
	}

	cases := []struct {
		name string
		msg  []byte
	}{
		{"пустой вход", nil},
		{"короче заголовка", valid[:HeaderLen-1]},
		{"только заголовок", valid[:HeaderLen]},
		{"QDCOUNT=0", withQD(0)},
		{"QDCOUNT=2", withQD(2)},
		{"имя без корневой метки", valid[:len(valid)-6]},
		{"метка за границей сообщения", append(append([]byte(nil), valid[:HeaderLen]...), 63, 'a')},
		{"вопрос без типа и класса", valid[:len(valid)-3]},
		{"сжатие в секции вопроса", append(append([]byte(nil), valid[:HeaderLen]...), 0xC0, 0x0C, 0, 1, 0, 1)},
		{"зарезервированные биты метки", append(append([]byte(nil), valid[:HeaderLen]...), 0x40, 'a', 0, 0, 1, 0, 1)},
		{"имя длиннее 255 байт", longName()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(c.msg); err == nil {
				t.Fatal("разбор принял непригодное сообщение")
			}
		})
	}
}

// D30, Р23. EXAMPLE.com и example.com — одна запись кэша; написание в ответе
// берётся из запроса, а значит в ключ регистр не попадает, а в Name попадает.
func TestD30NameFoldingAndKey(t *testing.T) {
	upper, err := Parse(assemble(1, 0, question("EXAMPLE.com", TypeA), nil, nil, nil))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	lower, err := Parse(assemble(2, 0, question("example.com", TypeA), nil, nil, nil))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !upper.Question.Name.EqualFold(lower.Question.Name) {
		t.Fatal("имена в разном регистре не признаны одним")
	}
	if upper.Question.Key() != lower.Question.Key() {
		t.Fatal("ключи кэша разошлись по регистру")
	}
	if bytes.Equal(upper.Question.Name, lower.Question.Name) {
		t.Fatal("написание из запроса потеряно — стаб с 0x20 отбросит ответ")
	}
}

// D31. A и TXT одного имени — две записи кэша, значит два разных ключа.
func TestD31KeySeparatesType(t *testing.T) {
	a, _ := Parse(assemble(1, 0, question("example.com", TypeA), nil, nil, nil))
	aaaa, _ := Parse(assemble(1, 0, question("example.com", TypeAAAA), nil, nil, nil))
	if a.Question.Key() == aaaa.Question.Key() {
		t.Fatal("ключ не различает тип вопроса")
	}
	other, _ := Parse(assemble(1, 0, question("example.org", TypeA), nil, nil, nil))
	if a.Question.Key() == other.Question.Key() {
		t.Fatal("ключ не различает имя")
	}
}

// Имя нужно печатать в логах и сообщениях об ошибках, и печать не должна
// падать на именах, пришедших из сети.
func TestNameString(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"обычное", "example.com", "example.com."},
		{"корень", "", "."},
		{"регистр сохранён", "EXAMPLE.com", "EXAMPLE.com."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Name(wireName(c.in)).String(); got != c.want {
				t.Fatalf("%q, ожидалось %q", got, c.want)
			}
		})
	}
	if got := Name([]byte{3, 'a'}).String(); !strings.Contains(got, "обрыв") {
		t.Fatalf("обрубленное имя напечаталось как %q", got)
	}
	if got := Name(append([]byte{5}, []byte("a.b\x00c")...)).String(); got != `a\.b\000c.` {
		t.Fatalf("экранирование дало %q", got)
	}
}
