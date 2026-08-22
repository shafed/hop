package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// D3, D47. Ответ клиенту отличается от ответа апстрима ровно идентификатором:
// секция вопроса и все три секции записей проходят байт в байт, включая TTL.
func TestD47ReplyChangesOnlyID(t *testing.T) {
	upstreamRaw := assemble(0xBEEF, FlagResponse|FlagRecursionAvailable,
		question("example.com", TypeA),
		[][]byte{record("example.com", TypeA, ClassIN, 300, []byte{203, 0, 113, 7})},
		[][]byte{record("example.com", TypeNS, ClassIN, 900, wireName("ns.example.com"))},
		[][]byte{optRecord(4096, true)})
	upstream, err := Parse(upstreamRaw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	before := append([]byte(nil), upstreamRaw...)

	reply := Reply(upstream, 0x1234)

	if reply.Header.ID != 0x1234 || binary.BigEndian.Uint16(reply.Raw[0:2]) != 0x1234 {
		t.Fatalf("идентификатор клиента не подставлен: %#x", reply.Header.ID)
	}
	if !bytes.Equal(reply.Sections(), upstream.Sections()) {
		t.Fatal("секции разошлись с апстримовыми")
	}
	if !bytes.Equal(reply.QuestionBytes(), upstream.QuestionBytes()) {
		t.Fatal("секция вопроса разошлась с апстримовой")
	}
	if !bytes.Equal(reply.Raw[2:], upstreamRaw[2:]) {
		t.Fatal("изменилось что-то кроме идентификатора")
	}
	if !bytes.Equal(upstreamRaw, before) {
		t.Fatal("буфер апстрима переписан на месте: он общий, в кэше он один на всех")
	}
	// Смещения перенесены на копию, а не оставлены смотреть в чужой буфер.
	if &reply.Raw[0] == &upstream.Raw[0] || &reply.Question.Name[0] == &upstream.Question.Name[0] {
		t.Fatal("копия делит память с оригиналом")
	}
	if !bytes.Equal(reply.Question.Name, upstream.Question.Name) {
		t.Fatal("имя в копии не совпало")
	}
}

// D3, D8, D11. Отказ отражает запрос: заголовок и вопрос из него, QR поднят,
// код подставлен, всё после вопроса отброшено вместе со счётчиками.
func TestD11Respond(t *testing.T) {
	q := question("EXAMPLE.com", TypeA)
	// В запросе есть OPT — в отказ он не переезжает: счётчики обнулены.
	raw := assemble(0x0F0F, FlagRecursionDesired, q, nil, nil, [][]byte{optRecord(4096, false, ecsOption())})
	m, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	for _, c := range []struct {
		name  string
		build func(Msg) []byte
		rcode uint8
	}{
		{"SERVFAIL", ServFail, RcodeServFail},
		{"пустой NOERROR", NoData, RcodeNoError},
		{"NXDOMAIN", func(m Msg) []byte { return Respond(m, RcodeNXDomain) }, RcodeNXDomain},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := c.build(m)
			resp, err := Parse(out)
			if err != nil {
				t.Fatalf("ответ не разбирается: %v", err)
			}
			if resp.Header.ID != m.Header.ID {
				t.Fatalf("идентификатор %#x, ожидался %#x", resp.Header.ID, m.Header.ID)
			}
			if !resp.Header.Response() {
				t.Fatal("QR не поднят: стаб примет ответ за запрос")
			}
			if resp.Header.Rcode() != c.rcode {
				t.Fatalf("код %d, ожидался %d", resp.Header.Rcode(), c.rcode)
			}
			if resp.Header.Truncated() {
				t.Fatal("TC поднят там, где ничего не урезано")
			}
			if resp.Header.Flags&FlagRecursionDesired == 0 {
				t.Fatal("RD не отражён")
			}
			if !bytes.Equal(resp.QuestionBytes(), q) {
				t.Fatal("секция вопроса не байт в байт")
			}
			if n := resp.Header.ANCount + resp.Header.NSCount + resp.Header.ARCount; n != 0 {
				t.Fatalf("счётчики не обнулены: %d", n)
			}
			if len(resp.Sections()) != 0 {
				t.Fatalf("после вопроса осталось %d байт", len(resp.Sections()))
			}
		})
	}
}

// D45, D46. AAAA при заблокированном IPv6 — пустой NOERROR, а не NXDOMAIN:
// иначе стаб вправе счесть, что имени нет вовсе, и A того же имени умрёт с
// ним.
func TestD45NoDataIsNotNXDomain(t *testing.T) {
	m, err := Parse(assemble(1, FlagRecursionDesired, question("example.com", TypeAAAA), nil, nil, nil))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	resp, err := Parse(NoData(m))
	if err != nil {
		t.Fatalf("ответ не разбирается: %v", err)
	}
	if resp.Header.Rcode() != RcodeNoError {
		t.Fatalf("код %d, ожидался NOERROR", resp.Header.Rcode())
	}
	if resp.Header.ANCount != 0 {
		t.Fatal("ANSWER не пуста")
	}
	if !resp.Negative() {
		t.Fatal("ответ не признан отрицательным — кэш положит его как обычный")
	}
}

// D34, D35. Не влезло в буфер клиента — заголовок с вопросом и TC, а не
// урезанные байты RRset.
func TestD34Fit(t *testing.T) {
	var answers [][]byte
	for i := 0; i < 40; i++ {
		answers = append(answers, record("example.com", TypeA, ClassIN, 300, []byte{203, 0, 113, byte(i)}))
	}
	big := assemble(1, FlagResponse|FlagRecursionAvailable, question("example.com", TypeA), answers, nil, nil)
	m, err := Parse(big)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(big) <= MinUDPSize {
		t.Fatalf("тест собрал сообщение в %d байт — оно влезает в 512", len(big))
	}

	t.Run("влезает — проходит как есть", func(t *testing.T) {
		out, truncated, err := Fit(m, 4096)
		if err != nil || truncated {
			t.Fatalf("truncated=%v err=%v", truncated, err)
		}
		if !bytes.Equal(out, big) {
			t.Fatal("влезающее сообщение изменено")
		}
	})

	t.Run("не влезает — TC и пустые секции", func(t *testing.T) {
		out, truncated, err := Fit(m, MinUDPSize)
		if err != nil || !truncated {
			t.Fatalf("truncated=%v err=%v", truncated, err)
		}
		if len(out) > MinUDPSize {
			t.Fatalf("ответ %d байт при потолке %d", len(out), MinUDPSize)
		}
		resp, err := Parse(out)
		if err != nil {
			t.Fatalf("усечённый ответ не разбирается: %v", err)
		}
		if !resp.Header.Truncated() {
			t.Fatal("TC не поднят: приложение получит мусор вместо указания прийти по TCP")
		}
		if !resp.Header.Response() || resp.Header.Rcode() != RcodeNoError {
			t.Fatalf("флаги ответа испорчены: %#x", resp.Header.Flags)
		}
		if resp.Header.ANCount != 0 || len(resp.Sections()) != 0 {
			t.Fatal("в усечённый ответ попали куски RRset")
		}
		if !bytes.Equal(resp.QuestionBytes(), m.QuestionBytes()) {
			t.Fatal("секция вопроса не байт в байт")
		}
	})

	t.Run("не влезает даже вопрос", func(t *testing.T) {
		if _, _, err := Fit(m, HeaderLen); err == nil {
			t.Fatal("Fit собрал ответ в потолок, куда не лезет вопрос")
		}
	})
}

// Наверх запрос уходит со своим идентификатором, а не клиентским (Р23, D4).
func TestD4WithID(t *testing.T) {
	q := aQuery(0x1111)
	out, err := WithID(q, 0x2222)
	if err != nil {
		t.Fatalf("WithID: %v", err)
	}
	if binary.BigEndian.Uint16(out[0:2]) != 0x2222 {
		t.Fatal("идентификатор не подставлен")
	}
	if !bytes.Equal(out[2:], q[2:]) {
		t.Fatal("изменилось что-то кроме идентификатора")
	}
	if binary.BigEndian.Uint16(q[0:2]) != 0x1111 {
		t.Fatal("исходный буфер переписан")
	}
	if _, err := WithID(q[:5], 1); err == nil {
		t.Fatal("принят буфер короче заголовка")
	}
}

// Bootstrap строит запрос сам; кодировщик имени — то место, где два разных
// кода разойдутся по-разному.
func TestNewQuery(t *testing.T) {
	out, err := NewQuery(0x7777, "node.example.com.", TypeA)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}
	m, err := Parse(out)
	if err != nil {
		t.Fatalf("собранный запрос не разбирается: %v", err)
	}
	if m.Header.ID != 0x7777 || m.Header.QDCount != 1 || m.Header.Response() {
		t.Fatalf("заголовок: %+v", m.Header)
	}
	if m.Header.Flags&FlagRecursionDesired == 0 {
		t.Fatal("RD не выставлен: апстрим ответит ссылкой, а не адресом")
	}
	if !bytes.Equal(m.Question.Name, wireName("node.example.com")) {
		t.Fatalf("имя %x", m.Question.Name)
	}
	if m.Question.Type != TypeA || m.Question.Class != ClassIN {
		t.Fatalf("тип/класс %d/%d", m.Question.Type, m.Question.Class)
	}
	if len(m.Sections()) != 0 {
		t.Fatal("в запросе оказалось что-то помимо вопроса")
	}

	bad := []struct {
		name string
		host string
	}{
		{"пустая метка", "node..example.com"},
		{"метка длиннее 63", strings.Repeat("x", 64) + ".example.com"},
		{"имя длиннее 255", strings.TrimSuffix(strings.Repeat(strings.Repeat("x", 63)+".", 5), ".")},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewQuery(1, c.host, TypeA); err == nil {
				t.Fatal("собран запрос с непригодным именем")
			}
		})
	}
}
