package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// D34, D35. Потолок ответа клиенту — объявленный им буфер EDNS0, а без OPT
// ровно 512 (RFC 6891 §6.2.3).
func TestD34BufferSize(t *testing.T) {
	cases := []struct {
		name string
		ar   [][]byte
		want int
	}{
		{"без OPT — 512", nil, MinUDPSize},
		{"объявлено 4096", [][]byte{optRecord(4096, false)}, 4096},
		{"объявлено 1232", [][]byte{optRecord(1232, false)}, 1232},
		{"объявлено меньше 512 — поднято до 512", [][]byte{optRecord(300, false)}, MinUDPSize},
		{"объявлен ноль — поднят до 512", [][]byte{optRecord(0, false)}, MinUDPSize},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := Parse(assemble(1, FlagRecursionDesired, question("example.com", TypeA), nil, nil, c.ar))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got, err := m.BufferSize()
			if err != nil {
				t.Fatalf("BufferSize: %v", err)
			}
			if got != c.want {
				t.Fatalf("буфер %d, ожидался %d", got, c.want)
			}
		})
	}
}

// D49, D50. Опции читаются границами, DO-бит виден и никуда не девается.
func TestD49Options(t *testing.T) {
	cookie := option(10, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	padding := option(12, make([]byte, 16))

	cases := []struct {
		name  string
		opts  [][]byte
		codes []uint16
	}{
		{"OPT без опций", nil, nil},
		{"одна ECS", [][]byte{ecsOption()}, []uint16{OptionECS}},
		{"ECS в середине", [][]byte{cookie, ecsOption(), padding}, []uint16{10, OptionECS, 12}},
		{"опция нулевой длины", [][]byte{option(12, nil)}, []uint16{12}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := assemble(1, FlagRecursionDesired, question("example.com", TypeA), nil, nil,
				[][]byte{optRecord(4096, true, c.opts...)})
			m, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			opt, ok, err := m.EDNS()
			if err != nil || !ok {
				t.Fatalf("EDNS: ok=%v err=%v", ok, err)
			}
			if !opt.DO {
				t.Fatal("DO-бит потерян: без него апстрим не пришлёт RRSIG (D50)")
			}
			if opt.UDPSize != 4096 {
				t.Fatalf("буфер %d", opt.UDPSize)
			}
			got, err := m.Options(opt)
			if err != nil {
				t.Fatalf("Options: %v", err)
			}
			if len(got) != len(c.codes) {
				t.Fatalf("опций %d, ожидалось %d", len(got), len(c.codes))
			}
			for i, code := range c.codes {
				if got[i].Code != code {
					t.Fatalf("опция %d: код %d, ожидался %d", i, got[i].Code, code)
				}
				if !bytes.Equal(raw[got[i].Start:got[i].End], c.opts[i]) {
					t.Fatalf("опция %d: границы не совпали с исходными байтами", i)
				}
			}
		})
	}
}

// Битая длина опции — мусор из сети, а не повод читать чужую память.
func TestOptionsRejectsBadLength(t *testing.T) {
	bad := option(OptionECS, []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint16(bad[2:4], 40) // длина больше, чем RDATA

	cases := []struct {
		name string
		opts []byte
	}{
		{"длина за границей RDATA", bad},
		{"обрубленный заголовок опции", []byte{0, 8, 0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := Parse(assemble(1, 0, question("example.com", TypeA), nil, nil,
				[][]byte{record("", TypeOPT, 4096, 0, c.opts)}))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			opt, ok, err := m.EDNS()
			if err != nil || !ok {
				t.Fatalf("EDNS: ok=%v err=%v", ok, err)
			}
			if _, err := m.Options(opt); err == nil {
				t.Fatal("разбор опций принял битую длину")
			}
		})
	}
}

// OPT из чужого сообщения — отказ, а не чтение за концом буфера. Из сети такой
// вход недостижим (нужны два разных сообщения), но сигнатура Options(opt) к
// путанице располагает: резолвер держит на руках и запрос клиента, и ответ
// апстрима сразу.
func TestOptionsRefusesForeignOPT(t *testing.T) {
	long := mustParse(t, assemble(1, 0, question("example.com", TypeA), nil, nil,
		[][]byte{record("", TypeOPT, 4096, 0, option(10, make([]byte, 64)))}))
	opt, ok, err := long.EDNS()
	if err != nil || !ok {
		t.Fatalf("EDNS: ok=%v err=%v", ok, err)
	}

	short := mustParse(t, aQuery(1)) // короче длинного и без OPT вовсе
	if opt.RDEnd <= len(short.Raw) {
		t.Fatalf("фикстура не короче: %d байт против границы OPT %d", len(short.Raw), opt.RDEnd)
	}
	if _, err := short.Options(opt); err == nil {
		t.Fatal("опции разобраны по границам чужого сообщения")
	}
	if _, err := (Msg{}).Options(opt); err == nil {
		t.Fatal("опции разобраны в нулевом Msg")
	}
}

// D49, Р26. ECS вырезается, RDLENGTH правится, всё остальное — байт в байт.
func TestD49StripECS(t *testing.T) {
	cookie := option(10, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	padding := option(12, make([]byte, 8))
	q := question("example.com", TypeA)

	cases := []struct {
		name string
		opts [][]byte
		want [][]byte
	}{
		{"единственная опция", [][]byte{ecsOption()}, nil},
		{"ECS в середине", [][]byte{cookie, ecsOption(), padding}, [][]byte{cookie, padding}},
		{"ECS первой", [][]byte{ecsOption(), cookie}, [][]byte{cookie}},
		{"ECS последней", [][]byte{cookie, ecsOption()}, [][]byte{cookie}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := assemble(0x2A2A, FlagRecursionDesired, q, nil, nil, [][]byte{optRecord(4096, true, c.opts...)})
			m, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			out, changed, err := StripECS(m)
			if err != nil || !changed {
				t.Fatalf("StripECS: changed=%v err=%v", changed, err)
			}

			want := assemble(0x2A2A, FlagRecursionDesired, q, nil, nil, [][]byte{optRecord(4096, true, c.want...)})
			if !bytes.Equal(out, want) {
				t.Fatalf("получилось %x\nожидалось  %x", out, want)
			}
			// Проверка отдельно от сравнения байт: RDLENGTH — то поле, которое
			// забывают поправить, и битым его увидит только апстрим.
			stripped, err := Parse(out)
			if err != nil {
				t.Fatalf("результат не разбирается: %v", err)
			}
			opt, ok, err := stripped.EDNS()
			if err != nil || !ok {
				t.Fatalf("OPT потеряна: ok=%v err=%v", ok, err)
			}
			opts, err := stripped.Options(opt)
			if err != nil {
				t.Fatalf("опции результата: %v", err)
			}
			if len(opts) != len(c.want) {
				t.Fatalf("опций осталось %d, ожидалось %d", len(opts), len(c.want))
			}
			for _, o := range opts {
				if o.Code == OptionECS {
					t.Fatal("ECS уцелела")
				}
			}
			if !opt.DO {
				t.Fatal("DO-бит снесён вместе с ECS (D50)")
			}
			if !bytes.Equal(stripped.QuestionBytes(), m.QuestionBytes()) {
				t.Fatal("секция вопроса изменилась")
			}
		})
	}
}

// Запрос без ECS переписывать не за чем: копии быть не должно.
func TestStripECSNothingToDo(t *testing.T) {
	cases := []struct {
		name string
		ar   [][]byte
	}{
		{"без OPT", nil},
		{"OPT без опций", [][]byte{optRecord(4096, false)}},
		{"OPT с другой опцией", [][]byte{optRecord(4096, false, option(10, []byte{1, 2}))}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := Parse(assemble(1, FlagRecursionDesired, question("example.com", TypeA), nil, nil, c.ar))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			out, changed, err := StripECS(m)
			if err != nil {
				t.Fatalf("StripECS: %v", err)
			}
			if changed || out != nil {
				t.Fatal("сделана копия там, где вырезать нечего")
			}
		})
	}
}

// Вырез сдвигает всё, что лежит за OPT, и абсолютные указатели сжатия в
// сдвинутых записях станут неверны. Отказ здесь — SERVFAIL на экзотику;
// молчаливый вырез был бы утечкой ECS наверх или битым запросом.
func TestStripECSRefusesWhenOPTNotLast(t *testing.T) {
	tail := record("example.com", 250 /* TSIG */, ClassIN, 0, []byte{1, 2, 3})
	raw := assemble(1, FlagRecursionDesired, question("example.com", TypeA), nil, nil,
		[][]byte{optRecord(4096, false, ecsOption()), tail})
	m, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, _, err := StripECS(m); err == nil {
		t.Fatal("вырез сделан там, где он сдвигает чужие записи")
	}
}
