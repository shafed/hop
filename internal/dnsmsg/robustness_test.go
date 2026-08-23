package dnsmsg

import "testing"

// Сюда приезжают байты из сети. D8 («не-DNS на :53») и D15 («мусор от
// апстрима») требуют отказа, а не паники и не зависания, и требуют этого от
// всех точек входа сразу — резолвер зовёт их одну за другой на одном и том же
// буфере.

// exercise прогоняет весь пакет по одному входу. Возвращает без утверждений:
// проверяется здесь только то, что вызов вернулся.
func exercise(t *testing.T, raw []byte) {
	t.Helper()
	m, err := Parse(raw)
	if err != nil {
		// Msg{} — то, что Parse отдал вместе с ошибкой, и ровно то, что
		// подаст дальше обработчик, написавший `return ServFail(m)` (D8).
		// Раньше сюда не заглядывали, и паника на этом пути дожила до ревью.
		exerciseMsg(t, m)
		return
	}
	exerciseMsg(t, m)
	_, _ = WithID(raw, 1)
}

// exerciseMsg прогоняет по одному Msg всё, что его принимает, — включая Msg{},
// который Parse возвращает при ошибке.
func exerciseMsg(t *testing.T, m Msg) {
	t.Helper()
	_ = m.Negative()
	_ = m.Question.Key()
	_ = m.Question.Name.String()
	_ = m.Question.Name.EqualFold(m.Question.Name)
	_, _ = m.Facts()
	_, _ = m.BufferSize()
	if opt, ok, err := m.EDNS(); err == nil && ok {
		_, _ = m.Options(opt)
	}
	_, _, _ = StripECS(m)
	_, _ = ServFail(m)
	_, _ = NoData(m)
	_, _, _ = Fit(m, MinUDPSize)
	_, _, _ = Fit(m, len(m.Raw))
	_ = Reply(m, 1)
	_, _ = ReplyTo(m, m)
	_, _ = ReplyTo(Msg{}, m)
	_, _ = ReplyTo(m, Msg{})

	s := m.Scan()
	for s.Next() {
	}
	_ = s.Err()
}

// richMessage — сообщение со всеми секциями, сжатым именем, OPT и ECS: чем
// больше в нём разных мест, тем больше их проверят обрезания и правки байт.
func richMessage() []byte {
	compressed := []byte{0xC0, HeaderLen, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 203, 0, 113, 7}
	return assemble(0x4242, FlagResponse|FlagRecursionDesired|FlagRecursionAvailable,
		question("example.com", TypeA),
		[][]byte{
			record("example.com", TypeCNAME, ClassIN, 30, wireName("target.example.com")),
			compressed,
			record("example.com", 65535, ClassIN, 60, []byte{9, 9, 9}),
		},
		[][]byte{record("example.com", TypeSOA, ClassIN, 900, soaRDATA(1, 300))},
		[][]byte{optRecord(4096, true, option(10, []byte{1, 2, 3, 4}), ecsOption())})
}

// D8, D15. Оборванное сообщение любой длины — отказ, а не паника.
func TestD15TruncatedPrefixes(t *testing.T) {
	raw := richMessage()
	for n := 0; n <= len(raw); n++ {
		exercise(t, raw[:n:n])
	}
}

// D8, D15. Один испорченный байт в любом месте — тоже отказ. Правятся именно
// длины и указатели: 0xC0 делает из байта указатель сжатия, 0xFF — длину, за
// которой в буфере ничего нет.
func TestD15ByteFlips(t *testing.T) {
	raw := richMessage()
	for i := range raw {
		for _, v := range []byte{0x00, 0x01, 0x3F, 0x40, 0xC0, 0xFF} {
			mutated := append([]byte(nil), raw...)
			mutated[i] = v
			exercise(t, mutated)
		}
	}
}

// D8. Пакет на :53, не являющийся DNS-сообщением вовсе.
func TestD8NotDNS(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		make([]byte, 1),
		make([]byte, HeaderLen),
		make([]byte, 4096),
	}
	for _, c := range cases {
		exercise(t, c)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(richMessage())
	f.Add(aQuery(1))
	f.Add(aResponse(1, 300))
	f.Add([]byte("не DNS"))
	f.Fuzz(func(t *testing.T, raw []byte) { exercise(t, raw) })
}
