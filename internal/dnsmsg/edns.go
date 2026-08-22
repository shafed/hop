package dnsmsg

import (
	"encoding/binary"
	"fmt"
)

// OPT — псевдозапись EDNS0 из секции ADDITIONAL. Поля класса и TTL в ней
// значат другое, чем в обычной записи, поэтому названы отдельно, а не читаются
// из RR на месте вызова.
type OPT struct {
	RR
	UDPSize uint16 // объявленный размер буфера, лежит в поле CLASS
	DO      bool   // клиент просит DNSSEC; проходит насквозь (Р26, D50)
}

// Option — опция внутри RDATA псевдозаписи OPT: код и границы. Границы, а не
// значение: ECS вырезается копированием соседних срезов, содержимое опции нам
// не нужно ни разу.
type Option struct {
	Code     uint16
	Start    int // первый байт тройки (код)
	End      int // первый байт после значения
	ValStart int
	ValEnd   int
}

// EDNS находит псевдозапись OPT в ADDITIONAL. ok=false — EDNS0 в сообщении
// нет, что для запроса означает буфер 512 (RFC 6891 §6.2.3).
//
// Обход прекращается на найденной OPT: хвост сообщения после неё в этот момент
// не проверяется. Целостность хвоста — забота Facts, который читает сообщение
// до конца.
func (m Msg) EDNS() (OPT, bool, error) {
	s := m.Scan()
	for s.Next() {
		rr := s.RR()
		if rr.Section != SectionAdditional || rr.Type != TypeOPT {
			continue
		}
		return OPT{RR: rr, UDPSize: rr.Class, DO: rr.TTL&optDOBit != 0}, true, nil
	}
	return OPT{}, false, s.Err()
}

// BufferSize — сколько байт ответа клиент готов принять по UDP: объявленное в
// OPT либо 512 (D34, D35).
//
// Объявленное меньше 512 поднимается до 512: RFC 6891 §6.2.3 велит трактовать
// такое значение как 512, а буквальное соблюдение дало бы потолок, в который
// не влезает даже заголовок с вопросом.
func (m Msg) BufferSize() (int, error) {
	opt, ok, err := m.EDNS()
	if err != nil {
		return 0, err
	}
	if !ok || int(opt.UDPSize) < MinUDPSize {
		return MinUDPSize, nil
	}
	return int(opt.UDPSize), nil
}

// Options разбирает список опций внутри RDATA псевдозаписи. Пустой список —
// нормальный случай: OPT без опций объявляет только размер буфера и DO.
//
// OPT принимается аргументом, а не берётся из m, чтобы не искать её второй
// раз, — и потому границы приходится сверять с буфером. Из сети такая путаница
// недостижима (нужны два разных сообщения), но сигнатура к ней располагает:
// OPT, разобранная из длинного ответа апстрима и применённая к короткому
// запросу клиента, читала бы за концом среза. Обещание пакета — ошибка на
// любом входе, а не паника на неверном вызове.
func (m Msg) Options(opt OPT) ([]Option, error) {
	if opt.RDStart < HeaderLen || opt.RDStart > opt.RDEnd || opt.RDEnd > len(m.Raw) {
		return nil, fmt.Errorf("%w: границы OPT %d..%d не из этого сообщения (%d байт)",
			ErrOption, opt.RDStart, opt.RDEnd, len(m.Raw))
	}
	var out []Option
	for off := opt.RDStart; off < opt.RDEnd; {
		if off+4 > opt.RDEnd {
			return nil, fmt.Errorf("%w: обрубленный заголовок опции", ErrOption)
		}
		code := binary.BigEndian.Uint16(m.Raw[off : off+2])
		l := int(binary.BigEndian.Uint16(m.Raw[off+2 : off+4]))
		if off+4+l > opt.RDEnd {
			return nil, fmt.Errorf("%w: код %d, длина %d, осталось %d", ErrOption, code, l, opt.RDEnd-off-4)
		}
		out = append(out, Option{
			Code:     code,
			Start:    off,
			End:      off + 4 + l,
			ValStart: off + 4,
			ValEnd:   off + 4 + l,
		})
		off += 4 + l
	}
	return out, nil
}

// StripECS — копия сообщения без опции EDNS Client Subnet, с поправленными
// RDLENGTH псевдозаписи (Р26, D49). changed=false — вырезать было нечего, и
// копия не делалась: запрос уходит наверх как есть.
//
// Требует, чтобы OPT была последней записью сообщения, и отказывается работать
// иначе. Причина: вырез сдвигает всё, что лежит дальше, а сжатые имена в
// сдвинутых записях указывают абсолютным смещением и станут неверны. В запросе
// клиента после OPT записей не бывает; отказ здесь означает SERVFAIL на
// экзотику, а не утечку ECS наверх, и из двух исходов верен этот.
func StripECS(m Msg) (out []byte, changed bool, err error) {
	opt, ok, err := m.EDNS()
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}
	opts, err := m.Options(opt)
	if err != nil {
		return nil, false, err
	}
	cut := 0
	for _, o := range opts {
		if o.Code == OptionECS {
			cut += o.End - o.Start
		}
	}
	if cut == 0 {
		return nil, false, nil
	}
	if opt.End != len(m.Raw) {
		return nil, false, fmt.Errorf("%w: за ней ещё %d байт", ErrOptNotLast, len(m.Raw)-opt.End)
	}

	// Всё, кроме самих опций ECS, переезжает байт в байт.
	out = make([]byte, 0, len(m.Raw)-cut)
	out = append(out, m.Raw[:opt.RDStart]...)
	kept := opt.RDStart
	for _, o := range opts {
		if o.Code != OptionECS {
			continue
		}
		out = append(out, m.Raw[kept:o.Start]...)
		kept = o.End
	}
	out = append(out, m.Raw[kept:]...)
	binary.BigEndian.PutUint16(out[opt.RDStart-2:opt.RDStart], uint16(opt.RDLength()-cut))
	return out, true, nil
}
