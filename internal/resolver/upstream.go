package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/shafed/hop/internal/dnsmsg"
	"github.com/shafed/hop/internal/policy"
)

// Путь наверх: два апстрима, второй с форой, таймаут попытки, повтор по TCP
// на флаг TC и усечение ответа к клиенту (D1, D14, D15, D33–D37, D40–D44).
//
// Файл держится на одном обещании: ни сокет, ни горутина не переживают вызов
// ask. Молчащий апстрим — штатное состояние сети, а не экзотика (D40, D44), и
// копятся ресурсы именно на нём: попытку, брошенную без ожидания её конца,
// видно не в тесте, а в NAT-таблице через сутки работы. Цена обещания —
// выигравшая попытка ждёт, пока проигравшие закроют свои сокеты; ждёт она
// отмену контекста, то есть время закрытия сокета, а не время ответа.

var (
	// errAttemptTimeout — попытка не уложилась в AttemptTimeout (D14).
	errAttemptTimeout = errors.New("resolver: апстрим не ответил за таймаут попытки")
	// errBadAnswer — апстрим ответил не тем, что можно отдать клиенту: битый
	// заголовок, лишние байты, чужой вопрос, оборванный кадр TCP (D15, D37).
	errBadAnswer = errors.New("resolver: ответ апстрима непригоден")
	// errNoDialer — на выбранном фазой пути наверх нет диалера. Это дефект
	// связки, а не сети, и потому отдельная ошибка: SERVFAIL из-за пустого
	// поля конфига неотличим от SERVFAIL из-за молчащего апстрима, а причины
	// у них разные.
	errNoDialer = errors.New("resolver: путь наверх без диалера")
)

// attemptResult — чем кончилась одна попытка. Пара «ответ или ошибка» ходит
// по каналу, поэтому она тип, а не два значения.
type attemptResult struct {
	msg dnsmsg.Msg
	err error
}

// ask спрашивает апстримы и возвращает ответ, годный для кэша и для клиента.
//
// Первый апстрим спрашивается сразу; если за HeadStart модельного времени
// ответа нет — спрашивается второй, и дальше ждут оба (D41, D42). Клиенту
// уходит первый доехавший (D43). Фора, а не гонка с первой миллисекунды:
// гонка удваивает трафик наверх на каждом промахе кэша, а §5.7 отводит
// второму апстриму роль замены, а не дублёра.
//
// Наш идентификатор запроса собирает upstreamQuery (Р23): клиентский наверх
// не уходит, иначе локальный процесс задаёт идентификаторы наших исходящих
// запросов. Оба апстрима и повтор по TCP получают один и тот же байтовый
// запрос — один вопрос, один идентификатор, одна пара сравнений на приёме.
func (r *Resolver) ask(ctx context.Context, q dnsmsg.Msg, rt route) (dnsmsg.Msg, error) {
	id := r.queryID()
	wire, err := r.upstreamQuery(q, id)
	if err != nil {
		return dnsmsg.Msg{}, err
	}

	n := len(r.cfg.Upstreams)
	if !policy.DNSUpstream.On() {
		// Флаг выключен — остаётся один апстрим, и блокировка единственного
		// означает мёртвый DNS при живом узле. Ровно то поведение, на котором
		// negcheck обязан увидеть красными D41 и D42.
		n = 1
	}

	ctx, cancel := context.WithCancel(ctx)
	// Порядок defer'ов обратный порядку записи: сначала cancel, потом Wait.
	// Так ask не возвращается, пока жива хоть одна попытка, а каждая попытка
	// закрывает свой сокет своим defer'ом — это и есть D40 и D44, только
	// сформулированные в коде, а не в тесте.
	var attempts sync.WaitGroup
	defer attempts.Wait()
	defer cancel()

	// Буфер на все попытки: проигравшая обязана отдать результат и уйти, а не
	// ждать читателя, которого уже нет.
	results := make(chan attemptResult, n)

	var (
		next    int              // следующий неспрошенный апстрим
		pending int              // выпущенных и ещё не ответивших
		head    <-chan time.Time // фора следующему; nil, если следующего нет
		lastErr error
	)
	launch := func() {
		idx := next
		next++
		pending++
		attempts.Add(1)
		go func() {
			defer attempts.Done()
			results <- r.attempt(ctx, idx, q, wire, id, rt)
		}()
		head = nil
		if next < n {
			head = r.clk.After(r.cfg.HeadStart)
		}
	}

	launch()
	for pending > 0 {
		select {
		case <-head:
			launch()
		case res := <-results:
			pending--
			if res.err == nil {
				return res.msg, nil
			}
			lastErr = res.err
			if next < n {
				// Фора существует, чтобы не удваивать нагрузку наверх на
				// ожидании. Ждать её после отказа не за чем: ожидания больше
				// нет, есть отказ.
				launch()
			}
		case <-ctx.Done():
			// Бюджет клиента (5 с) либо закрытие резолвера. Отдельная ветка,
			// а не таймаут попытки: попыток может быть две, а бюджет один.
			return dnsmsg.Msg{}, ctx.Err()
		}
	}
	return dnsmsg.Msg{}, lastErr
}

// attempt — один апстрим целиком: датаграмма и, если он ответил с флагом TC,
// повтор того же вопроса по TCP (D33).
//
// Повтор живёт внутри попытки, а не снаружи: «получить у этого апстрима
// полный ответ» — одно обязательство, и разделив его надвое, мы получили бы
// ветку, в которой усечённый ответ уже победил гонку, а полного ещё нет.
func (r *Resolver) attempt(ctx context.Context, idx int, q dnsmsg.Msg, wire []byte, id uint16, rt route) attemptResult {
	m, err := r.askUDP(ctx, idx, q, wire, id, rt)
	if err != nil {
		return attemptResult{err: err}
	}
	if !m.Header.Truncated() {
		return attemptResult{msg: m}
	}
	if !policy.DNSTCPRetry.On() {
		// Флаг выключен — усечённое уходит клиенту как есть: большие RRset
		// молча теряют записи, и приложение видит часть адресов вместо всех.
		// На этом поведении negcheck обязан увидеть красным D33.
		return attemptResult{msg: m}
	}

	full, err := r.askTCP(ctx, idx, q, wire, id, rt)
	if err != nil {
		// Откатиться на усечённый ответ нельзя (D37): он неполон по
		// определению, а клиент, получивший его без TC, примет обрезок за
		// весь RRset. Отказ здесь честнее — клиент придёт снова.
		return attemptResult{err: err}
	}
	return attemptResult{msg: full}
}

// askUDP — одна попытка по UDP: датаграмма целиком, без префикса длины.
//
// Таймаут строится на clk.After и закрытии сокета, а не на SetReadDeadline:
// дедлайн сокета — настоящее время (§8.1), и проверка таймаута в две секунды
// стоила бы двух секунд. Цена — читающая горутина на попытку; она уходит
// вместе с сокетом, и ask ждёт её ухода.
func (r *Resolver) askUDP(ctx context.Context, idx int, q dnsmsg.Msg, wire []byte, id uint16, rt route) (dnsmsg.Msg, error) {
	dst := r.cfg.Upstreams[idx]
	conn, err := r.dialDatagram(ctx, dst, rt)
	if err != nil {
		return dnsmsg.Msg{}, fmt.Errorf("апстрим %s: %w", dst, err)
	}

	// Порядок defer'ов обратный порядку записи: Close раньше Wait. Читатель
	// висит в Read и уходит только после закрытия сокета — Wait перед Close
	// был бы взаимной блокировкой.
	var reader sync.WaitGroup
	defer reader.Wait()
	defer conn.Close()

	if _, err := conn.Write(wire); err != nil {
		return dnsmsg.Msg{}, fmt.Errorf("апстрим %s: %w", dst, err)
	}
	r.countUpstream(idx, rt)

	answers := make(chan attemptResult, 1)
	reader.Add(1)
	go func() {
		defer reader.Done()
		// Буфер по объявленному апстриму размеру: больше он прислать не
		// вправе, а меньший буфер молча резал бы датаграмму на приёме.
		buf := make([]byte, UpstreamEDNS)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				answers <- attemptResult{err: err}
				return
			}
			m, mine, err := accept(buf[:n], id, q)
			if !mine {
				// Чужой идентификатор — не наш ответ: ждём дальше, пока не
				// кончится таймаут. Ответ на прошлый запрос с того же адреса
				// и подсунутая датаграмма выглядят одинаково, и оба не повод
				// объявить попытку неудавшейся.
				continue
			}
			answers <- attemptResult{msg: m, err: err}
			return
		}
	}()

	select {
	case res := <-answers:
		return res.msg, res.err
	case <-r.clk.After(AttemptTimeout):
		return dnsmsg.Msg{}, fmt.Errorf("%w: %s", errAttemptTimeout, dst)
	case <-ctx.Done():
		return dnsmsg.Msg{}, ctx.Err()
	}
}

// askTCP — повтор того же вопроса потоком (RFC 1035 §4.2.2: двухбайтовый
// префикс длины на запросе и на ответе).
//
// Соединение на один вопрос: клиентские соединения переиспользуются (D5, D6),
// наши наверх — нет. Пул наверх стоил бы учёта простоя и разбора чужих
// ответов не по порядку ради одного повтора на большой RRset.
func (r *Resolver) askTCP(ctx context.Context, idx int, q dnsmsg.Msg, wire []byte, id uint16, rt route) (dnsmsg.Msg, error) {
	dst := r.cfg.Upstreams[idx]
	if len(wire) > StreamMax {
		return dnsmsg.Msg{}, fmt.Errorf("%w: запрос %d байт при потолке %d", errBadAnswer, len(wire), StreamMax)
	}

	conn, err := r.dialStream(ctx, dst, rt)
	if err != nil {
		return dnsmsg.Msg{}, fmt.Errorf("апстрим %s: %w", dst, err)
	}

	var reader sync.WaitGroup
	defer reader.Wait()
	defer conn.Close()

	// Префикс и тело одной записью: два Write — два сегмента в сети и два
	// кадра для того, кто читает по границам записей.
	framed := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(wire)))
	copy(framed[2:], wire)
	if _, err := conn.Write(framed); err != nil {
		return dnsmsg.Msg{}, fmt.Errorf("апстрим %s: %w", dst, err)
	}
	r.countUpstream(idx, rt)
	r.cnt.tcpRetry.Add(1)

	answers := make(chan attemptResult, 1)
	reader.Add(1)
	go func() {
		defer reader.Done()
		answers <- readStream(conn, id, q)
	}()

	select {
	case res := <-answers:
		return res.msg, res.err
	case <-r.clk.After(AttemptTimeout):
		return dnsmsg.Msg{}, fmt.Errorf("%w: %s (TCP)", errAttemptTimeout, dst)
	case <-ctx.Done():
		return dnsmsg.Msg{}, ctx.Err()
	}
}

// readStream читает один кадр RFC 1035 §4.2.2.
//
// Префикс, обещавший больше, чем пришло, — отказ, а не «отдадим сколько
// есть» (D37): частичное сообщение выглядит корректным до попытки его
// разобрать, и клиент получил бы мусор вместо указания прийти ещё раз.
func readStream(conn net.Conn, id uint16, q dnsmsg.Msg) attemptResult {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return attemptResult{err: fmt.Errorf("%w: префикс длины: %w", errBadAnswer, err)}
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return attemptResult{err: fmt.Errorf("%w: префикс обещал %d байт: %w", errBadAnswer, len(body), err)}
	}

	m, mine, err := accept(body, id, q)
	if err != nil {
		return attemptResult{err: err}
	}
	if !mine {
		// В отличие от UDP: соединение мы открыли под один свой вопрос, и
		// чужой идентификатор в нём означает сломанный апстрим, а не чужую
		// датаграмму, залетевшую на общий сокет.
		return attemptResult{err: fmt.Errorf("%w: чужой идентификатор в потоке", errBadAnswer)}
	}
	return attemptResult{msg: m}
}

// accept — разбор ответа апстрима до того, как он станет ответом клиенту.
//
// mine=false означает «это не наш ответ, ждём дальше»; ошибка означает
// «апстрим ответил мусором» и уезжает клиенту как SERVFAIL (D15). Разделение
// нужно, потому что стоит по-разному: пропущенная чужая датаграмма стоит
// ожидания, принятая — подменённого ответа.
//
// Проверок четыре, и каждая закрывает свою дыру: идентификатор (Р23 — наверх
// ушёл наш, и только на него мы отвечаем), флаг QR (запрос на нашем сокете —
// не ответ), вопрос (апстрим, ответивший про другое имя, сломал бы сборку
// ответа клиенту, которая берёт вопрос у клиента, а секции у него) и целость
// секций (счётчики заголовка и содержимое разошлись — D15).
func accept(raw []byte, id uint16, q dnsmsg.Msg) (m dnsmsg.Msg, mine bool, err error) {
	if len(raw) < dnsmsg.HeaderLen {
		// Идентификатор прочитать не из чего, значит и пропустить датаграмму
		// как чужую нельзя: это мусор, а не чужой ответ.
		return dnsmsg.Msg{}, true, fmt.Errorf("%w: %d байт при заголовке %d", errBadAnswer, len(raw), dnsmsg.HeaderLen)
	}
	if binary.BigEndian.Uint16(raw[:2]) != id {
		return dnsmsg.Msg{}, false, nil
	}

	m, err = dnsmsg.Parse(raw)
	if err != nil {
		return dnsmsg.Msg{}, true, fmt.Errorf("%w: %w", errBadAnswer, err)
	}
	if !m.Header.Response() {
		return dnsmsg.Msg{}, true, fmt.Errorf("%w: QR не поднят", errBadAnswer)
	}
	if !sameQuestion(m, q) {
		return dnsmsg.Msg{}, true, fmt.Errorf("%w: ответ на чужой вопрос", errBadAnswer)
	}
	if err := checkSections(m); err != nil {
		return dnsmsg.Msg{}, true, fmt.Errorf("%w: %w", errBadAnswer, err)
	}
	return m, true, nil
}

// sameQuestion — тот же вопрос без учёта регистра имени.
//
// Без учёта регистра, потому что наверх уходит написание клиента, а апстрим
// вправе отразить его как угодно; с учётом длины — она у EqualFold совпадает
// по построению, и на этом держится сборка ответа клиенту (dnsmsg.ReplyTo).
func sameQuestion(answer, q dnsmsg.Msg) bool {
	return answer.Question.Type == q.Question.Type &&
		answer.Question.Class == q.Question.Class &&
		answer.Question.Name.EqualFold(q.Question.Name)
}

// checkSections проходит все записи ответа, ничего из них не беря.
//
// Нужен ровно затем, чтобы мусор из сети не доехал до клиента и до кэша
// (D15): Parse смотрит заголовок и вопрос, а разошедшиеся счётчики и
// оборванный RDATA видно только обходом.
func checkSections(m dnsmsg.Msg) error {
	s := m.Scan()
	for s.Next() {
	}
	return s.Err()
}

// countUpstream — запрос ушёл наверх.
//
// Два счётчика, потому что вопроса два и они ортогональны: Upstream[i] — кого
// спросили (D41: второй не спрошен вовсе), UpstreamDirect — каким путём
// (D52: мимо туннеля). Повтор по TCP считается обоими: это тоже запрос
// наверх к тому же апстриму, и отдельно его считает TCPRetry.
func (r *Resolver) countUpstream(idx int, rt route) {
	r.cnt.upstream[idx].Add(1)
	if rt == routeDirect {
		r.cnt.upstreamDirect.Add(1)
	}
}

// datagram — датаграммный сокет наверх, каким его видит попытка.
//
// Пути наверх два и интерфейсы у них разные: через узел — net.PacketConn
// (Config.DialUDP), мимо туннеля — net.Conn на "udp" (Config.DialDirect).
// Сводятся они здесь, а не двумя копиями цикла чтения: копия — это второе
// место, где забудут закрыть сокет.
type datagram interface {
	Write(p []byte) (int, error)
	Read(p []byte) (int, error)
	Close() error
}

// datagramTo — net.PacketConn в роли datagram: адрес назначения известен на
// весь срок жизни сокета, поэтому он в поле, а не в аргументе.
type datagramTo struct {
	net.PacketConn
	dst net.Addr
}

func (c datagramTo) Write(p []byte) (int, error) { return c.WriteTo(p, c.dst) }

// Read отбрасывает адрес отправителя: ответ принимается по совпадению
// идентификатора (Р23, accept), а не по адресу — сокет через узел приходит от
// движка, и чей адрес он назовёт источником, зависит от движка.
func (c datagramTo) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (r *Resolver) dialDatagram(ctx context.Context, dst netip.AddrPort, rt route) (datagram, error) {
	if rt == routeDirect {
		if r.cfg.DialDirect == nil {
			return nil, fmt.Errorf("%w: bypass без DialDirect", errNoDialer)
		}
		return r.cfg.DialDirect(ctx, "udp", dst)
	}
	if r.cfg.DialUDP == nil {
		return nil, fmt.Errorf("%w: путь через узел без DialUDP", errNoDialer)
	}
	pc, err := r.cfg.DialUDP(ctx, dst)
	if err != nil {
		return nil, err
	}
	return datagramTo{PacketConn: pc, dst: net.UDPAddrFromAddrPort(dst)}, nil
}

func (r *Resolver) dialStream(ctx context.Context, dst netip.AddrPort, rt route) (net.Conn, error) {
	if rt == routeDirect {
		if r.cfg.DialDirect == nil {
			return nil, fmt.Errorf("%w: bypass без DialDirect", errNoDialer)
		}
		return r.cfg.DialDirect(ctx, "tcp", dst)
	}
	if r.cfg.Dial == nil {
		return nil, fmt.Errorf("%w: путь через узел без Dial", errNoDialer)
	}
	return r.cfg.Dial(ctx, dst)
}

// fit — ответ клиенту: его идентификатор, его секция вопроса и потолок его
// буфера.
//
// Клиент по TCP получает сообщение целиком; клиент по UDP — не больше
// объявленного им буфера EDNS0, а не влезло — заголовок с вопросом и поднятым
// TC, а не обрезанные байты RRset (D34). Ошибка здесь тихая: без TC
// приложение получает мусор вместо указания прийти по TCP.
func (r *Resolver) fit(q dnsmsg.Msg, answer dnsmsg.Msg, tr Transport) ([]byte, error) {
	reply, err := dnsmsg.ReplyTo(q, answer)
	if err != nil {
		return nil, err
	}
	fitted, truncated, err := dnsmsg.Fit(reply, r.clientLimit(q, tr))
	if err != nil {
		return nil, err
	}
	if truncated {
		r.cnt.truncToClient.Add(1)
	}
	return fitted, nil
}

// clientLimit — сколько байт готов принять этот клиент.
//
// По TCP — весь потолок сообщения (RFC 1035 §4.2.2), по UDP — объявленный
// клиентом буфер EDNS0, а без EDNS0 — 512 (RFC 6891). Объявленный буфер
// меньше 512 потолка не понижает: RFC 6891 §6.2.3 велит считать такое
// значение равным 512, а не верить ему.
//
// Ошибку разбора EDNS0 в клиентском запросе глотаем осознанно: Parse смотрит
// заголовок и вопрос, и до сюда доезжает запрос со сломанной секцией
// ADDITIONAL. Отказ клиенту из-за неё был бы отказом на вопрос, который
// разобран целиком; 512 байт — консервативный ответ на «сколько ты готов
// принять», потому что столько обязан принять всякий (D34).
func (r *Resolver) clientLimit(q dnsmsg.Msg, tr Transport) int {
	if tr == TransportTCP {
		return StreamMax
	}
	limit := ClientUDPDefault
	if n, err := q.BufferSize(); err == nil && n > limit {
		limit = n
	}
	return limit
}

// fitRaw — то же для ответа, который резолвер собрал сам (отказ, синтез AAAA).
// Разбор собственной сборки стоит одного прохода по заголовку и вопросу и
// держит один путь усечения на все ответы, а не два.
func (r *Resolver) fitRaw(q dnsmsg.Msg, raw []byte, tr Transport) ([]byte, error) {
	m, err := dnsmsg.Parse(raw)
	if err != nil {
		return nil, err
	}
	return r.fit(q, m, tr)
}
