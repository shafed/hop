// Самотесты fault injector'а (PLAN.md, этап 4: «каждый режим даёт ожидаемое
// наблюдаемое»). Стенд §8.3 доказывает поведение агента только в той мере, в
// какой сам умеет ломать канал, поэтому здесь проверяется не код инжектора, а
// то, что каждый режим §8.1 отличим от остальных снаружи, со стороны сокета.
//
// Настоящее время в этом файле неизбежно и помечено построчно: проверяемое —
// поведение ядра на реальных сокетах, фейковым часам оно не подчиняется.
package faultinject

import (
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time" //hop:realtime
)

// dialTimeout — потолок на любое ожидание «оно должно случиться». Щедрый:
// тест, который его выбрал, уже упал, и точность потолка ничего не меняет.
const dialTimeout = 2 * time.Second

// silence — сколько ждём молчания, прежде чем признать чёрную дыру чёрной
// дырой. Тест на молчание ждёт полный срок по построению, поэтому срок
// короткий: весь пакет обязан укладываться в секунды.
const silence = 300 * time.Millisecond

// slowDelay — задержка режима slow. Заметно больше планировщика и заметно
// меньше silence, чтобы «медленно» не путалось ни с шумом, ни с зависанием.
const slowDelay = 120 * time.Millisecond

// --- pass ---------------------------------------------------------------

// pass: байты доходят до upstream и возвращаются обратно.
func TestPassForwardsBothWays(t *testing.T) {
	up := newUpstream(t, echoOn)
	inj := newInjector(t, up)
	c := dial(t, inj)

	const msg = "рукопожатие"
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("запись клиента не прошла: %v", err)
	}
	if got := string(readN(t, c, len(msg))); got != msg {
		t.Errorf("вернулось %q, ожидалось %q", got, msg)
	}
	if n := up.conns(); n != 1 {
		t.Errorf("upstream принял %d соединений, ожидалось 1", n)
	}
	if n := inj.Conns(); n != 1 {
		t.Errorf("инжектор насчитал %d соединений, ожидалось 1", n)
	}
}

// --- rst ----------------------------------------------------------------

// rst: клиент видит обрыв, а не штатное закрытие и не таймаут; узла попытка не
// касается.
func TestRSTBreaksConnectionAndSparesUpstream(t *testing.T) {
	up := newUpstream(t, echoOn)
	inj := newInjector(t, up)
	inj.SetMode(ModeRST)

	// Подключение здесь своё, а не через dial(): на loopback RST успевает
	// прийти раньше, чем connect() вернётся в пользовательский код, и тогда
	// отказ виден уже на нём. Это тот же наблюдаемый RST, только замеченный
	// раньше, — считать его ошибкой стенда нельзя, иначе тест флакает.
	// Штатное закрытие так проявиться не может: FIN connect() не ломает.
	c, err := net.DialTimeout("tcp", inj.Addr(), dialTimeout)
	if err == nil {
		t.Cleanup(func() { _ = c.Close() })
		// Клиент нарочно ничего не пишет. Стоит ему что-нибудь послать — и ядро
		// на той стороне ответит RST на данные в уже закрытый сокет, каким бы
		// способом тот ни закрывали; тест начал бы проходить и без SO_LINGER,
		// то есть перестал бы отличать «немедленный RST» от штатного FIN.
		// Молчащий клиент разницу видит: обычное закрытие дало бы ему EOF.
		_, err = readByte(t, c, dialTimeout)
	}
	assertBroken(t, err)

	if n := up.conns(); n != 0 {
		t.Errorf("upstream принял %d соединений, а снятый сервер не принимает ничего", n)
	}
}

// --- blackhole ----------------------------------------------------------

// blackhole: за отведённый срок ни байта и никакого закрытия, upstream не
// тронут вовсе. Именно этим blackhole отличается от rst: §8.1 держит их
// разными режимами, потому что RST маскирует отсутствие таймаута в агенте, а
// чёрная дыра — нет.
func TestBlackholeHangsSilentlyAndSparesUpstream(t *testing.T) {
	up := newUpstream(t, echoOn)
	inj := newInjector(t, up)
	inj.SetMode(ModeBlackhole)
	c := dial(t, inj)

	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("запись клиента не прошла, а чёрная дыра обязана принимать: %v", err)
	}
	n, err := readByte(t, c, silence)
	if n != 0 {
		t.Fatalf("за %v пришло %d байт, чёрная дыра обязана молчать", silence, n)
	}
	assertHung(t, err)

	if n := up.conns(); n != 0 {
		t.Errorf("upstream принял %d соединений, а blackhole не должен его трогать", n)
	}
	if n := inj.Conns(); n != 1 {
		t.Errorf("инжектор насчитал %d соединений, ожидалось 1: соединение принимается, но не обслуживается", n)
	}
}

// --- slow ---------------------------------------------------------------

// slow(d): ответ доходит, но не раньше чем через d.
func TestSlowDelaysEveryWrite(t *testing.T) {
	up := newUpstream(t, echoOn)
	inj := newInjector(t, up)
	inj.SetSlow(slowDelay)
	inj.SetMode(ModeSlow)
	c := dial(t, inj)

	start := time.Now() //hop:realtime — замер задержки канала, часы стенда здесь не при чём
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("запись клиента не прошла: %v", err)
	}
	got := readN(t, c, 4)
	elapsed := time.Since(start) //hop:realtime — тот же замер

	if string(got) != "ping" {
		t.Errorf("вернулось %q, ожидалось \"ping\": slow задерживает, но не портит", got)
	}
	// Нижняя граница, не окно: задержек на круге две (в обе стороны), а
	// верхнюю границу задаёт планировщик — на неё тест опираться не вправе.
	if elapsed < slowDelay {
		t.Errorf("ответ вернулся за %v, то есть быстрее заданных %v — задержка не применена", elapsed, slowDelay)
	}
}

// --- cut-after-handshake ------------------------------------------------

// cut-after-handshake(n): до upstream доходит ровно n байт от клиента, после
// чего рвётся и клиентская сторона.
func TestCutAfterHandshakeForwardsExactlyN(t *testing.T) {
	const n = 4

	// Эхо выключено: иначе непонятно, чем кончилось чтение клиента — обрывом
	// или гонкой между обрывом и ответом узла.
	up := newUpstream(t, echoOff)
	inj := newInjector(t, up)
	inj.SetCutAfter(n)
	inj.SetMode(ModeCutAfterHandshake)
	c := dial(t, inj)

	if _, err := c.Write([]byte("0123456789")); err != nil {
		t.Fatalf("запись клиента не прошла: %v", err)
	}

	uc := up.waitConn(t)
	uc.waitClosed(t)
	if got := uc.bytes(); len(got) != n {
		t.Errorf("upstream получил %d байт (%q), ожидалось ровно %d", len(got), got, n)
	}

	_, err := readByte(t, c, dialTimeout)
	assertClosed(t, err)
}

// --- смена режима на живом соединении -----------------------------------

// Режим переключается на лету: соединение, установленное в pass, обязано
// замолчать при переходе в blackhole и не закрыться. Без этого нечем проверить
// §8.3 T9, где узел уходит в чёрную дыру посреди долгого соединения.
func TestModeChangeReachesLiveConnection(t *testing.T) {
	up := newUpstream(t, echoOn)
	inj := newInjector(t, up)
	c := dial(t, inj)

	if _, err := c.Write([]byte("a")); err != nil {
		t.Fatalf("запись клиента не прошла: %v", err)
	}
	if got := string(readN(t, c, 1)); got != "a" {
		t.Fatalf("в режиме pass вернулось %q, ожидалось \"a\"", got)
	}

	inj.SetMode(ModeBlackhole)
	if _, err := c.Write([]byte("b")); err != nil {
		t.Fatalf("запись после смены режима не прошла: %v", err)
	}
	n, err := readByte(t, c, silence)
	if n != 0 {
		t.Fatalf("за %v пришло %d байт, а соединение уже в чёрной дыре", silence, n)
	}
	assertHung(t, err)
}

// Смена режима доходит и до молчащего соединения: по нему ничего не идёт, узел
// уходит в rst — клиент обязан узнать об этом сам, а не со своей следующей
// записи. Это и есть причина, по которой перекачка сверяется с режимом по
// дедлайну, а не только вместе с байтами (§8.3 T11: отказ обнаруживается за
// отведённый срок, а не когда приложению вздумается что-то послать).
func TestModeChangeBreaksIdleConnection(t *testing.T) {
	up := newUpstream(t, echoOn)
	inj := newInjector(t, up)
	c := dial(t, inj)

	if _, err := c.Write([]byte("a")); err != nil {
		t.Fatalf("запись клиента не прошла: %v", err)
	}
	if got := string(readN(t, c, 1)); got != "a" {
		t.Fatalf("в режиме pass вернулось %q, ожидалось \"a\"", got)
	}

	inj.SetMode(ModeRST)
	_, err := readByte(t, c, dialTimeout)
	assertBroken(t, err)
}

// --- утверждения --------------------------------------------------------

// assertBroken требует, чтобы соединение оборвалось ошибкой, а не закрылось
// штатно и не подвисло.
//
// Проверка нарочно двухступенчатая. ECONNRESET — то, что даёт Linux, и это
// основной путь; но macOS на записи в сброшенный сокет отдаёт EPIPE, а Windows
// — WSAECONNRESET, который к syscall.ECONNRESET не всегда сводится. Привязка
// теста к одному errno сделала бы его платформенным, а §8.3 требует «на всех
// трёх ОС». Поэтому решает более слабое и кроссплатформенное свойство: ошибка
// есть, и это не EOF (штатное закрытие) и не таймаут (зависание).
func assertBroken(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("соединение живо, а режим rst обязан его оборвать")
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("пришёл EOF: соединение закрыто штатно (FIN), а rst обязан дать RST")
	}
	if isTimeout(err) {
		t.Fatalf("таймаут вместо обрыва (%v): так ведёт себя blackhole, а не rst", err)
	}
}

// assertClosed требует, чтобы соединение кончилось не по воле клиента: EOF или
// сброс. Слабее assertBroken — режим cut рвёт через FIN намеренно (см.
// deliver), и требовать здесь именно RST значило бы требовать потери уже
// доставленных байт.
func assertClosed(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("соединение живо, а обрыв после n байт обязан наступить")
	}
	if isTimeout(err) {
		t.Fatalf("таймаут вместо обрыва (%v): соединение висит, а должно было кончиться", err)
	}
}

// assertHung требует обратного: соединение висит. Таймаут чтения — не помеха
// тесту, а его результат.
func assertHung(t *testing.T, err error) {
	t.Helper()
	if !isTimeout(err) {
		t.Fatalf("чтение кончилось не таймаутом (%v), а соединение обязано висеть: "+
			"иначе агент упрётся в обрыв и таймаут §8.3 T11 останется непроверенным", err)
	}
}

// --- стенд --------------------------------------------------------------

const (
	echoOn  = true
	echoOff = false
)

// upstream — то, что стоит за прослойкой. В настоящем стенде §8.1 это
// VLESS-инбаунд Xray; здесь достаточно эха, потому что проверяется прослойка,
// а не узел.
type upstream struct {
	ln       net.Listener
	echo     bool
	accepted chan *upConn

	mu    sync.Mutex
	count int
}

func newUpstream(t *testing.T, echo bool) *upstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream не поднялся: %v", err)
	}
	u := &upstream{ln: ln, echo: echo, accepted: make(chan *upConn, 8)}
	t.Cleanup(func() { _ = ln.Close() })
	go u.serve()
	return u
}

func (u *upstream) serve() {
	for {
		c, err := u.ln.Accept()
		if err != nil {
			return
		}
		uc := &upConn{done: make(chan struct{})}
		u.mu.Lock()
		u.count++
		u.mu.Unlock()
		select {
		case u.accepted <- uc:
		default: // тест столько соединений не разбирает — считать всё равно посчитали
		}
		go uc.run(c, u.echo)
	}
}

// conns — сколько подключений дошло до узла. Ноль здесь — самостоятельное
// утверждение: rst и blackhole обязаны узла не касаться.
func (u *upstream) conns() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.count
}

func (u *upstream) waitConn(t *testing.T) *upConn {
	t.Helper()
	select {
	case c := <-u.accepted:
		return c
	case <-time.After(dialTimeout): //hop:realtime — потолок ожидания на реальном сокете
		t.Fatalf("за %v до upstream не дошло ни одного соединения", dialTimeout)
		return nil
	}
}

// upConn — одно соединение, дошедшее до узла: что по нему пришло и закрылось
// ли оно.
type upConn struct {
	done chan struct{}

	mu  sync.Mutex
	got []byte
}

func (c *upConn) run(conn net.Conn, echo bool) {
	defer close(c.done)
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			c.mu.Lock()
			c.got = append(c.got, buf[:n]...)
			c.mu.Unlock()
			if echo {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (c *upConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.got...)
}

// waitClosed ждёт конца соединения: считать пришедшие байты имеет смысл только
// после него, иначе «ровно n» окажется гонкой с чтением.
func (c *upConn) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(dialTimeout): //hop:realtime — потолок ожидания на реальном сокете
		t.Fatalf("за %v upstream не увидел обрыва", dialTimeout)
	}
}

func newInjector(t *testing.T, up *upstream) *Injector {
	t.Helper()
	inj, err := New(up.ln.Addr().String())
	if err != nil {
		t.Fatalf("инжектор не поднялся: %v", err)
	}
	t.Cleanup(func() { _ = inj.Close() })
	return inj
}

func dial(t *testing.T, inj *Injector) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", inj.Addr(), dialTimeout)
	if err != nil {
		t.Fatalf("клиент не подключился к прослойке: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(dialTimeout)) //hop:realtime — дедлайн сокета
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("не дочитали %d байт: %v", n, err)
	}
	return buf
}

// readByte читает один байт с заданным потолком и возвращает результат как
// есть: здесь ошибка чтения — предмет проверки, а не повод падать.
func readByte(t *testing.T, c net.Conn, within time.Duration) (int, error) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(within)) //hop:realtime — дедлайн сокета
	var buf [1]byte
	return c.Read(buf[:])
}
