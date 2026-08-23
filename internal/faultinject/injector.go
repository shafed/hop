// Package faultinject — fault injector из SPEC.md §8.1: TCP-прослойка перед
// настоящим VLESS-инбаундом Xray, которая по команде превращает исправный
// канал в один из пяти видов отказа (`pass`, `rst`, `blackhole`, `slow`,
// `cut-after-handshake`).
//
// Зачем отдельный пакет и почему не мок. Отказ, который проверяет оракул §8.3,
// живёт не внутри агента, а в сети между агентом и узлом: RST, чёрная дыра,
// деградация латентности, обрыв после рукопожатия. Подменить его фейковым
// диалером нельзя — мок встанет ровно на то место, которое и проверяется
// («путь сквозной, моков между netstack и узлом нет», §8.3). Поэтому инжектор
// — настоящий слушатель на localhost, а не заглушка, и живёт отдельно от
// internal/fakenet, где собраны именно заглушки.
//
// Почему `rst` и `blackhole` — разные режимы, а не два имени одного: §8.1
// требует их разными тестами, потому что это разные пути в коде и «blackhole
// ловит отсутствие таймаута там, где RST его маскирует».
//
// Настоящее время здесь допустимо и помечено //hop:realtime построчно:
// задержка режима `slow` и дедлайны сокетов — свойство канала, а не логики
// продукта. Инъектируемые часы (§8.1, internal/clock) изображают окна и
// гистерезис агента; на другом конце сокета ядро, у которого фейковых часов
// нет, и подменять ему время нечем.
package faultinject

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time" //hop:realtime
)

// Mode — режим прослойки; значения повторяют таблицу §8.1 один в один.
type Mode int

const (
	// ModePass — прозрачный форвард в обе стороны: норма, на фоне которой
	// остальные режимы имеют смысл.
	ModePass Mode = iota
	// ModeRST — немедленный RST на принятом соединении: «сервер снят».
	ModeRST
	// ModeBlackhole — соединение принято, но не читается, не пишется и не
	// закрывается: «пакеты дропаются, соединение висит».
	ModeBlackhole
	// ModeSlow — как ModePass, но каждая запись задержана на SetSlow:
	// деградация латентности.
	ModeSlow
	// ModeCutAfterHandshake — форвардит первые SetCutAfter байт от клиента и
	// рвёт соединение: DPI-подобное поведение.
	ModeCutAfterHandshake
)

// String даёт те же имена, что в таблице §8.1, — тестам и логам стенда незачем
// расходиться со спекой в названиях.
func (m Mode) String() string {
	switch m {
	case ModePass:
		return "pass"
	case ModeRST:
		return "rst"
	case ModeBlackhole:
		return "blackhole"
	case ModeSlow:
		return "slow"
	case ModeCutAfterHandshake:
		return "cut-after-handshake"
	default:
		return fmt.Sprintf("mode(%d)", int(m))
	}
}

// pollInterval — как часто перекачка возвращается к проверке режима, пока
// данных нет.
//
// Возобновляемый дедлайн на чтении, а не сигнал в канал: смена режима обязана
// доходить до уже установленных соединений (§8.3 T9 — «долгое соединение через
// A, A → blackhole»), а сокет, висящий в Read, узнать о ней иначе не может.
const pollInterval = 20 * time.Millisecond

// bufSize — размер буфера одной перекачки. Совпадать с MTU не обязано: здесь
// байтовый поток, а не пакеты.
const bufSize = 32 * 1024

// Injector — прослойка между клиентом и upstream. Нулевое значение
// неработоспособно, создавать через New.
type Injector struct {
	upstream string
	ln       net.Listener

	mu       sync.Mutex
	mode     Mode
	slow     time.Duration
	cut      int
	changed  chan struct{}         // закрывается при любой смене настроек
	live     map[net.Conn]struct{} // открытое прямо сейчас — чтобы Close убрал за blackhole
	accepted int
	closed   bool

	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// New поднимает прослойку на 127.0.0.1 со свободным портом и начинает
// принимать соединения в режиме ModePass.
//
// Порт нулевой и адрес именно loopback: стенд §8.1 весь локальный, «без
// интернета», и слушать наружу ему незачем.
func New(upstream string) (*Injector, error) {
	if _, _, err := net.SplitHostPort(upstream); err != nil {
		return nil, fmt.Errorf("faultinject: upstream %q не вида host:port: %w", upstream, err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("faultinject: не удалось занять порт на localhost: %w", err)
	}
	i := &Injector{
		upstream: upstream,
		ln:       ln,
		changed:  make(chan struct{}),
		live:     make(map[net.Conn]struct{}),
		done:     make(chan struct{}),
	}
	i.wg.Add(1)
	go i.accept()
	return i, nil
}

// Addr — адрес, куда подключается клиент вместо upstream.
func (i *Injector) Addr() string { return i.ln.Addr().String() }

// SetMode переключает режим на лету.
//
// Смена доходит и до уже установленных соединений, а не только до новых: без
// этого нечем проверить §8.3 T9 и T10, где отказ наступает посреди долгого
// соединения, а не до его установки.
func (i *Injector) SetMode(m Mode) {
	i.mu.Lock()
	i.mode = m
	i.notifyLocked()
	i.mu.Unlock()
}

// Mode — текущий режим.
func (i *Injector) Mode() Mode {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.mode
}

// SetSlow задаёт задержку режима ModeSlow. Задержка применяется к каждой
// записи в обе стороны, поэтому клиент видит примерно 2d на круговом обмене —
// §8.1 говорит «задержка на каждой записи», а не «на соединении».
func (i *Injector) SetSlow(d time.Duration) {
	i.mu.Lock()
	i.slow = d
	i.notifyLocked()
	i.mu.Unlock()
}

// SetCutAfter задаёт, сколько байт от клиента пройдёт до обрыва в режиме
// ModeCutAfterHandshake. Считаются байты только в сторону upstream: «рвёт
// после TLS» в §8.1 — про размер клиентского ClientHello, ответ узла на него
// уже не влияет.
func (i *Injector) SetCutAfter(n int) {
	i.mu.Lock()
	i.cut = n
	i.notifyLocked()
	i.mu.Unlock()
}

// Conns — сколько соединений принято за всё время жизни прослойки.
//
// Именно принято, а не открыто сейчас: это счётчик наблюдаемого («узел увидел
// попытку»), и режимы, которые не доводят соединение до upstream, тоже в него
// попадают.
func (i *Injector) Conns() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.accepted
}

// Close закрывает слушатель и все висящие соединения и ждёт завершения
// обслуживающих горутин.
//
// Закрывать зависшее приходится явно: режим blackhole по определению не
// закрывает ничего сам, и без уборки стенд утечёт дескрипторами за прогон.
func (i *Injector) Close() error {
	i.closeOnce.Do(func() {
		close(i.done)
		_ = i.ln.Close()
		i.mu.Lock()
		i.closed = true
		for c := range i.live {
			_ = c.Close()
		}
		i.live = make(map[net.Conn]struct{})
		i.mu.Unlock()
	})
	i.wg.Wait()
	return nil
}

// notifyLocked будит всех, кто ждёт смены настроек. Канал закрывается и
// заводится заново — это широковещание без списка подписчиков и без риска
// разбудить не всех.
func (i *Injector) notifyLocked() {
	close(i.changed)
	i.changed = make(chan struct{})
}

// settings отдаёт снимок настроек и канал, который закроется при следующей их
// смене. Снимок целиком, а не по полю: иначе перекачка может увидеть новый
// режим со старой задержкой.
func (i *Injector) settings() (Mode, time.Duration, int, <-chan struct{}) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.mode, i.slow, i.cut, i.changed
}

func (i *Injector) accept() {
	defer i.wg.Done()
	for {
		c, err := i.ln.Accept()
		if err != nil {
			return // слушатель закрыт из Close — единственный штатный выход
		}
		i.mu.Lock()
		i.accepted++
		closed := i.closed
		if !closed {
			i.live[c] = struct{}{}
		}
		i.mu.Unlock()
		if closed {
			_ = c.Close()
			continue
		}
		i.wg.Add(1)
		go i.serve(c)
	}
}

// serve обслуживает одно принятое соединение.
func (i *Injector) serve(client net.Conn) {
	defer i.wg.Done()

	// Режим сверяется до подключения к upstream: blackhole обязан оставить
	// узел вообще нетронутым («принимает и молчит», §8.1), иначе тест не
	// отличит чёрную дыру от очень медленного узла — а §8.3 T11 требует
	// именно этого различия.
	for {
		mode, _, _, changed := i.settings()
		switch mode {
		case ModeRST:
			i.reset(client)
			return
		case ModeBlackhole:
			select {
			case <-changed: // режим сменили — соединение оживает и идёт к upstream
			case <-i.done:
				i.drop(client)
				return
			}
		default:
			i.forward(client)
			return
		}
	}
}

// forward открывает upstream и качает байты в обе стороны до первой ошибки.
func (i *Injector) forward(client net.Conn) {
	up, err := net.Dial("tcp", i.upstream)
	if err != nil {
		// Узла нет — самое честное, что можно показать клиенту, это RST:
		// прослойка не должна выглядеть живее, чем то, что за ней.
		i.reset(client)
		return
	}
	i.track(up)

	// Обрыв всегда двусторонний: полузакрытие пришлось бы отличать от
	// настоящего отказа, а стенду нужен именно отказ целиком.
	var once sync.Once
	stop := func(rst bool) {
		once.Do(func() {
			if rst {
				i.reset(client)
				i.reset(up)
				return
			}
			i.drop(client)
			i.drop(up)
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); i.pump(client, up, true, stop) }()
	go func() { defer wg.Done(); i.pump(up, client, false, stop) }()
	wg.Wait()
}

// pump качает байты src → dst, сверяясь с режимом дважды: перед чтением (gate)
// и перед записью (deliver). fromClient отмечает направление к upstream —
// только его байты считает ModeCutAfterHandshake.
func (i *Injector) pump(src, dst net.Conn, fromClient bool, stop func(rst bool)) {
	buf := make([]byte, bufSize)
	forwarded := 0 // байт от клиента: бюджет режима cut-after-handshake

	for {
		if !i.gate(stop) {
			return
		}
		// Дедлайн нужен не для отказа, а чтобы регулярно возвращаться к gate
		// (см. pollInterval); его срабатывание — не ошибка.
		_ = src.SetReadDeadline(time.Now().Add(pollInterval)) //hop:realtime — дедлайн ядра, фейковые часы его не задают
		n, err := src.Read(buf)
		if n > 0 && !i.deliver(buf[:n], dst, fromClient, &forwarded, stop) {
			return
		}
		if err != nil {
			if isTimeout(err) {
				continue
			}
			stop(false)
			return
		}
	}
}

// gate сверяет режим до чтения. false — перекачку пора прекратить.
//
// Проверка именно здесь, а не только в deliver: rst и blackhole обязаны
// действовать и на молчащем соединении (§8.3 T11 — «оба случая дают
// переключение за ≤ 5 с»), а в соединение, по которому никто не пишет, deliver
// никогда не позовут. Отсюда же и дедлайн pollInterval на чтении: без него
// перекачка вернулась бы сюда только вместе с байтами.
func (i *Injector) gate(stop func(rst bool)) bool {
	for {
		mode, _, _, changed := i.settings()
		switch mode {
		case ModeRST:
			stop(true)
			return false
		case ModeBlackhole:
			// Не читаем вовсе: байты остаются в буфере ядра, окно закрывается,
			// отправитель упирается — это ближе к настоящей чёрной дыре, чем
			// вычитывать и молча выбрасывать.
			select {
			case <-changed:
			case <-i.done:
				return false
			}
		default:
			return true
		}
	}
}

// deliver отдаёт прочитанный кусок согласно текущему режиму. false означает
// «перекачку пора прекратить»: либо соединение уже разорвано, либо инжектор
// закрыт.
func (i *Injector) deliver(chunk []byte, dst net.Conn, fromClient bool, forwarded *int, stop func(rst bool)) bool {
	for {
		mode, slow, cut, changed := i.settings()
		cutting := false

		switch mode {
		case ModeRST:
			stop(true)
			return false
		case ModeBlackhole:
			// Окно между gate и записью: режим сменили, пока кусок был уже
			// прочитан. Наружу он не пойдёт и соединение не закроется — ровно
			// то, что видит клиент за чёрной дырой; отдать его можно будет,
			// только если режим сменят обратно.
			select {
			case <-changed:
				continue
			case <-i.done:
				return false
			}
		case ModeSlow:
			i.pause(slow)
		case ModeCutAfterHandshake:
			if fromClient {
				left := cut - *forwarded
				if left <= 0 {
					stop(false)
					return false
				}
				if left < len(chunk) {
					chunk = chunk[:left]
				}
				cutting = true
			}
		}

		w, err := dst.Write(chunk)
		if fromClient {
			*forwarded += w
		}
		if err != nil {
			stop(false)
			return false
		}
		if cutting && *forwarded >= cut {
			// Бюджет исчерпан — рвём, не дожидаясь следующего чтения: клиент
			// мог больше ничего не прислать, а обрыв обязан наступить.
			//
			// Обрыв здесь именно FIN, а не RST: RST заставил бы ядро на той
			// стороне выбросить непрочитанное, и «upstream получил ровно n
			// байт» перестало бы быть проверяемым. Для клиента наблюдаемое
			// одно и то же — соединение кончилось не по его воле.
			stop(false)
			return false
		}
		return true
	}
}

// pause держит запись на d, но не переживает Close: иначе стенд с большой
// задержкой заставил бы тест ждать закрытия инжектора.
func (i *Injector) pause(d time.Duration) {
	if d <= 0 {
		return
	}
	select {
	case <-time.After(d): //hop:realtime — задержка канала, а не логики продукта
	case <-i.done:
	}
}

// track берёт соединение под уборку Close. Гонка с Close реальна: upstream
// может открыться уже после закрытия инжектора.
func (i *Injector) track(c net.Conn) {
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		_ = c.Close()
		return
	}
	i.live[c] = struct{}{}
	i.mu.Unlock()
}

// drop закрывает соединение штатно: FIN, уже отданные байты доходят.
func (i *Injector) drop(c net.Conn) {
	i.mu.Lock()
	delete(i.live, c)
	i.mu.Unlock()
	_ = c.Close()
}

// reset закрывает соединение так, чтобы ядро отправило RST, а не FIN:
// SO_LINGER с нулевым таймаутом (§8.1, режим rst — «сервер снят»). Плата —
// недоставленные байты теряются, поэтому reset уместен только там, где отказ
// и есть цель.
func (i *Injector) reset(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	i.drop(c)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
