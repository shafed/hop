// Package faultinject — инжектор отказов из §8.1: TCP-прослойка перед
// настоящим VLESS-инбаундом Xray.
//
// Форвардит байты и по команде переключает режим. Нужен потому, что «узел
// умер» — это не одно наблюдаемое, а несколько разных путей в коде: rst
// возвращает ошибку сразу, blackhole не возвращает ничего и ловит отсутствие
// таймаута там, где rst его маскирует (§8.1 требует их разными тестами).
//
// Прослойка честная: за ней стоит настоящий инбаунд, и агент реально
// устанавливает VLESS-соединение — моков между netstack и узлом нет (§8.3).
package faultinject

import (
	"net"
	"net/netip"
	"sync"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
)

// Mode — режим прослойки, §8.1.
type Mode string

const (
	// Pass — прозрачно, норма.
	Pass Mode = "pass"
	// RST — немедленный RST: сервер снят.
	RST Mode = "rst"
	// Blackhole — принимает и молчит: пакеты дропаются, соединение висит.
	Blackhole Mode = "blackhole"
	// Slow — задержка на каждой записи: деградация латентности.
	Slow Mode = "slow"
	// CutAfterHandshake — рвёт после первых Config.CutAfter байт, то есть
	// сразу за рукопожатием: DPI-подобное поведение.
	CutAfterHandshake Mode = "cut-after-handshake"
)

// Config — числа для режимов, которым число нужно. Задаются один раз при
// создании: на лету переключается режим, а не его параметры.
type Config struct {
	// Slow — задержка на каждой записи в режиме Slow.
	Slow time.Duration
	// CutAfter — сколько байт пропустить в режиме CutAfterHandshake до
	// разрыва. Ноль — значение по умолчанию, «после первой записи».
	CutAfter int
}

// Server — сама прослойка. Слушает на 127.0.0.1 со случайным портом и
// форвардит на upstream.
type Server struct {
	upstream netip.AddrPort
	cfg      Config
	clk      clock.Clock

	ln   net.Listener
	addr netip.AddrPort
	// done закрывается на Close. Режим blackhole висит на нём: соединение
	// обязано не закрываться, пока стенд жив, — в этом весь смысл режима.
	done chan struct{}

	mu    sync.Mutex
	mode  Mode
	conns map[net.Conn]struct{}
}

// New поднимает прослойку перед upstream и начинает принимать соединения.
// Стартовый режим — Pass.
//
// Часы приходят снаружи, потому что задержка режима Slow — это интервал, а
// интервалы в этом продукте не берутся из настоящего времени (§8.1).
func New(upstream netip.AddrPort, cfg Config, clk clock.Clock) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		ln.Close()
		return nil, err
	}
	s := &Server{
		upstream: upstream,
		cfg:      cfg,
		clk:      clk,
		ln:       ln,
		addr:     addr,
		done:     make(chan struct{}),
		mode:     Pass,
		conns:    make(map[net.Conn]struct{}),
	}
	go s.accept()
	return s, nil
}

// Addr — куда подключаться клиенту.
func (s *Server) Addr() netip.AddrPort { return s.addr }

// SetMode переключает режим на лету: новые соединения видят его сразу, уже
// установленные — на ближайшей операции. Без этого тест не смог бы уронить узел
// посреди живого соединения, а именно это проверяют T9 и T11.
func (s *Server) SetMode(m Mode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = m
}

// Mode — текущий режим.
func (s *Server) Mode() Mode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

// Close снимает прослойку и рвёт всё, что через неё шло.
func (s *Server) Close() error {
	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return nil
	default:
		close(s.done)
	}
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.conns = make(map[net.Conn]struct{})
	s.mu.Unlock()

	err := s.ln.Close()
	for _, c := range conns {
		c.Close()
	}
	return err
}

func (s *Server) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.serve(c)
	}
}

func (s *Server) serve(c net.Conn) {
	if !s.track(c) {
		c.Close()
		return
	}
	defer s.drop(c)

	switch s.Mode() {
	case RST:
		// Сначала дожидаемся первых байт клиента и только потом рвём. Close с
		// linger=0 на соединении, чьи данные ещё в полёте, ядро иногда
		// завершает штатным FIN, и клиент получает EOF вместо ECONNRESET — а
		// это разные наблюдаемые (§8.1), стенд обязан давать ровно одно.
		// Молчащего клиента разблокирует Close стенда, как и в blackhole.
		var b [1]byte
		c.Read(b[:])
		reset(c)
		return
	case Blackhole:
		// Принимаем и молчим: наверх не ходим вообще, соединение висит до
		// закрытия стенда. Клиент не увидит ни байта и ни FIN — ровно то, на
		// чём ломается код без собственного таймаута.
		<-s.done
		return
	}

	up, err := net.Dial("tcp", s.upstream.String())
	if err != nil {
		reset(c)
		return
	}
	if !s.track(up) {
		up.Close()
		return
	}
	defer s.drop(up)

	// Первая же завершившаяся сторона снимает обе: полузакрытое соединение
	// стенду не нужно, а живой второй пампе некому отдавать байты.
	var once sync.Once
	stop := make(chan struct{})
	halt := func() { once.Do(func() { close(stop) }) }
	go func() { defer halt(); s.pump(up, c, false) }()
	go func() { defer halt(); s.pump(c, up, true) }()
	<-stop
}

// pump перекладывает байты из src в dst, сверяясь с режимом на каждой порции.
// toClient отмечает направление «узел → клиент»: только в нём считаются байты
// для CutAfterHandshake, потому что разрыв обязан наступить на наблюдаемой
// клиентом границе, а не на случайной внутренней.
func (s *Server) pump(dst, src net.Conn, toClient bool) {
	buf := make([]byte, 32*1024)
	var sent int
	for {
		n, err := src.Read(buf)
		if n > 0 {
			// Режим снимается один раз на порцию: иначе переключение посреди
			// её обработки раздвоило бы поведение.
			mode := s.Mode()
			chunk := buf[:n]
			switch mode {
			case RST:
				reset(dst)
				reset(src)
				return
			case Blackhole:
				// Роняем байты и не закрываемся: возврат отсюда снял бы
				// соединение, а blackhole тем и отличается от rst, что не
				// снимает.
				continue
			case Slow:
				<-s.clk.After(s.cfg.Slow)
			case CutAfterHandshake:
				// Режем ровно на границе, а не по концу порции: наблюдаемое
				// «пришло N байт и всё» не должно зависеть от того, как
				// упаковались чтения.
				if toClient {
					if left := s.cutAfter() - sent; left < len(chunk) {
						chunk = chunk[:left]
					}
				}
			}
			if _, err := dst.Write(chunk); err != nil {
				return
			}
			if mode == CutAfterHandshake && toClient {
				if sent += len(chunk); sent >= s.cutAfter() {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *Server) cutAfter() int {
	if s.cfg.CutAfter <= 0 {
		return 1
	}
	return s.cfg.CutAfter
}

// track берёт соединение под учёт, чтобы Close его снял. false — стенд уже
// закрыт, и соединение брать некуда.
func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return false
	default:
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) drop(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	c.Close()
}

// reset закрывает соединение так, чтобы вышел RST, а не FIN: клиент обязан
// получить ECONNRESET. Корректное закрытие он бы принял за штатный конец
// ответа, и «сервер снят» стало бы неотличимо от «сервер ответил и попрощался».
func reset(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
	c.Close()
}
