package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time" //hop:realtime

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	xnet "github.com/xtls/xray-core/common/net"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/node"
)

// Engine — движок поверх одного экземпляра Xray.
//
// Активный узел — это тег, а не конфиг: SetActive меняет строку, по которой
// исходящее выбирает inboundTag, и больше ничего. Пересборка экземпляра на
// каждом переключении рвала бы все соединения разом — ровно то, что §5.5
// запрещает делать при переключении по причине faster.
type Engine struct {
	opts Options
	rep  health.Reporter
	clk  clock.Clock

	// cfg — конфиг, собранный buildConfig ещё в New. Узел с битым транспортом
	// обязан уронить New, а не первое соединение через час работы.
	cfg  []byte
	inst *core.Instance

	mu     sync.RWMutex
	nodes  map[string]node.Node
	active string
}

// Проверка контракта §3.4: исходящее netstack — это Engine. Цикла импортов
// нет, netstack про engine не знает и знать не должен.
var _ netstack.Dialer = (*Engine)(nil)

// errNotStarted — движок ещё не поднят. Отдельная ошибка, а не молчаливый
// проход напрямую: молчаливый обход туннеля есть fail-open (§5.6).
var errNotStarted = errors.New("engine: движок не запущен")

// errNoActive — активный узел не назначен. Тоже отказ, а не direct.
var errNoActive = errors.New("engine: активный узел не выбран")

// New собирает движок: конфиг Xray на все поддержанные узлы плюс direct.
// Экземпляр ещё не запущен — это делает Start.
func New(nodes []node.Node, opts Options, rep health.Reporter, clk clock.Clock) (*Engine, error) {
	cfg, err := buildConfig(nodes, opts)
	if err != nil {
		return nil, err
	}
	known := make(map[string]node.Node, len(nodes))
	for _, n := range nodes {
		// Неподдержанный узел (§6.11) в конфиг не попал, значит и outbound-а
		// у него нет: пустить в него трафик было бы промахом по правилу.
		if n.Supported {
			known[n.ID] = n
		}
	}
	return &Engine{opts: opts, rep: rep, clk: clk, cfg: cfg, nodes: known}, nil
}

// Start поднимает экземпляр Xray. До Start любой Dial обязан вернуть ошибку, а
// не молча пойти напрямую: молчаливый обход туннеля — это fail-open (§5.6).
func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inst != nil {
		return errors.New("engine: уже запущен")
	}
	// JSON разбирается тем же кодом Xray, который его понимает в проде
	// (infra/conf), поэтому расхождение нашего конфига с движком невозможно
	// по построению. main/json взят бы вместе с загрузкой конфига по http(s).
	pb, err := serial.LoadJSONConfig(bytes.NewReader(e.cfg))
	if err != nil {
		return fmt.Errorf("engine: разбор конфига: %w", err)
	}
	inst, err := core.New(pb)
	if err != nil {
		return fmt.Errorf("engine: сборка экземпляра: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return fmt.Errorf("engine: старт экземпляра: %w", err)
	}
	e.inst = inst
	return nil
}

// Close снимает экземпляр. Установленные соединения при этом умирают — Close
// зовётся только на выходе агента, переключение узла его не трогает.
func (e *Engine) Close() error {
	e.mu.Lock()
	inst := e.inst
	e.inst = nil
	e.mu.Unlock()
	if inst == nil {
		return nil
	}
	return inst.Close()
}

// SetActive назначает узел, через который пойдёт новый трафик. Уже открытые
// соединения продолжают жить в своём outbound: рвать их или нет, решает §5.5 по
// причине переключения, а не движок.
func (e *Engine) SetActive(nodeID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active = nodeID
}

// Active — текущий активный узел, пусто до первого SetActive.
func (e *Engine) Active() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.active
}

// DialTCP — исходящее TCP через активный узел (netstack.Dialer).
func (e *Engine) DialTCP(dst netip.AddrPort) (net.Conn, error) {
	return e.DialVia(context.Background(), e.Active(), dst)
}

// DialUDP — исходящее UDP через активный узел (netstack.Dialer).
//
// Принимает **исходный** адрес клиента, а не назначение: core.DialUDP отдаёт
// net.PacketConn, один на исходный порт, и из этого получается full-cone (§5.3).
func (e *Engine) DialUDP(src netip.AddrPort) (net.PacketConn, error) {
	nodeID := e.Active()
	if nodeID == "" {
		return nil, errNoActive
	}
	inst, err := e.instance()
	if err != nil {
		return nil, err
	}
	if err := e.known(nodeID); err != nil {
		return nil, err
	}

	tr := &tracker{}
	// Source заполняется намеренно: NAT-запись Xray ключуется исходным
	// addr:port, и full-cone держится ровно на том, что все датаграммы одного
	// клиентского порта идут одним PacketConn (§5.3, T15).
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    tagOf(nodeID),
		Source: xnet.UDPDestination(xnet.IPAddress(src.Addr().AsSlice()), xnet.Port(src.Port())),
	})
	ctx = session.TrackedConnectionError(ctx, tr)

	start := e.clk.Now()
	pc, err := core.DialUDP(ctx, inst)
	if err != nil {
		return nil, e.report(nodeID, tr.fault(err), e.clk.Now().Sub(start))
	}
	return &trackedPacketConn{PacketConn: pc, e: e, nodeID: nodeID, tr: tr, start: start}, nil
}

// DialVia — соединение через конкретный узел, а не через активный.
//
// Этим ходят пробы (§6.7): тот же outbound, тот же роутинг, что и у трафика.
// Проба в обход измеряет не то, что нужно, — узел может быть жив для пробера и
// мёртв для трафика.
func (e *Engine) DialVia(ctx context.Context, nodeID string, dst netip.AddrPort) (net.Conn, error) {
	if nodeID == "" {
		return nil, errNoActive
	}
	if err := e.known(nodeID); err != nil {
		return nil, err
	}
	return e.dial(ctx, nodeID, tagOf(nodeID), dst)
}

// DialDirect — соединение мимо всех узлов, по тегу direct.
//
// Нужен bootstrap-резолверу (§5.7а): хостнеймы самих узлов резолвить через
// туннель нельзя, иначе на старте петля. Попасть в direct можно только этим
// вызовом — маршрутного правила, ведущего сюда по умолчанию, нет намеренно.
func (e *Engine) DialDirect(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return e.dial(ctx, "", DirectTag, dst)
}

// dial — общий путь исходящего TCP. Пустой nodeID означает direct: его отказы
// не принадлежат ни одному узлу и в health не идут.
func (e *Engine) dial(ctx context.Context, nodeID, tag string, dst netip.AddrPort) (net.Conn, error) {
	inst, err := e.instance()
	if err != nil {
		return nil, err
	}

	tr := &tracker{}
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: tag})
	ctx = session.TrackedConnectionError(ctx, tr)

	start := e.clk.Now()
	dest := xnet.TCPDestination(xnet.IPAddress(dst.Addr().AsSlice()), xnet.Port(dst.Port()))
	c, err := core.Dial(ctx, inst, dest)
	if nodeID == "" {
		return c, err
	}
	if err != nil {
		return nil, e.report(nodeID, tr.fault(err), e.clk.Now().Sub(start))
	}
	return &trackedConn{Conn: c, e: e, nodeID: nodeID, tr: tr, start: start}, nil
}

func (e *Engine) instance() (*core.Instance, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.inst == nil {
		return nil, errNotStarted
	}
	return e.inst, nil
}

func (e *Engine) known(nodeID string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if _, ok := e.nodes[nodeID]; !ok {
		return fmt.Errorf("engine: узел %q не в конфиге", nodeID)
	}
	return nil
}

// tracker ловит ошибку, которую Xray отдаёт не вызывающему, а в контекст.
//
// Так устроен core.Dial: диспетчер уходит в горутину и возвращает трубу
// немедленно, поэтому отказ узла (не поднялось соединение, не прошло
// рукопожатие, TLS не сошёлся) приезжает позже и в другом месте. На самой
// трубе от него остаётся io.ErrClosedPipe — по нему §6.15 не разложить, а
// значит и классифицировать было бы нечего.
type tracker struct {
	mu  sync.Mutex
	err error
}

// SubmitError реализует session.TrackedRequestErrorFeedback. Первая ошибка
// выигрывает: она ближе к причине, дальнейшие — её следствия.
func (t *tracker) SubmitError(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.err == nil {
		t.err = err
	}
}

// fault помечает ошибку как пришедшую с пути к узлу, если Xray такую сообщил.
// Иначе отдаёт исходную как есть: труба закрылась, но узел тут ни при чём —
// это сайт, и §6.15 узел за него не убивает.
func (t *tracker) fault(err error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.err == nil {
		return err
	}
	return &nodeFault{err: t.err}
}

// trackedConn — соединение, доносящее исход до классификации.
//
// Отчётов ровно два вида и по одному каждого: первый прочитанный байт значит,
// что узел работает, первая ошибка — что что-то сломалось. Оба нужны и оба
// раздельны: соединение может сперва отработать, а потом оборваться, и от
// того, чей это обрыв, зависит судьба узла.
type trackedConn struct {
	net.Conn
	e      *Engine
	nodeID string
	tr     *tracker
	start  time.Time

	okOnce   sync.Once
	failOnce sync.Once
}

func (c *trackedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.ok()
	}
	if err != nil {
		c.fail(err)
	}
	return n, err
}

func (c *trackedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil {
		c.fail(err)
	}
	return n, err
}

func (c *trackedConn) ok() {
	c.okOnce.Do(func() { c.e.report(c.nodeID, nil, c.e.clk.Now().Sub(c.start)) })
}

func (c *trackedConn) fail(err error) {
	c.failOnce.Do(func() { c.e.report(c.nodeID, c.tr.fault(err), c.e.clk.Now().Sub(c.start)) })
}

// trackedPacketConn — то же для UDP. Без него узел, через который ходит только
// UDP, никогда бы не подал признаков жизни в health.
type trackedPacketConn struct {
	net.PacketConn
	e      *Engine
	nodeID string
	tr     *tracker
	start  time.Time

	okOnce   sync.Once
	failOnce sync.Once
}

func (c *trackedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if n > 0 {
		c.okOnce.Do(func() { c.e.report(c.nodeID, nil, c.e.clk.Now().Sub(c.start)) })
	}
	if err != nil {
		c.fail(err)
	}
	return n, addr, err
}

func (c *trackedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, addr)
	if err != nil {
		c.fail(err)
	}
	return n, err
}

func (c *trackedPacketConn) fail(err error) {
	c.failOnce.Do(func() { c.e.report(c.nodeID, c.tr.fault(err), c.e.clk.Now().Sub(c.start)) })
}
