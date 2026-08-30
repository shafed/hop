package agent

// Граница «клиенты ↔ агент» (§3.3): сокет, к которому ходят `hop status`,
// `hop events`, `hop up`, `hop bypass`, `hop auto`.
//
// # Форма: тот же транспорт, второй сокет, свой набор операций
//
// Вопрос стоял так: второй сервер на транспорте `internal/ipc` или отдельный
// транспорт. Ответ — тот же довод, которым §6.1 отвечает hiddify: **не TCP**.
// hiddify слушает gRPC на `127.0.0.1:18020` без всякой проверки, и любой
// процесс любого пользователя машины поднимает чужой туннель. Локальный порт
// не умеет ответить на вопрос «кто на том конце»; unix-сокет с правами
// владельца и named pipe с SDDL умеют, и это единственная причина, по которой
// транспорт §3.1 написан так, как написан. Переписывать его второй раз ради
// второй границы значило бы получить вторую реализацию того же ответа — и
// однажды разойтись с первой ровно в этом месте.
//
// Поэтому взят транспорт `internal/ipc` целиком (`Listen`, `Dial`, `Conn`,
// кадр «длина + JSON») и **отдельный сокет** со своим набором операций. Три
// причины, по которым это не второй сервер на том же файле:
//
//  1. Разные владельцы. `/run/hop.sock` создаёт привилегированный сервис и
//     открывает группе; клиентский сокет создаёт непривилегированный агент в
//     каталоге пользователя (§3.3). Один файл потребовал бы, чтобы клиенты
//     ходили в сокет сервиса, а §3.3 запрещает это буквально: «клиенты никогда
//     не говорят с привилегированным сервисом напрямую».
//  2. Разные множества операций. Через §3.1 не проходит ни один узел и ни один
//     ключ; через §3.3 проходит вся наблюдаемая картина. Общий набор Op свёл бы
//     два перечисления в одно, и «сервис не знает, куда идёт трафик» перестало
//     бы держаться типом.
//  3. Разные адресаты в двоичных файлах. `cmd/hopd` импортирует `internal/ipc`
//     и работает под root; сервер этой границы спрашивает связку. Положи его в
//     `internal/ipc` — и привилегированный демон утащит в себя весь агент
//     вместе с Xray по графу импортов.
//
// # Несколько клиентов с первого дня
//
// §3.3 требует этого прямо: в v1 клиент один, но GUI и трей подключатся
// одновременно, и события рассылаются **всем** подписчикам. Кольцо событий
// связки (`eventRing`) умеет это с этапа С — `subscribe` отдаёт накопленное и
// свой канал каждому. Сервер здесь только не мешает: соединение обслуживается
// своей горутиной, подписка заводится на соединение, а не на сервер.
//
// Политика `event_broadcast` выключает ровно это и ничего больше: живая
// подписка остаётся одна, остальные получают историю и молчание — форма,
// в которой у связки был бы один канал событий на всех.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/policy"
)

// ClientStatus — картина, которую §1/С5 требует от `hop status`.
//
// Обе фазы (§2), активный узел с латентностью, состояние автоматики и
// фиксация, последнее переключение. Списка узлов здесь нет намеренно: С5
// отдаёт его `hop nodes`, а `status` отвечает на вопрос «что происходит», а не
// «как оно устроено». Счётчики `alive`/`nodes` — не список: без них
// «живых узлов нет» неотличимо от «узлов нет вовсе», а это разные коды
// возврата (§5.9).
//
// Теги полей — заодно и схема `--json` глагола `status`: `cmd/hop` печатает
// это значение как есть. Второй экземпляр той же структуры в `cmd/hop`
// разошёлся бы с этим молча — тот же довод, по которому `hop nodes` печатает
// готовый `store.NodeView`.
type ClientStatus struct {
	// Tunnel — фаза сервиса (§2, tunnel_phase), как её знает связка.
	Tunnel string `json:"tunnel"`
	// Traffic — фаза трафика (§2). Половина, которой у `hop status` не было
	// до этого сокета.
	Traffic string `json:"traffic"`
	// Active — id активного узла; пусто, когда его нет.
	Active string `json:"active,omitempty"`
	// ActiveState и ActiveRTTMs — живость активного узла. С5 требует
	// «активный узел с латентностью», и латентность приезжает отсюда, а не
	// из стора: стор держит эксклюзивный flock всё время жизни агента.
	ActiveState string `json:"active_state,omitempty"`
	ActiveRTTMs int64  `json:"active_rtt_ms,omitempty"`
	// Auto — автопереключение (§1/С3).
	Auto bool `json:"auto"`
	// Pinned — зафиксированный узел (§1/С3). Отдельным полем, потому что С5
	// требует отдельной строки: фиксация буквальна, и мёртвый
	// зафиксированный узел не заменяется.
	Pinned string `json:"pinned,omitempty"`
	// Alive, Nodes — сколько узлов живо из скольких поддерживаемых.
	Alive int `json:"alive"`
	Nodes int `json:"nodes"`
	// Detached — почему нет связи с сервисом; пусто, когда связь есть (Р34).
	Detached string `json:"detached,omitempty"`
	// Last — последнее переключение. null, если его не было: нулевое событие
	// в выводе читалось бы как «переключились в никого в нулевом году».
	Last *ClientEvent `json:"last_switch"`
}

// ClientEvent — событие переключения на проводе (§2).
//
// Своя структура, а не `health.SwitchEvent`: у той поля без тегов и `Reason`
// числом со своим `String()`, а протокол читают глазами и разбирают чужой
// автоматикой.
type ClientEvent struct {
	At          time.Time `json:"at"`
	From        string    `json:"from,omitempty"`
	To          string    `json:"to"`
	Reason      string    `json:"reason"`
	Interrupted int       `json:"interrupted"`
}

func toClientEvent(ev health.SwitchEvent) ClientEvent {
	return ClientEvent{
		At: ev.At, From: ev.From, To: ev.To,
		Reason: ev.Reason.String(), Interrupted: ev.Interrupted,
	}
}

// clientOp — операция границы §3.3.
//
// Не экспортируется: снаружи пакета глаголы вызываются методами Client, а не
// сборкой запроса руками. Второй способ послать `Bypass` означал бы второе
// место, где протокол знают.
type clientOp string

const (
	opStatus clientOp = "Status"
	opEvents clientOp = "Events"
	opUp     clientOp = "Up"
	opDown   clientOp = "Down"
	opBypass clientOp = "Bypass"
	opAuto   clientOp = "Auto"
)

type clientRequest struct {
	Op clientOp `json:"op"`
	// On — для Bypass и Auto. Указатель: «on|off» — обязательный аргумент
	// глагола, и забытое поле обязано быть отказом, а не молчаливым false.
	On *bool `json:"on,omitempty"`
	// Node — `hop up --node <id>` (§1/С3).
	Node string `json:"node,omitempty"`
	// Follow — `hop events --follow` (§1/С5).
	Follow bool `json:"follow,omitempty"`
}

type clientResponse struct {
	Error  string        `json:"error,omitempty"`
	Status *ClientStatus `json:"status,omitempty"`
	Event  *ClientEvent  `json:"event,omitempty"`
	// End закрывает поток истории: без него клиент, дочитавший события, не
	// отличает «история кончилась» от «сервер задумался».
	End bool `json:"end,omitempty"`
}

// ClientAPI — то, что граница §3.3 спрашивает у связки.
//
// Интерфейс, а не *Agent, по одной причине: `cmd/hop` проверяет свои глаголы
// против настоящего сокета, и поднимать ради этого весь агент с Xray значило
// бы проверять сборку вместо разбора аргументов.
type ClientAPI interface {
	Snapshot() Snapshot
	Events(buf int) ([]health.SwitchEvent, <-chan health.SwitchEvent)
	Unsubscribe(c <-chan health.SwitchEvent)
	History() []health.SwitchEvent
	Up() error
	Down() error
	Bypass(on bool) error
	Auto(on bool)
	Pin(nodeID string) error
}

// Связка обязана удовлетворять границе целиком: расхождение — ошибка сборки,
// а не отказ в рантайме.
var _ ClientAPI = (*Agent)(nil)

// clientEventBuf — глубина очереди событий одного подписчика.
//
// Кольцо рассылает неблокирующе (см. eventRing.push): подписчик, который не
// читает, теряет события, но не останавливает переключение узлов. Буфер
// нужен, чтобы «не читает» означало «завис», а не «занят отправкой
// предыдущего».
const clientEventBuf = 32

// ClientServer — сервер границы §3.3.
type ClientServer struct {
	api ClientAPI
	log *slog.Logger

	mu     sync.Mutex
	conns  map[ipc.Conn]struct{}
	subs   int // живых подписок на события
	closed bool

	done chan struct{}
	wg   sync.WaitGroup
}

func NewClientServer(api ClientAPI, log *slog.Logger) *ClientServer {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &ClientServer{
		api:   api,
		log:   log,
		conns: map[ipc.Conn]struct{}{},
		done:  make(chan struct{}),
	}
}

// Serve обслуживает соединения, пока жив слушатель.
//
// Каждое — своей горутиной, и это не оптимизация: §3.3 требует нескольких
// одновременных клиентов, а `hop events --follow` не возвращается никогда.
// Последовательный accept означал бы, что первый же трей вешает CLI.
func (s *ClientServer) Serve(l ipc.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		if !s.track(c) {
			c.Close()
			return errors.New("сокет клиентов закрыт")
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrack(c)
			s.handle(c)
		}()
	}
}

// Close закрывает сокет для всех: соединения рвутся, потоки событий кончаются.
func (s *ClientServer) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.done)
	conns := make([]ipc.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	// Соединения закрываются снаружи чтения: подписчик `--follow` висит на
	// канале и своего Recv не ждёт, поэтому разбудить его можно только тем же
	// s.done, а читающего — только закрытием сокета.
	for _, c := range conns {
		_ = c.Close()
	}
	s.wg.Wait()
}

func (s *ClientServer) track(c ipc.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *ClientServer) untrack(c ipc.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	_ = c.Close()
}

func (s *ClientServer) handle(c ipc.Conn) {
	for {
		body, _, err := c.Recv()
		if err != nil {
			return
		}
		var req clientRequest
		if err := json.Unmarshal(body, &req); err != nil {
			if s.send(c, clientResponse{Error: "неразбираемый запрос: " + err.Error()}) != nil {
				return
			}
			continue
		}
		if req.Op == opEvents {
			if !s.stream(c, req) {
				return
			}
			continue
		}
		if s.send(c, s.dispatch(req)) != nil {
			return
		}
	}
}

// dispatch — управляющие глаголы §5.9.
func (s *ClientServer) dispatch(req clientRequest) clientResponse {
	switch req.Op {
	case opStatus:
		st := s.status()
		return clientResponse{Status: &st}

	case opUp:
		// Порядок обязателен: набор узлов живости обновляет Up, а Pin
		// фиксирует узел из этого набора. Обратный порядок отказывал бы на
		// узле, только что приехавшем из подписки. Цена — неизвестный id
		// оставляет туннель поднятым на автоматически выбранном узле; отказ
		// это и говорит, вместо того чтобы промолчать.
		if err := s.api.Up(); err != nil {
			return clientResponse{Error: err.Error()}
		}
		if req.Node != "" {
			if err := s.api.Pin(req.Node); err != nil {
				return clientResponse{Error: fmt.Sprintf(
					"туннель поднят, но узел %q не зафиксирован: %v", req.Node, err)}
			}
		}
		return clientResponse{}

	case opDown:
		if err := s.api.Down(); err != nil {
			return clientResponse{Error: err.Error()}
		}
		return clientResponse{}

	case opBypass:
		if req.On == nil {
			return clientResponse{Error: "bypass без on|off"}
		}
		if err := s.api.Bypass(*req.On); err != nil {
			return clientResponse{Error: err.Error()}
		}
		return clientResponse{}

	case opAuto:
		if req.On == nil {
			return clientResponse{Error: "auto без on|off"}
		}
		s.api.Auto(*req.On)
		return clientResponse{}

	default:
		return clientResponse{Error: "неизвестная операция " + string(req.Op)}
	}
}

// status собирает ClientStatus из снимка связки.
//
// Живость активного узла ищется в снимке, а не спрашивается вторым вызовом:
// между двумя вызовами состояние меняется, и картина, собранная из двух
// обращений, не существовала ни в один момент времени (тот же довод, что у
// самого Snapshot).
func (s *ClientServer) status() ClientStatus {
	snap := s.api.Snapshot()
	st := ClientStatus{
		Tunnel:   string(snap.Tunnel),
		Traffic:  string(snap.Traffic),
		Active:   snap.Active,
		Auto:     snap.Auto,
		Pinned:   snap.Pinned,
		Detached: snap.Detached,
		Nodes:    len(snap.Nodes),
	}
	for _, n := range snap.Nodes {
		if n.State == health.Alive {
			st.Alive++
		}
		if n.NodeID == snap.Active {
			st.ActiveState = n.State.String()
			st.ActiveRTTMs = int64(n.RTT / time.Millisecond)
		}
	}
	if !snap.Last.At.IsZero() {
		ev := toClientEvent(snap.Last)
		st.Last = &ev
	}
	return st
}

// stream — `hop events` и `hop events --follow`.
//
// Возвращает false, когда соединение кончилось: обслуживать его дальше нечем.
func (s *ClientServer) stream(c ipc.Conn, req clientRequest) bool {
	var (
		history []health.SwitchEvent
		ch      <-chan health.SwitchEvent
	)
	switch {
	case !req.Follow:
		history = s.api.History()
	case s.claimSub():
		// Накопленное и подписка — одним вызовом и под одним замком кольца:
		// двумя было бы окно, в котором событие уже не в истории и ещё не в
		// канале, и клиент, подключившийся сразу после переключения, его бы
		// не увидел (§2 регистра).
		history, ch = s.api.Events(clientEventBuf)
		defer func() {
			s.api.Unsubscribe(ch)
			s.releaseSub()
		}()
	default:
		// event_broadcast выключена, живая подписка уже занята. Это и есть
		// форма «один канал событий на всех»: второй клиент получает историю
		// и молчание.
		history = s.api.History()
	}

	for _, ev := range history {
		e := toClientEvent(ev)
		if s.send(c, clientResponse{Event: &e}) != nil {
			return false
		}
	}
	if !req.Follow {
		return s.send(c, clientResponse{End: true}) == nil
	}

	for {
		select {
		case <-s.done:
			return false
		case ev, ok := <-ch:
			if !ok {
				// Кольцо закрылось вместе со связкой.
				return false
			}
			e := toClientEvent(ev)
			if s.send(c, clientResponse{Event: &e}) != nil {
				return false
			}
		}
	}
}

// claimSub берёт право на живую подписку.
//
// При включённой политике право есть всегда: §3.3 требует рассылки всем
// подписчикам. Выключенная оставляет одну подписку на сервер — краснеет W60.
func (s *ClientServer) claimSub() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !policy.EventBroadcast.On() && s.subs > 0 {
		return false
	}
	s.subs++
	return true
}

func (s *ClientServer) releaseSub() {
	s.mu.Lock()
	s.subs--
	s.mu.Unlock()
}

func (s *ClientServer) send(c ipc.Conn, resp clientResponse) error {
	body, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return c.Send(body, -1)
}

// Client — тонкий клиент границы §3.3 (§5.9: «CLI — тонкий клиент, вся логика
// в агенте»).
type Client struct {
	mu sync.Mutex
	c  ipc.Conn
}

// DialClient подключается к сокету связки.
func DialClient(path string) (*Client, error) {
	c, err := ipc.Dial(path)
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

func (cl *Client) Close() error { return cl.c.Close() }

// Status — картина §1/С5 целиком.
func (cl *Client) Status() (ClientStatus, error) {
	resp, err := cl.call(clientRequest{Op: opStatus})
	if err != nil {
		return ClientStatus{}, err
	}
	if resp.Status == nil {
		return ClientStatus{}, errors.New("связка ответила пустым состоянием")
	}
	return *resp.Status, nil
}

// Up поднимает туннель; node непуст — фиксирует узел (§1/С3).
func (cl *Client) Up(node string) error {
	_, err := cl.call(clientRequest{Op: opUp, Node: node})
	return err
}

func (cl *Client) Down() error {
	_, err := cl.call(clientRequest{Op: opDown})
	return err
}

func (cl *Client) Bypass(on bool) error {
	_, err := cl.call(clientRequest{Op: opBypass, On: &on})
	return err
}

func (cl *Client) Auto(on bool) error {
	_, err := cl.call(clientRequest{Op: opAuto, On: &on})
	return err
}

// Events отдаёт события в fn: сперва накопленное, затем — при follow — всё,
// что придёт дальше, пока fn не откажет или связка не уйдёт.
//
// Колбэк, а не срез: поток `--follow` не кончается, и срезом он невыразим.
func (cl *Client) Events(follow bool, fn func(ClientEvent) error) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if err := cl.send(clientRequest{Op: opEvents, Follow: follow}); err != nil {
		return err
	}
	for {
		resp, err := cl.recv()
		if err != nil {
			return err
		}
		if resp.End {
			return nil
		}
		if resp.Event == nil {
			return errors.New("связка прислала кадр без события")
		}
		if err := fn(*resp.Event); err != nil {
			return err
		}
	}
}

func (cl *Client) call(req clientRequest) (clientResponse, error) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if err := cl.send(req); err != nil {
		return clientResponse{}, err
	}
	return cl.recv()
}

func (cl *Client) send(req clientRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return cl.c.Send(body, -1)
}

func (cl *Client) recv() (clientResponse, error) {
	raw, _, err := cl.c.Recv()
	if err != nil {
		return clientResponse{}, err
	}
	var resp clientResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return clientResponse{}, err
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}
