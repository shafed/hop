package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// maxRequest — предел на запрос клиента. Клиент — процесс того же
// пользователя, но неограниченный json.Decoder читает значение целиком, и одна
// опечатка в скрипте съела бы память агента.
const maxRequest = 64 << 10

// Agent — то, что сервер спрашивает у агента. Реализация живёт в cmd/hop:
// только там сходятся супервизор (§3.4) и соединение с сервисом (§3.1).
type Agent interface {
	Status() Status
	Nodes() []NodeInfo
	// Pin — `hop up --node` (§С3).
	Pin(nodeID string) error
	Auto(on bool)
	Bypass(on bool)
	// Ping — форс-проверка узла (§6.6) и его состояние после неё.
	Ping(nodeID string) (NodeInfo, error)
}

// Server — сокет клиентов агента.
type Server struct {
	ln    net.Listener
	agent Agent
	hub   *Hub
	path  string
	once  sync.Once
}

// Serve поднимает сокет и начинает принимать клиентов.
//
// Права даёт каталог, а не сокет: net.Listen создаёт файл по umask, и chmod
// после bind оставил бы окно, в котором сокет доступен лишним. Каталог 0700
// (§6.14) закрывает и сокет, и лежащий рядом attach-token, и не требует
// платформенных вызовов.
func Serve(path string, a Agent) (*Server, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	// Файл от прошлого сеанса: bind по существующему пути не проходит, а
	// «сокет занят» после kill -9 агента — штатный сценарий (§6.2).
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("events: сокет клиентов: %w", err)
	}
	s := &Server{ln: ln, agent: a, hub: NewHub(), path: path}
	go s.accept()
	return s, nil
}

// Publish рассылает событие всем клиентам (§3.3).
func (s *Server) Publish(ev Event) { s.hub.Publish(ev) }

// Close снимает сокет. Подписки закрываются вместе с хабом, и потоки клиентов
// расходятся сами.
func (s *Server) Close() error {
	var err error
	s.once.Do(func() {
		err = s.ln.Close()
		s.hub.Close()
		_ = os.Remove(s.path)
	})
	return err
}

func (s *Server) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return // сокет закрыт: агент уходит
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	var req Request
	if err := json.NewDecoder(io.LimitReader(c, maxRequest)).Decode(&req); err != nil {
		c.Close()
		return
	}
	if req.Cmd == CmdEvents {
		s.stream(c)
		return
	}
	defer c.Close()
	_ = json.NewEncoder(c).Encode(s.dispatch(req))
}

func (s *Server) dispatch(req Request) Response {
	switch req.Cmd {
	case CmdStatus:
		st := s.agent.Status()
		return Response{Status: &st}
	case CmdNodes:
		return Response{Nodes: s.agent.Nodes()}
	case CmdPin:
		if err := s.agent.Pin(req.Node); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case CmdAuto:
		s.agent.Auto(req.On)
		return Response{}
	case CmdBypass:
		s.agent.Bypass(req.On)
		return Response{}
	case CmdPing:
		n, err := s.agent.Ping(req.Node)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Node: &n}
	default:
		return Response{Error: fmt.Sprintf("events: неизвестная команда %q", req.Cmd)}
	}
}

// stream отдаёт клиенту поток событий до закрытия соединения.
func (s *Server) stream(c net.Conn) {
	sub := s.hub.Subscribe()
	// Клиент, ушедший молча, иначе обнаружился бы только на следующем событии,
	// а событий может не быть часами: чтение до EOF снимает подписку сразу.
	go func() {
		_, _ = io.Copy(io.Discard, c)
		sub.Close()
	}()

	enc := json.NewEncoder(c)
	for ev := range sub.C() {
		if err := enc.Encode(Response{Event: &ev}); err != nil {
			break
		}
	}
	sub.Close()
	c.Close()
}
