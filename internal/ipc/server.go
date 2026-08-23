package ipc

import (
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/shafed/hop/internal/tunnel"
)

// FDSource — то, что умеет отдать дескриптор устройства. На Linux и macOS его
// реализует TUN; на Windows не реализует никто, и Response несёт имя трубы.
type FDSource interface{ Fd() int }

// Server — управляющая сторона сервиса.
type Server struct {
	m   *tunnel.Machine
	log *slog.Logger

	mu    sync.Mutex
	owner Conn // соединение, которому принадлежит туннель
}

// NewServer связывает транспорт с машиной состояний.
func NewServer(m *tunnel.Machine, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{m: m, log: log}
}

// Serve обслуживает соединения, пока слушатель жив.
func (s *Server) Serve(l Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

// handle обслуживает одно соединение.
//
// Выход из этой функции для соединения-владельца **и есть ребро в orphaned**
// (§6.2): ядро закрывает дескрипторы умершего процесса мгновенно, включая
// kill -9, и никакого таймера для этого не нужно.
func (s *Server) handle(c Conn) {
	defer c.Close()
	for {
		body, _, err := c.Recv()
		if err != nil {
			if !isClosed(err) {
				s.log.Debug("ipc: соединение оборвалось", "err", err)
			}
			s.ownerGone(c)
			return
		}

		var req Request
		if err := json.Unmarshal(body, &req); err != nil {
			_ = s.reply(c, Response{Error: "неразбираемый запрос: " + err.Error()}, -1)
			continue
		}
		resp, fd := s.dispatch(c, req)
		if err := s.reply(c, resp, fd); err != nil {
			s.ownerGone(c)
			return
		}
	}
}

func (s *Server) dispatch(c Conn, req Request) (Response, int) {
	switch req.Op {
	case OpStart:
		if req.Params == nil {
			return Response{Error: "StartTunnel без параметров"}, -1
		}
		p := *req.Params
		h, err := s.m.Start(p, c.Peer())
		if err != nil {
			return Response{Error: err.Error()}, -1
		}
		s.setOwner(c)
		return s.handleResponse(h)

	case OpAttach:
		h, err := s.m.Attach(req.Token, c.Peer())
		if err != nil {
			// Причина не уточняется: различать «не тот токен» и «не тот
			// владелец» значит помогать подбирать. Дедлайн от неудачи не
			// двигается (§3.1) — это уже обеспечено машиной.
			s.log.Debug("ipc: Attach отвергнут", "peer", c.Peer(), "err", err)
			return Response{Error: err.Error()}, -1
		}
		s.setOwner(c)
		return s.handleResponse(h)

	case OpStop:
		// По личности, а не по соединению: `hop -down` — отдельный процесс с
		// новым соединением, владельцем оно не бывает никогда.
		if err := s.m.StopBy(c.Peer()); err != nil {
			return Response{Error: err.Error()}, -1
		}
		// Туннеля больше нет, и прежнее соединение-владелец больше ничем не
		// владеет: его обрыв не должен звать AgentGone.
		s.dropOwner()
		return Response{}, -1

	case OpDetach:
		// Detach и Heartbeat агент шлёт тем же соединением, которое получило
		// туннель, поэтому здесь сверяется именно оно. Посторонний процесс того
		// же пользователя иначе роняет чужой туннель в orphaned — а там §6.2
		// поднимает респондер, и живой агент делит дескриптор с ним.
		if !s.isOwner(c) {
			return Response{Error: "Detach не от владельца туннеля"}, -1
		}
		s.m.Detach(req.Reason)
		s.clearOwner(c)
		return Response{}, -1

	case OpHeartbeat:
		// Тот же гейт: посторонний, обновляющий lastBeat, маскирует заклинивший
		// агент и отменяет heartbeat_miss (§6.2).
		if !s.isOwner(c) {
			return Response{Error: "Heartbeat не от владельца туннеля"}, -1
		}
		s.m.Heartbeat()
		return Response{}, -1

	case OpStatus:
		st := s.m.State()
		return Response{State: &st}, -1

	default:
		return Response{Error: "неизвестная операция " + string(req.Op)}, -1
	}
}

// handleResponse собирает ответ на StartTunnel/Attach: токен, Ref устройства и
// сам дескриптор, если ОС умеет его передавать.
func (s *Server) handleResponse(h tunnel.Handle) (Response, int) {
	resp := Response{Token: h.Token, Device: h.Device.Ref()}
	if src, ok := h.Device.(FDSource); ok {
		resp.HasFD = true
		return resp, src.Fd()
	}
	return resp, -1
}

func (s *Server) reply(c Conn, resp Response, fd int) error {
	body, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return c.Send(body, fd)
}

func (s *Server) setOwner(c Conn) {
	s.mu.Lock()
	s.owner = c
	s.mu.Unlock()
}

func (s *Server) clearOwner(c Conn) {
	s.mu.Lock()
	if s.owner == c {
		s.owner = nil
	}
	s.mu.Unlock()
}

// dropOwner снимает владельца, каким бы соединением он ни был: туннеля больше
// нет, и владеть нечем.
func (s *Server) dropOwner() {
	s.mu.Lock()
	s.owner = nil
	s.mu.Unlock()
}

// isOwner — то ли это соединение, которому принадлежит туннель.
func (s *Server) isOwner(c Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.owner == c
}

// ownerGone — то самое ребро. Обрыв постороннего соединения (например,
// `hop status`) ничего не двигает: туннелем владеет ровно одно соединение.
func (s *Server) ownerGone(c Conn) {
	s.mu.Lock()
	owner := s.owner == c
	if owner {
		s.owner = nil
	}
	s.mu.Unlock()
	if owner {
		s.m.AgentGone(tunnel.ReasonClosed)
	}
}
