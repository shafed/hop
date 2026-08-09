package ipc

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/shafed/hop/internal/tunnel"
)

// Client — сторона агента.
//
// Соединение живёт всё время работы туннеля: его закрытие и есть сигнал
// сервису (§6.2). Поэтому «переподключиться на каждый вызов» здесь не просто
// неэффективно — это ложное срабатывание ребра.
type Client struct {
	mu sync.Mutex
	c  Conn
}

// Connect подключается к сервису.
func Connect(path string) (*Client, error) {
	c, err := Dial(path)
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

func (cl *Client) Close() error { return cl.c.Close() }

// Result — ответ на StartTunnel или Attach.
type Result struct {
	Token  tunnel.Token
	Device string
	// FD — дескриптор TUN, приехавший через SCM_RIGHTS. -1 на Windows: там
	// устройство приезжает трубой с именем Device (§3.2).
	FD int
}

// Start — StartTunnel(TunnelParams).
func (cl *Client) Start(p tunnel.Params) (Result, error) {
	return cl.handshake(Request{Op: OpStart, Params: &p})
}

// Attach — реаттач по токену.
func (cl *Client) Attach(t tunnel.Token) (Result, error) {
	return cl.handshake(Request{Op: OpAttach, Token: t})
}

func (cl *Client) handshake(req Request) (Result, error) {
	resp, fd, err := cl.call(req)
	if err != nil {
		return Result{}, err
	}
	if fd < 0 && resp.HasFD {
		return Result{}, errors.New("ipc: сервис обещал дескриптор, но не прислал его")
	}
	return Result{Token: resp.Token, Device: resp.Device, FD: fd}, nil
}

func (cl *Client) Stop() error      { _, _, err := cl.call(Request{Op: OpStop}); return err }
func (cl *Client) Heartbeat() error { _, _, err := cl.call(Request{Op: OpHeartbeat}); return err }
func (cl *Client) Detach(r tunnel.Reason) error {
	_, _, err := cl.call(Request{Op: OpDetach, Reason: r})
	return err
}

// Status — TunnelState (§3.1).
func (cl *Client) Status() (tunnel.State, error) {
	resp, _, err := cl.call(Request{Op: OpStatus})
	if err != nil {
		return tunnel.State{}, err
	}
	if resp.State == nil {
		return tunnel.State{}, errors.New("ipc: пустой Status")
	}
	return *resp.State, nil
}

func (cl *Client) call(req Request) (Response, int, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return Response{}, -1, err
	}

	cl.mu.Lock()
	defer cl.mu.Unlock()

	if err := cl.c.Send(body, -1); err != nil {
		return Response{}, -1, err
	}
	raw, fd, err := cl.c.Recv()
	if err != nil {
		return Response{}, -1, err
	}
	var resp Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Response{}, -1, err
	}
	if resp.Error != "" {
		return resp, fd, errors.New(resp.Error)
	}
	return resp, fd, nil
}
