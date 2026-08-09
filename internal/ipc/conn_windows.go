//go:build windows

package ipc

import (
	"fmt"
	"io"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// sddl — дескриптор безопасности трубы, заданный **явно** (§3.1).
//
//	D:P            — DACL, наследование запрещено
//	(A;;GA;;;SY)   — LocalSystem: полный доступ (под ним живёт сервис)
//	(A;;GA;;;BA)   — администраторы: полный доступ
//	(A;;GRGW;;;%s) — владелец туннеля: чтение и запись, и больше никто
//
// Умолчания named pipe дают доступ Everyone; §6.1 — про ровно эту ошибку у
// hiddify, только на TCP. Явный SDDL — единственный способ не повторить её.
func sddl(ownerSID string) string {
	return fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;%s)", ownerSID)
}

// Listen поднимает named pipe, доступный только LocalSystem, администраторам и
// владельцу туннеля.
func Listen(path string) (Listener, error) {
	sid, err := currentSID()
	if err != nil {
		return nil, err
	}
	l, err := winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: sddl(sid),
		MessageMode:        false,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
	if err != nil {
		return nil, err
	}
	return &pipeListener{l: l, peer: "sid:" + sid}, nil
}

type pipeListener struct {
	l    net.Listener
	peer string
}

func (p *pipeListener) Accept() (Conn, error) {
	c, err := p.l.Accept()
	if err != nil {
		return nil, err
	}
	return &pipeConn{c: c, peer: p.peer, rbuf: make([]byte, 8192)}, nil
}

func (p *pipeListener) Close() error { return p.l.Close() }

// Dial подключается к трубе сервиса.
func Dial(path string) (Conn, error) {
	c, err := winio.DialPipe(path, nil)
	if err != nil {
		return nil, err
	}
	sid, err := currentSID()
	if err != nil {
		c.Close()
		return nil, err
	}
	return &pipeConn{c: c, peer: "sid:" + sid, rbuf: make([]byte, 8192)}, nil
}

type pipeConn struct {
	c    net.Conn
	peer string
	fr   frames
	rbuf []byte
}

func (p *pipeConn) Peer() string { return p.peer }
func (p *pipeConn) Close() error { return p.c.Close() }

// Send — fd на Windows не передаётся: Wintun это хендл драйвера с кольцевым
// буфером, привязанный к процессу-владельцу адаптера (§3.2). Устройство
// приезжает агенту трубой данных, имя которой лежит в Response.Device.
func (p *pipeConn) Send(body []byte, fd int) error {
	if fd >= 0 {
		return fmt.Errorf("ipc: передача дескриптора на Windows невозможна (§3.2)")
	}
	frame, err := encodeFrame(body)
	if err != nil {
		return err
	}
	_, err = p.c.Write(frame)
	return err
}

func (p *pipeConn) Recv() ([]byte, int, error) {
	for {
		body, err := p.fr.next()
		if err != nil {
			return nil, -1, err
		}
		if body != nil {
			return body, -1, nil
		}
		n, err := p.c.Read(p.rbuf)
		if n > 0 {
			p.fr.feed(p.rbuf[:n])
		}
		if err != nil {
			return nil, -1, err
		}
		if n == 0 {
			return nil, -1, io.EOF
		}
	}
}

func encodeFrame(body []byte) ([]byte, error) {
	if len(body) > maxFrame {
		return nil, fmt.Errorf("ipc: кадр %d байт, предел %d", len(body), maxFrame)
	}
	out := make([]byte, 4+len(body))
	out[0] = byte(len(body) >> 24)
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	copy(out[4:], body)
	return out, nil
}

func currentSID() (string, error) {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("GetTokenUser: %w", err)
	}
	return u.User.Sid.String(), nil
}
