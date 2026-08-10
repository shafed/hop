//go:build unix

package ipc

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Listen поднимает unix-сокет, доступный владельцу и группе gid (§3.1, §6.1).
//
// Группа нужна потому, что стороны границы живут под разными пользователями:
// сервис под root (ему нужен /dev/net/tun и ip), агент — под обычным. Сокет
// только для владельца означал бы EACCES у агента, а заодно ломал бы §6.8:
// подключиться смог бы один root, и peerUID вернул бы 0, то есть правило с
// UID-диапазоном вывело бы из туннеля весь root-трафик вместо агентского.
//
// gid < 0 — группу не трогать: сокет остаётся доступен одному владельцу.
//
// Порядок прав важен. Сначала umask даёт 0600, и только потом доступ
// расширяется до группы: в промежутке сокет уже, чем задуман, а не шире.
// Обратный порядок оставил бы окно, в котором он доступен лишним.
func Listen(path string, gid int) (Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	old := unix.Umask(0o177) // всё, кроме rw для владельца
	l, err := net.Listen("unix", path)
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	if gid >= 0 {
		if err := chownGroup(path, gid); err != nil {
			l.Close()
			return nil, err
		}
	}
	return &unixListener{l: l.(*net.UnixListener)}, nil
}

// chownGroup отдаёт сокет группе и открывает ей rw. Everyone-доступа не
// появляется ни на миг: 0660, и ни битом больше (§6.1).
func chownGroup(path string, gid int) error {
	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("ipc: группа сокета: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return fmt.Errorf("ipc: права сокета: %w", err)
	}
	return nil
}

type unixListener struct{ l *net.UnixListener }

func (u *unixListener) Accept() (Conn, error) {
	c, err := u.l.AcceptUnix()
	if err != nil {
		return nil, err
	}
	return newUnixConn(c)
}

func (u *unixListener) Close() error { return u.l.Close() }

// Dial подключается к сокету сервиса.
func Dial(path string) (Conn, error) {
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	return newUnixConn(c.(*net.UnixConn))
}

type unixConn struct {
	uc   *net.UnixConn
	peer string

	fr   frames
	fds  []int
	rbuf []byte
	oob  []byte
}

func newUnixConn(c *net.UnixConn) (Conn, error) {
	peer, err := peerOwner(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &unixConn{
		uc:   c,
		peer: peer,
		rbuf: make([]byte, 8192),
		oob:  make([]byte, unix.CmsgSpace(4)),
	}, nil
}

func (c *unixConn) Peer() string { return c.peer }
func (c *unixConn) Close() error { return c.uc.Close() }

func (c *unixConn) Send(body []byte, fd int) error {
	frame, err := encodeFrame(body)
	if err != nil {
		return err
	}
	if fd < 0 {
		_, err = c.uc.Write(frame)
		return err
	}
	_, _, err = c.uc.WriteMsgUnix(frame, unix.UnixRights(fd), nil)
	return err
}

// Recv собирает кадр из потока, попутно забирая дескрипторы.
//
// Кадр и дескриптор приезжают одним sendmsg, поэтому дескриптор не может
// опередить свой кадр. Обратный порядок — кадр без своего дескриптора —
// возможен только при конвейере из нескольких ответов подряд, которого в §3.1
// нет: запрос и ответ строго чередуются.
func (c *unixConn) Recv() ([]byte, int, error) {
	for {
		body, err := c.fr.next()
		if err != nil {
			return nil, -1, err
		}
		if body != nil {
			fd := -1
			if len(c.fds) > 0 {
				fd, c.fds = c.fds[0], c.fds[1:]
			}
			return body, fd, nil
		}

		n, oobn, _, _, err := c.uc.ReadMsgUnix(c.rbuf, c.oob)
		if n > 0 {
			c.fr.feed(c.rbuf[:n])
		}
		if oobn > 0 {
			if err := c.collectFDs(c.oob[:oobn]); err != nil {
				return nil, -1, err
			}
		}
		if err != nil {
			return nil, -1, err
		}
		if n == 0 && oobn == 0 {
			return nil, -1, io.EOF
		}
	}
}

func (c *unixConn) collectFDs(oob []byte) error {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return fmt.Errorf("ipc: разбор ancillary: %w", err)
	}
	for _, m := range msgs {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			continue // не SCM_RIGHTS
		}
		c.fds = append(c.fds, fds...)
	}
	return nil
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
