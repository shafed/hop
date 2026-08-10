//go:build windows

package ipc

import (
	"fmt"
	"io"
	"net"
	"runtime"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// sddl — дескриптор безопасности трубы, заданный **явно** (§3.1).
//
//	D:P            — DACL, наследование запрещено
//	(A;;GA;;;SY)   — LocalSystem: полный доступ (под ним живёт сервис)
//	(A;;GA;;;BA)   — администраторы: полный доступ
//	(A;;GRGW;;;IU) — интерактивные пользователи: чтение и запись
//
// IU, а не SID слушателя. Прежде сюда подставлялся currentSID() сервиса, то
// есть LocalSystem, и агент обычного пользователя получал ERROR_ACCESS_DENIED —
// подключиться к своему же сервису он не мог вовсе.
//
// Право открыть трубу даётся классу, а владение конкретным туннелем держит
// проверка личности в Attach (§3.1): SID меряется на каждом соединении, поэтому
// широкий ACE не даёт перехватить чужой туннель.
//
// Умолчания named pipe дают доступ Everyone; §6.1 — про ровно эту ошибку у
// hiddify, только на TCP. Явный SDDL — единственный способ не повторить её.
const sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

// Listen поднимает named pipe, доступный LocalSystem, администраторам и
// интерактивным пользователям. gid — часть общей сигнатуры с Unix; групп в
// понимании Unix на Windows нет, доступ целиком задаёт SDDL.
func Listen(path string, gid int) (Listener, error) {
	_ = gid
	l, err := winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		MessageMode:        false,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
	if err != nil {
		return nil, err
	}
	return &pipeListener{l: l}, nil
}

type pipeListener struct {
	l net.Listener
}

// Accept снимает SID клиента у ядра на каждом соединении. Прежде сюда ехал SID
// слушателя, то есть самого сервиса, и сверка владельца в Attach (§3.1)
// сравнивала сервис с самим собой — то есть не проверяла ничего.
func (p *pipeListener) Accept() (Conn, error) {
	for {
		c, err := p.l.Accept()
		if err != nil {
			return nil, err
		}
		sid, err := clientSID(c)
		if err != nil {
			// Отказ одному клиенту, а не остановка сервиса: ошибка из Accept
			// разматывает Serve, и клиент, отваливающийся до олицетворения,
			// уносил бы с собой всю управляющую границу.
			c.Close()
			continue
		}
		return &pipeConn{c: c, peer: "sid:" + sid, rbuf: make([]byte, 8192)}, nil
	}
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

// clientSID — SID процесса на том конце трубы, снятый у ядра олицетворением.
// Windows-аналог SO_PEERCRED из peer_linux.go: личность меряется, а не
// принимается со слов клиента.
func clientSID(c net.Conn) (string, error) {
	h, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return "", fmt.Errorf("ipc: труба не отдаёт хендл, SID клиента не снять")
	}

	type result struct {
		sid string
		err error
	}
	done := make(chan result, 1)

	// Олицетворение живёт на потоке ОС, а не на горутине, поэтому снимается на
	// отдельной горутине с привязкой к потоку. Если RevertToSelf не сработает,
	// поток не отпускается: вернуть в пул поток с чужим токеном значит раздать
	// олицетворение остальным горутинам привилегированного сервиса. Такой поток
	// умрёт вместе с горутиной.
	go func() {
		runtime.LockOSThread()

		if err := impersonateNamedPipeClient(windows.Handle(h.Fd())); err != nil {
			runtime.UnlockOSThread() // олицетворения нет, поток чист
			done <- result{"", fmt.Errorf("ImpersonateNamedPipeClient: %w", err)}
			return
		}

		sid, err := impersonatedUserSID()

		if rerr := windows.RevertToSelf(); rerr != nil {
			done <- result{"", fmt.Errorf("ipc: RevertToSelf: %w", rerr)}
			return
		}
		runtime.UnlockOSThread()
		done <- result{sid, err}
	}()

	r := <-done
	return r.sid, r.err
}

// impersonatedUserSID читает пользователя из токена потока. Зовётся только под
// олицетворением, иначе вернёт SID самого сервиса.
func impersonatedUserSID() (string, error) {
	var tok windows.Token
	// openAsSelf=true: доступ к токену проверяется по токену процесса, а не по
	// олицетворению — иначе клиент с урезанными правами закрывает сервису
	// доступ к тому, что сервис же и открывает.
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok); err != nil {
		return "", fmt.Errorf("OpenThreadToken: %w", err)
	}
	defer tok.Close()

	u, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("GetTokenUser: %w", err)
	}
	return u.User.Sid.String(), nil
}

// x/sys/windows этот вызов не обёртывает, поэтому привязка вручную.
var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").
	NewProc("ImpersonateNamedPipeClient")

func impersonateNamedPipeClient(h windows.Handle) error {
	r, _, err := procImpersonateNamedPipeClient.Call(uintptr(h))
	if r == 0 {
		return err
	}
	return nil
}
