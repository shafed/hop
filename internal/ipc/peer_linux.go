//go:build linux

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerOwner — UID процесса на том конце, взятый у ядра, а не со слов клиента.
// На нём стоит проверка владельца в Attach (§3.1).
func peerOwner(c *net.UnixConn) (string, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return "", err
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return "", err
	}
	if serr != nil {
		return "", fmt.Errorf("SO_PEERCRED: %w", serr)
	}
	return fmt.Sprintf("uid:%d", cred.Uid), nil
}
