//go:build darwin

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerOwner — UID процесса на том конце. На macOS это LOCAL_PEERCRED, тот же
// смысл, что у SO_PEERCRED на Linux: значение приходит от ядра, а не со слов
// клиента.
func peerOwner(c *net.UnixConn) (string, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return "", err
	}
	var cred *unix.Xucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return "", err
	}
	if serr != nil {
		return "", fmt.Errorf("LOCAL_PEERCRED: %w", serr)
	}
	return fmt.Sprintf("uid:%d", cred.Uid), nil
}
