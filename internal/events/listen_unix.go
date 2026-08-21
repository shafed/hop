//go:build unix

package events

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// listen поднимает сокет агента с правами §3.3: владелец всегда, группа `hop` —
// когда её назвали. Everyone-доступа не появляется ни на миг: umask сначала
// сужает до 0600, и только затем chmod расширяет до 0660 — и ни битом больше.
func listen(path string, gid int) (net.Listener, error) {
	old := unix.Umask(0o177) // всё, кроме rw для владельца
	l, err := net.Listen("unix", path)
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	if gid < 0 {
		return l, nil
	}
	if err := os.Chown(path, -1, gid); err != nil {
		l.Close()
		return nil, fmt.Errorf("группа сокета: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		l.Close()
		return nil, fmt.Errorf("права сокета: %w", err)
	}
	return l, nil
}
