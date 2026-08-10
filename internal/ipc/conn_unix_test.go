//go:build unix

package ipc

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Права сокета — это и есть аутентификация IPC на Unix (§6.1). Стороны границы
// живут под разными пользователями: сервис под root, агент под обычным, — и без
// группы агент получает EACCES. Открыть сокет всем нельзя тем более: ровно за
// это §6.1 поминает hiddify.
func TestSocketPermissions(t *testing.T) {
	for _, tc := range []struct {
		name string
		gid  int
		want os.FileMode
	}{
		{"с группой агента", os.Getgid(), 0o660},
		{"без группы", -1, 0o600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hop.sock")
			l, err := Listen(path, tc.gid)
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer l.Close()

			fi, err := os.Stat(path)
			if err != nil {
				t.Fatalf("Stat: %v", err)
			}
			if got := fi.Mode().Perm(); got != tc.want {
				t.Fatalf("права = %04o, ожидались %04o", got, tc.want)
			}
			if got := fi.Mode().Perm() & 0o007; got != 0 {
				t.Fatalf("права = %04o: сокет открыт посторонним", fi.Mode().Perm())
			}
			if tc.gid >= 0 {
				st, ok := fi.Sys().(*syscall.Stat_t)
				if !ok {
					t.Fatal("Stat_t недоступен")
				}
				if int(st.Gid) != tc.gid {
					t.Fatalf("gid сокета = %d, ожидался %d", st.Gid, tc.gid)
				}
			}
		})
	}
}
