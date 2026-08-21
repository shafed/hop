package main

import "testing"

// noEnv — машина без единой переменной: так выглядит агент под systemd, где
// окружения пользователя нет вовсе.
func noEnv(string) string { return "" }

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// §2 и §6.8: под системным пользователем `hop` стор агента лежит в системном
// каталоге, а не в `$HOME` того, кто запустил CLI, — своего `$HOME` у агента
// нет, а в чужой он не пишет.
//
// Только Linux. Защита от петли там выражена правилом по UID-диапазону, и
// собственный UID агенту нужен именно для неё (§6.8); на macOS и Windows петлю
// режет привязка сокета, отдельная личность агенту не нужна, и стор остаётся
// пользовательским. Отклонение записано в notes (C27).
func TestStoreDirIsSystemOnLinux(t *testing.T) {
	if got := storeDir("linux", noEnv); got != "/var/lib/hop" {
		t.Fatalf("стор на linux — %q, ожидался /var/lib/hop", got)
	}

	user := envOf(map[string]string{"HOME": "/home/ivan"})
	if got := storeDir("darwin", user); got != "/home/ivan/.local/share/hop" {
		t.Fatalf("стор на darwin — %q, ожидался пользовательский", got)
	}

	// HOP_STORE перебивает всё: им пользуются стенд и отладка.
	forced := envOf(map[string]string{"HOP_STORE": "/tmp/hop-store", "HOME": "/home/ivan"})
	for _, goos := range []string{"linux", "darwin", "windows"} {
		if got := storeDir(goos, forced); got != "/tmp/hop-store" {
			t.Fatalf("%s: HOP_STORE не подействовал: %q", goos, got)
		}
	}
}

// Attach-token лежит не рядом с сокетом, а в приватном каталоге агента.
//
// §6.14: членство в группе `hop` даёт доступ к сокету, но не к каталогу
// агента. Сокет открыт группе, и токен в том же каталоге открылся бы ей
// заодно — а он позволяет перехватить туннель у живого агента (§3.1).
func TestTokenFileIsNotBesideTheSocket(t *testing.T) {
	tok := tokenFile("linux", noEnv)
	sock := agentSocket("linux", noEnv)
	if tok == sock {
		t.Fatal("токен и сокет — один путь")
	}
	if dirOf(tok) == dirOf(sock) {
		t.Fatalf("токен %q лежит в каталоге сокета %q: группа `hop` прочтёт его вместе с сокетом", tok, sock)
	}
}

// §3.3: сокет агента — на общем пути, а не в каталоге пользователя. Под своим
// UID агент до `$XDG_RUNTIME_DIR` клиента не дотянется.
func TestAgentSocketIsSharedOnLinux(t *testing.T) {
	runtimeDir := envOf(map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"})
	if got := agentSocket("linux", runtimeDir); got != "/run/hop/agent.sock" {
		t.Fatalf("сокет агента — %q, ожидался /run/hop/agent.sock", got)
	}

	// macOS: агент остался пользовательским, и сокет вместе с ним.
	if got := agentSocket("darwin", runtimeDir); got == "/run/hop/agent.sock" {
		t.Fatalf("на darwin сокет уехал на системный путь: %q", got)
	}
}
