package ipc

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// DefaultPath — управляющая граница по умолчанию (§3.1).
var DefaultPath = defaultPath()

func defaultPath() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\hop`
	}
	return "/run/hop.sock"
}

// DefaultClientPath — граница «клиенты ↔ агент» (§3.3).
//
// Отдельный путь, а не второй слушатель на `/run/hop.sock`: §3.3 требует
// сокета **в каталоге пользователя**, и это не косметика. Управляющая граница
// живёт в системном каталоге и открыта группе (агенту под обычным
// пользователем нужен доступ к сервису под root); клиентская принадлежит
// одному пользователю целиком, и путь в его runtime-каталоге — единственное
// место, где право «мой и больше ничей» даёт сама файловая система, а не наша
// проверка.
//
// Runtime-каталог, а не каталог конфигурации, где лежит стор: сокет — не
// настройка, он не переживает логин и обязан исчезать вместе с сессией.
// XDG_RUNTIME_DIR ровно это и означает; там же лежит attach-token (§6.14).
//
// Запасной путь — подкаталог временного каталога с UID в имени. UID именно в
// имени, а не только в правах: без него первый пользователь машины занял бы
// `/tmp/hop`, а второй получил бы отказ на ровном месте.
var DefaultClientPath = defaultClientPath()

func defaultClientPath() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\hop-agent`
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "hop", "agent.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("hop-%d", os.Getuid()), "agent.sock")
}
