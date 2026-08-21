package main

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/shafed/hop/internal/events"
)

// Пути агента: где стор, где attach-token, где сокет клиентов.
//
// ОС здесь аргумент, а не build tag, и окружение спрашивается через функцию:
// решение — данные, и проверяется на любой машине. Тот же приём, что в
// internal/loopguard, и по той же причине (§8).
//
// Развилка по ОС не косметическая. На Linux агент работает под системным
// пользователем `hop` (§1 С1): защита от петли выражена там правилом по
// UID-диапазону, и собственный UID агенту нужен именно для неё (§6.8). Своего
// `$HOME` у такого агента нет, в чужой он не пишет, и стор с сокетом уезжают на
// системные пути. На macOS и Windows петлю режет привязка сокета к интерфейсу,
// отдельная личность агенту не нужна — там всё остаётся пользовательским
// (отклонение C27).

// systemStoreDir — §2: системный каталог агента. Права 0700 и владельца `hop`
// ставит инсталлятор (StateDirectory юнита), а сам стор подтверждает 0700 при
// открытии (§6.14).
const systemStoreDir = "/var/lib/hop"

// systemRuntimeDir — общий каталог агента в /run. Заводит его systemd
// (RuntimeDirectory=hop): под своим UID агент в /run не пишет.
const systemRuntimeDir = "/run/hop"

func defaultStoreDir() string  { return storeDir(runtime.GOOS, os.Getenv) }
func defaultTokenFile() string { return tokenFile(runtime.GOOS, os.Getenv) }

// storeDir — каталог стора агента (§2).
func storeDir(goos string, env func(string) string) string {
	if dir := env("HOP_STORE"); dir != "" {
		return dir
	}
	if goos == "linux" {
		return systemStoreDir
	}
	if dir := env("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "hop")
	}
	return filepath.Join(homeOf(env), ".local", "share", "hop")
}

// tokenFile — где лежит attach-token.
//
// Attach-token переживает `kill -9` агента, потому что иначе его незачем
// заводить: реаттач (T24) по определению делает **новый процесс**, а память
// убитого ему недоступна. Отсюда файл — но с оговорками §6.14: каталог 0700,
// файл 0600, в логи не попадает ни на debug (за это отвечает тип
// tunnel.Token), сервису не передаётся никуда, кроме самого Attach, и в вывод
// status не входит.
//
// Каталог — **не** тот, где лежит сокет. Сокет открыт группе `hop` (§3.3), и
// токен рядом с ним открылся бы ей заодно; §6.14 требует ровно обратного —
// членство в группе даёт сокет, но не каталог агента. Токеном же можно
// перехватить туннель у живого агента (§3.1).
func tokenFile(goos string, env func(string) string) string {
	if goos == "linux" {
		return filepath.Join(systemRuntimeDir, "agent", "attach-token")
	}
	return filepath.Join(userRuntimeDir(env), "hop", "attach-token")
}

// agentSocket — сокет клиентов агента (§3.3). Путь считает events: его знают
// обе стороны границы, и разойтись они не имеют права.
func agentSocket(goos string, env func(string) string) string {
	return events.SocketPath(goos, env)
}

func userRuntimeDir(env func(string) string) string {
	if dir := env("XDG_RUNTIME_DIR"); dir != "" {
		return dir
	}
	return os.TempDir()
}

func homeOf(env func(string) string) string {
	if home := env("HOME"); home != "" {
		return home
	}
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	return os.TempDir()
}

func dirOf(path string) string { return filepath.Dir(path) }
