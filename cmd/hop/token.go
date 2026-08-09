package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/shafed/hop/internal/tunnel"
)

// Attach-token переживает `kill -9` агента, потому что иначе его незачем
// заводить: реаттач (T24) по определению делает **новый процесс**, а память
// убитого ему недоступна.
//
// Отсюда файл — но с оговорками §6.14: каталог 0700, файл 0600, в логи не
// попадает ни на debug (за это отвечает тип tunnel.Token), сервису не
// передаётся никуда, кроме самого Attach, и в вывод status не входит.
// Подробнее — «Deviations» в implementation-notes.md.
func defaultTokenFile() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "hop", "attach-token")
}

func loadToken(path string) (tunnel.Token, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return tunnel.Token(strings.TrimSpace(string(b))), nil
}

func saveToken(path string, t tunnel.Token) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// 0600 задаётся при создании, а не chmod-ом после: между созданием и
	// chmod был бы момент, когда файл читается всеми.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(string(t)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func removeToken(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
