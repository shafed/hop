package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/shafed/hop/internal/tunnel"
)

// Где лежит attach-token — в paths.go вместе с остальными путями агента.

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
