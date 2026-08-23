//go:build !windows

package store

import (
	"fmt"
	"os"
)

// syncDir синхронизирует сам каталог. На Unix это обязательный четвёртый шаг
// записи: rename меняет каталог, и без его fsync обрыв питания может оставить
// переименование, но не появление содержимого (§4 регистра, §2 SPEC).
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("store: не открыть каталог %s для синхронизации: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("store: не синхронизировать каталог %s: %w", dir, err)
	}
	return nil
}
