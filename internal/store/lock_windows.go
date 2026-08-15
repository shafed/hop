package store

import (
	"errors"

	"golang.org/x/sys/windows"
)

// try — одна попытка взять эксклюзивный замок на первом байте файла.
// LOCKFILE_FAIL_IMMEDIATELY делает её неблокирующей, а ERROR_LOCK_VIOLATION —
// это «занято», а не отказ.
//
// Байтовый замок, а не открытие файла без разделения доступа: замок снимается
// явно и переживает повторные транзакции одного процесса, тогда как повторное
// открытие пришлось бы делать на каждую из них.
func (l *fileLock) try() (bool, error) {
	err := windows.LockFileEx(windows.Handle(l.f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, new(windows.Overlapped))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, windows.ERROR_LOCK_VIOLATION):
		return false, nil
	default:
		return false, err
	}
}

// release отпускает замок, не закрывая файл.
func (l *fileLock) release() {
	_ = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, new(windows.Overlapped))
}
