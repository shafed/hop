//go:build !windows

package store

import (
	"errors"

	"golang.org/x/sys/unix"
)

// try — одна неблокирующая попытка взять flock. false без ошибки означает
// «занято», и ждать этого решает acquire.
//
// flock, а не fcntl-замок: fcntl снимается при закрытии любого дескриптора
// того же файла в процессе, и одна невнимательная функция, открывшая и
// закрывшая замок, молча отпустила бы чужую транзакцию.
func (l *fileLock) try() (bool, error) {
	err := unix.Flock(int(l.f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.EWOULDBLOCK):
		return false, nil
	default:
		return false, err
	}
}

// release отпускает замок, не закрывая файл: следующая транзакция того же
// процесса возьмёт его снова.
func (l *fileLock) release() {
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
}
