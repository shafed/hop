package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time" //hop:realtime — только константы длительности, обращений к часам здесь нет

	"github.com/shafed/hop/internal/clock"
)

// lockTimeout — сколько второй писатель ждёт замок, прежде чем отказать
// (§4 регистра, Р14). Ждёт по часам стора, а не по настоящим: иначе проверка
// S28 стоила бы пяти секунд реального времени.
const lockTimeout = 5 * time.Second

// lockRetry — как часто повторяется попытка. flock не умеет ждать с
// таймаутом, поэтому ожидание собрано из неблокирующих попыток.
const lockRetry = 50 * time.Millisecond

// ErrLocked — стор занят другим процессом дольше lockTimeout. Отдельная
// ошибка, а не текст: Р14 требует, чтобы второй писатель падал внятно, и
// вызывающему нужно уметь отличить занятый стор от сломанного.
var ErrLocked = errors.New("store: стор занят другим процессом")

// fileLock — рекомендательный замок каталога стора (Р14): flock на Unix,
// LockFileEx на Windows. Рекомендательный означает, что он не защищает от
// программы, которая про него не знает, и не ловит гонку двух горутин одного
// процесса — от неё есть txMu в Store.
type fileLock struct {
	path string
	f    *os.File
}

// openLock создаёт (при необходимости) и открывает файл замка. Файл пустой:
// значение имеет только сам факт удержания.
func openLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, secretPerm)
	if err != nil {
		return nil, fmt.Errorf("store: не открыть замок %s: %w", path, err)
	}
	return &fileLock{path: path, f: f}, nil
}

// acquire ждёт замок до lockTimeout по часам clk и затем отказывает.
//
// Именно отказывает, а не пишет поверх: два процесса пишут в стор законно
// (Р14, C12), но по очереди, и потерянная запись здесь — это исчезнувшая
// подписка со всей историей проб.
func (l *fileLock) acquire(clk clock.Clock) error {
	deadline := clk.After(lockTimeout)
	for {
		ok, err := l.try()
		if err != nil {
			return fmt.Errorf("store: не взять замок %s: %w", l.path, err)
		}
		if ok {
			return nil
		}
		select {
		case <-deadline:
			return fmt.Errorf("%w: замок %s не освободился за %s — идёт другая команда hop или работает агент; дождитесь её окончания и повторите",
				ErrLocked, l.path, lockTimeout)
		case <-clk.After(lockRetry):
		}
	}
}

// close отпускает замок и закрывает файл. Файл остаётся в каталоге: удалять
// его нельзя, иначе два процесса возьмут замки на разных inode.
func (l *fileLock) close() error {
	if err := l.f.Close(); err != nil {
		return fmt.Errorf("store: не закрыть замок %s: %w", l.path, err)
	}
	return nil
}

// lockPath — путь к файлу замка в каталоге стора.
func lockPath(root string) string { return filepath.Join(root, lockFile) }
