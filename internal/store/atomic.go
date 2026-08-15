package store

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// tempSuffix — по нему опознаётся временный файл записи. Он же — единственная
// примета, по которой Open отличает мусор, оставшийся от убитого процесса, от
// настоящих файлов стора.
const tempSuffix = ".tmp-"

// tempFile — файл, который атомарная запись наполняет и синхронизирует.
// Интерфейс, а не *os.File, ровно ради требования 6 регистра
// (docs/verification-store.md §2): отказ обязан инъектироваться в назначенную
// точку, а не изображаться убийством процесса в надежде попасть в окно.
type tempFile interface {
	io.Writer
	Sync() error
	Close() error
	// Name — путь, по которому файл лежит прямо сейчас. Для атомарной записи
	// это временное имя, для записи на месте — конечное.
	Name() string
}

// createFunc — «создать временный файл» из требования 6 регистра.
type createFunc func(dir, base string, perm fs.FileMode) (tempFile, error)

// renameFunc — «переименовать» оттуда же.
type renameFunc func(oldpath, newpath string) error

// writer — единственное место этапа, где имеет значение, какая под нами
// файловая система (§4 регистра). Три системных вызова на файл — временный
// файл, fsync файла, rename — плюс fsync каталога на Unix; всё это собрано
// здесь, а не размазано по вызовам, поэтому и подменяется одним куском.
//
// Обе функции — поля, а не вызовы напрямую: тест подменяет их, оборачивая
// прежние, и получает отказ ровно там, где хочет (S25, S26).
type writer struct {
	dir    string
	create createFunc
	rename renameFunc
}

// newWriter собирает слой записи. atomic снимается из политики один раз при
// Open: горячего места здесь нет, но и смысла спрашивать флаг на каждой записи
// тоже.
func newWriter(dir string, atomic bool) *writer {
	create := createTemp
	if !atomic {
		// Политика atomic_write выключена: файл открывается на месте, с
		// O_TRUNC, и любой отказ посреди записи виден снаружи как полуправда —
		// ровно то состояние, которого У4 не допускает. rename при этом
		// вырождается: временного имени нет, переименовывать нечего.
		create = createInPlace
	}
	return &writer{dir: dir, create: create, rename: os.Rename}
}

// write кладёт data в файл base с правами perm так, что читатель видит либо
// прежнее содержимое целиком, либо новое целиком (У4).
func (w *writer) write(base string, perm fs.FileMode, data []byte) (err error) {
	dst := filepath.Join(w.dir, base)

	f, err := w.create(w.dir, base, perm)
	if err != nil {
		return fmt.Errorf("store: не создать файл записи для %s: %w", base, err)
	}
	tmp := f.Name()
	defer func() {
		// Недописанный временный файл убирается сразу; если запись шла на
		// место, убирать нечего — там конечный файл.
		if err != nil && tmp != dst {
			_ = os.Remove(tmp)
		}
	}()

	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return fmt.Errorf("store: не записать %s: %w", base, werr)
	}
	// fsync файла до rename: без него переименование может пережить обрыв, а
	// содержимое — нет, и на месте прежнего состояния окажется пустой файл.
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return fmt.Errorf("store: не синхронизировать %s: %w", base, serr)
	}
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("store: не закрыть %s: %w", base, cerr)
	}
	// Права выставляются до появления файла под своим именем: иначе nodes.json
	// на мгновение виден с правами os.CreateTemp, а §6.14 не про «в основном
	// 0600».
	if cerr := os.Chmod(tmp, perm); cerr != nil {
		return fmt.Errorf("store: не выставить права %04o на %s: %w", perm, base, cerr)
	}
	if tmp != dst {
		if rerr := w.rename(tmp, dst); rerr != nil {
			return fmt.Errorf("store: не переименовать %s в %s: %w", filepath.Base(tmp), base, rerr)
		}
	}
	// fsync каталога: на Unix без него rename может пережить обрыв, а
	// появление имени в каталоге — нет (§4 регистра).
	return syncDir(w.dir)
}

// sweep убирает временные файлы, оставшиеся от процесса, убитого посреди
// записи (S26). Зовётся под замком стора: иначе уборка снесла бы временный
// файл чужой записи, идущей прямо сейчас.
func (w *writer) sweep() error {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return fmt.Errorf("store: не прочитать каталог %s: %w", w.dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !isTempName(e.Name()) {
			continue
		}
		if rerr := os.Remove(filepath.Join(w.dir, e.Name())); rerr != nil {
			return fmt.Errorf("store: не убрать временный файл %s: %w", e.Name(), rerr)
		}
	}
	return nil
}

// isTempName опознаёт временный файл только у известных имён стора: каталог
// пользовательский, и удалять из него всё, что похоже на временное, стор права
// не имеет.
func isTempName(name string) bool {
	for _, base := range []string{groupsFile, nodesFile, healthFile} {
		if strings.HasPrefix(name, base+tempSuffix) {
			return true
		}
	}
	return false
}

// createTemp — обычный путь: временный файл рядом с целевым, в том же
// каталоге, чтобы rename остался переименованием внутри одной файловой
// системы, а не копированием.
func createTemp(dir, base string, _ fs.FileMode) (tempFile, error) {
	f, err := os.CreateTemp(dir, base+tempSuffix+"*")
	if err != nil {
		return nil, err
	}
	return f, nil
}

// createInPlace — путь выключенной политики atomic_write.
func createInPlace(dir, base string, perm fs.FileMode) (tempFile, error) {
	f, err := os.OpenFile(filepath.Join(dir, base), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return nil, err
	}
	return f, nil
}
