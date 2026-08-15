// Стор не теряет данные — docs/verification-store.md §5.4, У4. Отказ здесь
// инъектируется в назначенную точку, а не изображается убийством процесса:
// тест, который зелен потому, что не попал в окно между fsync и rename, ничего
// не проверяет (§5.4, замечание к S25 и S26).
package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// errInjected — отказ, вставленный тестом. Своя ошибка, чтобы отличить его от
// настоящего отказа файловой системы.
var errInjected = errors.New("инъекция теста")

// brokenFile — временный файл, запись в который обрывается после limit байт.
// Оборачивает то, что создал бы стор сам, поэтому при выключенной политике
// atomic_write обрывается запись прямо в конечный файл — ровно та разница,
// которую проверяет S26.
type brokenFile struct {
	tempFile
	limit   int
	written int
}

func (b *brokenFile) Write(p []byte) (int, error) {
	left := b.limit - b.written
	if left <= 0 {
		return 0, errInjected
	}
	if left < len(p) {
		p = p[:left]
	}
	n, err := b.tempFile.Write(p)
	b.written += n
	if err != nil {
		return n, err
	}
	return n, errInjected
}

// failRename подменяет «переименовать»: точка отказа — сразу после fsync
// файла, до появления нового содержимого под своим именем.
func failRename(s *Store, base string) {
	prev := s.w.rename
	s.w.rename = func(oldpath, newpath string) error {
		if filepath.Base(newpath) == base {
			return errInjected
		}
		return prev(oldpath, newpath)
	}
}

// failWrite подменяет «создать временный файл»: точка отказа — середина записи
// содержимого, до fsync.
func failWrite(s *Store, base string, after int) {
	prev := s.w.create
	s.w.create = func(dir, name string, perm fs.FileMode) (tempFile, error) {
		f, err := prev(dir, name, perm)
		if err != nil || name != base {
			return f, err
		}
		return &brokenFile{tempFile: f, limit: after}, nil
	}
}

// TestS25FailureBetweenFsyncAndRenameKeepsOldState — S25.
func TestS25FailureBetweenFsyncAndRenameKeepsOldState(t *testing.T) {
	s, dir := newStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))
	if err := s.Flush(); err != nil {
		t.Fatalf("первая запись не прошла: %v", err)
	}
	before := string(readRaw(t, dir, nodesFile))

	addNode(t, s, node("n2", "g", "b.example"))
	failRename(s, nodesFile)

	if err := s.Flush(); !errors.Is(err, errInjected) {
		t.Fatalf("отказ rename не дошёл до вызывающего: %v", err)
	}

	if got := string(readRaw(t, dir, nodesFile)); got != before {
		t.Errorf("на диске третье состояние: ни прежнее целиком, ни новое целиком\n%s", got)
	}

	s2 := openStore(t, dir)
	if _, ok := s2.Node("n2"); ok {
		t.Error("узел, запись которого оборвалась, виден после перезапуска")
	}
	if _, ok := s2.Node("n1"); !ok {
		t.Error("прежний узел потерян: оборванная запись унесла с собой прежнее состояние")
	}
}

// TestS26FailureWhileWritingTempKeepsMainFile — S26.
func TestS26FailureWhileWritingTempKeepsMainFile(t *testing.T) {
	s, dir := newStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))
	if err := s.Flush(); err != nil {
		t.Fatalf("первая запись не прошла: %v", err)
	}
	before := string(readRaw(t, dir, nodesFile))

	addNode(t, s, node("n2", "g", "b.example"))
	failWrite(s, nodesFile, 8)

	if err := s.Flush(); !errors.Is(err, errInjected) {
		t.Fatalf("отказ записи не дошёл до вызывающего: %v", err)
	}

	if got := string(readRaw(t, dir, nodesFile)); got != before {
		t.Errorf("основной файл пострадал от обрыва записи временного\n%s", got)
	}

	// Мусорный временный файл, оставшийся от процесса, убитого посреди записи:
	// сам стор свой временный убирает, а убитый — нет.
	garbage := filepath.Join(dir, nodesFile+tempSuffix+"убитыйпроцесс")
	if err := os.WriteFile(garbage, []byte("обрубок"), secretPerm); err != nil {
		t.Fatalf("не подложить мусор: %v", err)
	}

	// Первый стор намеренно не закрывается: у него в грязных так и осталась
	// не записанная секция узлов, и закрытие снова упёрлось бы в инъекцию.
	s2 := openStore(t, dir)
	if _, err := os.Stat(garbage); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("временный файл убитого процесса не убран при открытии: %v", err)
	}
	if _, ok := s2.Node("n2"); ok {
		t.Error("узел, запись которого оборвалась, виден после перезапуска")
	}
	if _, ok := s2.Node("n1"); !ok {
		t.Error("прежний узел потерян: оборванная запись унесла с собой прежнее состояние")
	}
}
