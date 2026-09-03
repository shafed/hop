//go:build unix

// Тесты `cmd/hop`, которым нужен настоящий flock.
//
// Отдельный файл с тегом `unix`, а не общий clients_test.go: замок стора на
// Unix — это flock (`internal/store/lock_unix.go`), и на Windows его нет ни у
// стора, ни в `golang.org/x/sys/unix`. Пока тест лежал в файле без тега,
// `go vet ./...` на Windows падал с «undefined: unix.Flock» — то есть шаг
// l3-windows в CI был красным не из-за датаплейна, которого там ещё нет, а
// из-за тестового файла. Замер: `internal\engine\dialer.go` и следом
// `vet.exe: cmd\hop\clients_test.go:500:17: undefined: unix.Flock`, прогон
// l3-windows 33603152058.
//
// Windows-половина этого утверждения приедет вместе с замком стора для
// Windows, а не раньше: писать её на несуществующем механизме нечем.

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shafed/hop/internal/store"
	"golang.org/x/sys/unix"
)

// TestW65ReadingCommandDoesNotLieAboutItsOwnSuccess — читающая команда при
// занятом сторе отвечает и отдаёт ноль, а не печатает ответ и падает следом.
//
// Замер на живом бинаре, из-за которого этот тест написан: пока чужой процесс
// держал `.lock`, `hop nodes` печатал все 201 строку ответа, ждал пять секунд
// и возвращал код 1. Чтение стора идёт БЕЗ замка (store.load), а Close брал
// его безусловно — то есть отказ приходил уже после того, как команда сделала
// своё дело. Для мониторинга вокруг кодов возврата (§5.9) это худший вид
// ошибки: код говорит «утилита упала», а вывод при этом полон и верен.
//
// Замок здесь берётся тем же flock, каким его берёт стор (internal/store,
// lock_unix.go): дефект межпроцессный, и второй *store.Store в этом же
// процессе его не воспроизводит.
func TestW65ReadingCommandDoesNotLieAboutItsOwnSuccess(t *testing.T) {
	root := withTestStore(t)
	if err := withStore(func(st *store.Store) error {
		return addNode(st, "vless://"+uuidA+"@a.example:443?type=ws&security=tls#узел", io.Discard)
	}); err != nil {
		t.Fatalf("узел не добавился: %v", err)
	}

	// Имя файла замка — не догадка, а то, что стор создал: если оно поменяется,
	// тест обязан покраснеть здесь, а не тихо перестать держать замок.
	lock := filepath.Join(root, ".lock")
	if _, err := os.Stat(lock); err != nil {
		t.Fatalf("файла замка нет по ожидаемому пути %s: %v", lock, err)
	}
	f, err := os.OpenFile(lock, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("замок не взялся: %v", err)
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)

	c, out, errs := testCLI(t)
	sock := filepath.Join(t.TempDir(), "связки-нет.sock")

	done := make(chan int, 1)
	go func() { done <- c.dispatch([]string{"nodes", "-client-socket", sock}) }()

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("`hop nodes` при занятом сторе дал %d, ожидался 0: %s", code, errs.String())
		}
	case <-time.After(2 * time.Second): //hop:realtime
		// Потолок ниже lockTimeout (5 с) намеренно: ждать замок ради одного
		// чтения команда не имеет права вовсе, и «дождалась и вернула 0» —
		// тоже дефект.
		t.Fatalf("`hop nodes` ждёт замок, которого ему не нужно; напечатано:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "a.example") {
		t.Errorf("узел не показан:\n%s", out.String())
	}
}
