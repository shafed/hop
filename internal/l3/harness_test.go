//go:build linux

// Package l3 — тесты уровня L3 из §8.4: требуют прав и специфичны для ОС.
//
// Здесь Linux, потому что это единственная платформа, где полный e2e дёшев:
// сетевые namespace дают изоляцию и воспроизводимость, а `unshare -Urn` даёт
// CAP_NET_ADMIN внутри namespace без root. Поэтому набор гоняется на каждый PR
// (§8.4, матрица запуска), а не по расписанию.
//
// Запуск:
//
//	go test -c -o /tmp/l3.test ./internal/l3
//	HOP_L3=1 unshare -Urn /tmp/l3.test
//
// Без HOP_L3=1 тесты пропускаются: трогать сеть машины разработчика они не
// должны и не будут.
package l3

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shafed/hop/internal/netstate"
	"github.com/shafed/hop/internal/platform"
)

const (
	ifname = "hopt0"
	table  = 8421
	addr   = "10.255.0.1/24"
	// Дедлайн взят коротким намеренно: T23-slow ждёт его целиком, а тест,
	// который идёт 15 секунд, перестают запускать локально.
	orphanDeadline = 2 * time.Second
)

// requireNetns пропускает тест, если запуск не подтверждён явно.
//
// Именно явно, переменной окружения, а не догадкой по признакам: цена ошибки
// несимметрична. Лишний пропуск стоит одной строки в логе, а лишний запуск в
// общем namespace снимает сеть у машины, на которой идёт `go test ./...`.
// Никакая эвристика такой перекос не оправдывает.
func requireNetns(t *testing.T) {
	t.Helper()
	if os.Getenv("HOP_L3") == "" {
		t.Skip("L3 требует собственного netns; запуск: " +
			"go test -c -o /tmp/l3.test ./internal/l3 && HOP_L3=1 unshare -Urn /tmp/l3.test")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("нет iproute2")
	}
}

// service — запущенный hopd вместе со снапшотом сети, снятым до его старта.
type service struct {
	t      *testing.T
	cmd    *exec.Cmd
	sock   string
	before netstate.Snapshot
	src    netstate.Source
	agents []*agent
}

func startService(t *testing.T, deadline time.Duration) *service {
	t.Helper()
	requireNetns(t)

	// lo должен быть поднят: без него ядро ведёт себя странно с локальными
	// маршрутами, и падать будет не то, что проверяется.
	_ = exec.Command("ip", "link", "set", "lo", "up").Run()

	src := netstate.System()
	before, err := src.Capture()
	if err != nil {
		t.Fatalf("снапшот: %v", err)
	}

	dir := t.TempDir()
	sock := filepath.Join(dir, "hop.sock")
	ready := filepath.Join(dir, "ready")

	cmd := exec.Command(hopd(t),
		"-socket", sock,
		"-ready-file", ready,
		"-orphan-deadline", deadline.String(),
		"-heartbeat", "200ms",
		// L3 гоняет и сервис, и агента под root в своём netns, группы hop на
		// раннере нет и заводить её тест не вправе.
		"-group", "",
		"-debug",
	)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	// Собственная группа процессов: kill по группе не заденет сам тест.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("запуск hopd: %v", err)
	}

	s := &service{t: t, cmd: cmd, sock: sock, before: before, src: src}
	t.Cleanup(s.cleanup)
	waitFile(t, ready)
	return s
}

// kill убивает сервис так, как это делает T29: без шанса убрать за собой.
func (s *service) kill() {
	s.t.Helper()
	_ = s.cmd.Process.Kill()
	_, _ = s.cmd.Process.Wait()
}

// stop останавливает сервис штатно и ждёт выхода.
func (s *service) stop() {
	s.t.Helper()
	if s.cmd.Process == nil {
		return
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	_ = s.cmd.Wait()
}

func (s *service) cleanup() {
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_, _ = s.cmd.Process.Wait()
	}
	// Что бы ни случилось в тесте, netns остаётся общим для всего файла:
	// уборка руками, иначе следующий тест увидит чужое состояние.
	sh("ip", "link", "del", ifname)
	sh("ip", "route", "flush", "table", fmt.Sprint(table))
	dropHopRules()
}

// dropHopRules снимает всё, что раскладывает hopd, по приоритету. Приоритеты
// выбраны так, чтобы уборка не могла случайно снять чужое правило.
//
// Список берётся у продукта, а не повторяется здесь: своя копия однажды уже
// отстала от него, и правила с новыми приоритетами оставались в общем netns —
// следующий тест снимал их своим Reclaim и падал на снапшоте, хотя ломался не
// он.
func dropHopRules() {
	for _, prio := range platform.Priorities {
		for i := 0; i < 32; i++ {
			if exec.Command("ip", "rule", "del", "priority", fmt.Sprint(prio)).Run() != nil {
				break
			}
		}
	}
}

// verifySnapshot — общий платформенный контракт §8.4: снапшот после down
// обязан совпасть с исходным.
func (s *service) verifySnapshot() {
	s.t.Helper()
	if err := netstate.Verify(s.before, s.src); err != nil {
		s.t.Fatal(err)
	}
}

// agent — запущенный hop.
type agent struct {
	t     *testing.T
	cmd   *exec.Cmd
	token string
}

// commandAgent собирает команду агента, но не запускает её.
func commandAgent(t *testing.T, sock, tokenFile string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(hopAgent(t),
		"-socket", sock,
		"-ifname", ifname,
		"-addr", addr,
		"-table", fmt.Sprint(table),
		"-heartbeat", "200ms",
		"-token-file", tokenFile,
		"-debug",
	)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func (s *service) startAgent(tokenFile string) *agent {
	s.t.Helper()
	cmd := commandAgent(s.t, s.sock, tokenFile)
	if err := cmd.Start(); err != nil {
		s.t.Fatalf("запуск hop: %v", err)
	}
	a := &agent{t: s.t, cmd: cmd, token: tokenFile}
	s.agents = append(s.agents, a)
	s.t.Cleanup(func() {
		if a.cmd.Process != nil {
			_ = a.cmd.Process.Kill()
			_, _ = a.cmd.Process.Wait()
		}
	})
	waitLink(s.t, ifname, true)
	// Ждать интерфейса мало: он появляется в сервисе ещё до того, как ответ
	// дойдёт до агента. Тест, который убьёт агента в этом зазоре, промахнётся
	// мимо проверяемого свойства и будет мигать.
	waitUntil(s.t, 10*time.Second, "агент дошёл до phase=up", func() bool {
		return strings.Contains(s.status(), "phase=up")
	})
	waitUntil(s.t, 10*time.Second, "агент сохранил attach-token", func() bool {
		st, err := os.Stat(tokenFile)
		return err == nil && st.Size() > 0
	})
	return a
}

// kill — kill -9: ровно то, чем §6.2 обосновывает ребро. Ядро закрывает
// дескрипторы, сервис получает EOF на управляющем сокете.
func (a *agent) kill() {
	a.t.Helper()
	_ = a.cmd.Process.Kill()
	_, _ = a.cmd.Process.Wait()
}

// status спрашивает сервис отдельным коротким соединением: оно не владеет
// туннелем, и его обрыв ребра не вызывает.
func (s *service) status() string {
	s.t.Helper()
	out, err := exec.Command(hopAgent(s.t), "-socket", s.sock, "-status").Output()
	if err != nil {
		s.t.Fatalf("status: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// --- сборка бинарей ---

var built = map[string]string{}

// Переменные HOP_L3_BIN_* позволяют подсунуть уже собранные бинари. В CI это
// обязательно: тесты идут под `sudo unshare -n`, а `go build` из-под root
// пошёл бы в чужой кеш и полез бы в сеть за модулями.
var binEnv = map[string]string{
	"cmd/hopd": "HOP_L3_BIN_HOPD",
	"cmd/hop":  "HOP_L3_BIN_HOP",
}

func buildOnce(t *testing.T, pkg string) string {
	t.Helper()
	if p := os.Getenv(binEnv[pkg]); p != "" {
		return p
	}
	if p, ok := built[pkg]; ok {
		return p
	}
	out := filepath.Join(os.TempDir(), "hop-l3-"+filepath.Base(pkg))
	cmd := exec.Command("go", "build", "-o", out, "./"+pkg)
	cmd.Dir = repoRoot(t)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("сборка %s: %v: %s", pkg, err, b)
	}
	built[pkg] = out
	return out
}

func hopd(t *testing.T) string     { return buildOnce(t, "cmd/hopd") }
func hopAgent(t *testing.T) string { return buildOnce(t, "cmd/hop") }

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod не найден")
		}
		dir = parent
	}
}

// --- ожидания ---

// Тесты этого файла живут в реальном времени: они и существуют затем, чтобы
// увидеть, что делает настоящее ядро. Фейковые часы стоят уровнем выше, в
// internal/tunnel.

func waitFile(t *testing.T, path string) {
	t.Helper()
	waitUntil(t, 10*time.Second, "файл "+path, func() bool {
		_, err := os.Stat(path)
		return err == nil
	})
}

func waitLink(t *testing.T, name string, want bool) {
	t.Helper()
	what := "появления"
	if !want {
		what = "исчезновения"
	}
	waitUntil(t, 10*time.Second, what+" интерфейса "+name, func() bool {
		return linkExists(name) == want
	})
}

func waitUntil(t *testing.T, limit time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit) //hop:realtime
	for {
		if ok() {
			return
		}
		if time.Now().After(deadline) { //hop:realtime
			t.Fatalf("не дождались: %s", what)
		}
		time.Sleep(20 * time.Millisecond) //hop:realtime
	}
}

// --- обёртки над ip ---

func sh(args ...string) string {
	out, _ := exec.Command(args[0], args[1:]...).CombinedOutput()
	return string(out)
}

func linkExists(name string) bool {
	return exec.Command("ip", "link", "show", name).Run() == nil
}

func linkIndex(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("ip", "-o", "link", "show", name).Output()
	if err != nil {
		t.Fatalf("ip link show %s: %v", name, err)
	}
	idx, _, _ := strings.Cut(string(out), ":")
	return strings.TrimSpace(idx)
}

func tunnelRoutes() string { return sh("ip", "-o", "route", "show", "table", fmt.Sprint(table)) }

func rules() string { return sh("ip", "-o", "rule", "show") }
