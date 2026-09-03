//go:build linux

package l3

import (
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestW71AgentStartedBeforeTheServiceWaitsAndAttaches — шов, которого L1 не
// видит: `hop agent`, запущенный раньше hopd, обязан дожить до него.
//
// До этого прохода агент соединялся с сервисом первой строкой runAgent.
// Замерено на этом дереве: `hop agent` с несуществующим сокетом —
// «фоновая половина hop недоступна: сокет … connect: no such file or
// directory», код 2, 11 мс, ни одной попытки. Автозапуск §6.13 делает из этого
// цикл: `systemctl --global enable hop-agent.service` поднимает агента при
// каждом логине, а логин обгоняет hopd — юнит уходит в failed, и RestartSec=2s
// там стоит именно поэтому.
//
// L1-половина (W71 в cmd/hop) проверяет lazyControl: ожидание не кончается
// само, соединение берётся при появлении сервиса и остаётся одним. Это не
// доказывает, что `run()` вообще его ждёт, — ровно та же дыра, что была у W67
// без W68: run() поднимает настоящий TUN и требует прав, и шов между
// механизмом и его вызовом виден только здесь.
//
// Форма — три части, и первая не декорация. (1) Сервиса нет, а агент жив и
// отвечает на сокете §3.3: старый бинарь до этой проверки не дожил бы. (2)
// Интерфейса при этом нет — иначе «жив» ничего не стоило бы, туннель мог
// подняться и без сервиса, то есть проверялось бы не то. (3) Появляется hopd —
// и ТОТ ЖЕ процесс поднимает туннель сам, без единого глагола и без
// перезапуска: это и есть «прицепился, когда сервис пришёл».
func TestW71AgentStartedBeforeTheServiceWaitsAndAttaches(t *testing.T) {
	requireNetns(t)

	// Каталог стенда заводится тестом, а не сервисом: путь сокета нужно знать
	// раньше, чем сервис появится.
	dir := t.TempDir()
	token := filepath.Join(dir, "token")

	cmd := commandAgent(t, serviceSock(dir), clientSock(dir), token)
	if err := cmd.Start(); err != nil {
		t.Fatalf("запуск hop agent без сервиса: %v", err)
	}
	a := &agent{t: t, cmd: cmd, token: token}
	t.Cleanup(func() {
		if a.cmd.Process != nil {
			_ = a.cmd.Process.Kill()
			_, _ = a.cmd.Process.Wait()
		}
	})

	// --- 1. сервиса нет, а агент жив и отвечает ---
	waitUntil(t, 10*time.Second, "агент открыл сокет клиентов без сервиса", func() bool {
		err := exec.Command(hopAgent(t), "status", "-client-socket", clientSock(dir), "--json").Run()
		if err == nil {
			return true
		}
		// Код 3 — fail-close (§5.9): агент ответил, живых узлов нет. Штатное
		// состояние стенда, тот же разбор, что в W68.
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 3 {
			return true
		}
		return false
	})
	if a.cmd.ProcessState != nil {
		t.Fatalf("агент вышел без сервиса (%v) — ровно тот дефект, который проход и чинит", a.cmd.ProcessState)
	}

	// --- 2. и интерфейса при этом нет ---
	if linkExists(ifname) {
		t.Fatal("интерфейс поднят без сервиса: проверяется не то, туннель поднимает hopd")
	}

	// --- 3. сервис появился: тот же процесс поднимает туннель сам ---
	s := startServiceIn(t, orphanDeadline, dir)
	waitLink(t, ifname, true)
	waitUntil(t, 10*time.Second, "агент дошёл до phase=up после прихода сервиса", func() bool {
		return s.phase() == "up"
	})
	if a.cmd.ProcessState != nil {
		t.Fatalf("агент вышел (%v): туннель подняла бы перезапущенная копия, а не дождавшаяся", a.cmd.ProcessState)
	}

	a.kill()
	waitLink(t, ifname, false)
	s.stop()
	s.verifySnapshot()
}
