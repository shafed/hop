//go:build linux

package l3

import (
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestW68AutoconnectOffSkipsInitialUp — шов, который W67 (cmd/hop) не видит.
//
// W67 проверяет shouldAutoUp как чистую функцию: стор говорит false, функция
// отвечает false. Это не доказывает, что `run()` в cmd/hop/main.go её вообще
// спрашивает — а до этого прохода там стоял безусловный `a.Up()`, и шов между
// функцией и её вызовом никакой модульный тест не видит: run() поднимает
// настоящий TUN и требует прав. L3 — единственное место, где это измеримо.
//
// Форма — сначала доказать, что при `autoconnect=on` (умолчание §6.13)
// `hop agent` поднимает интерфейс сам, ни одного управляющего глагола не
// подав, и только потом требовать, что при `off` тот же самый бинарь, тем же
// способом запущенный, интерфейс не поднимает. Без первой половины «не
// поднялся» ничего не стоило бы: интерфейс мог бы не появляться никогда,
// например из-за сломанной сборки стенда — ровно так стенд уже однажды молчал
// целым пакетом (см. HANDOFF.json, found_first) и это осталось незамеченным
// один полный проход.
//
// Третья часть — что агент при этом жив и способен поднять туннель, просто не
// сделал это сам: `hop up` через сокет §3.3 поднимает интерфейс вручную. Без
// неё «не поднялся» было бы неотличимо от «агент не запустился вовсе», и
// охрана ловила бы падение процесса, а не решение shouldAutoUp.
func TestW68AutoconnectOffSkipsInitialUp(t *testing.T) {
	s := startService(t, orphanDeadline)

	// --- 1. on (умолчание §6.13): агент поднимает туннель сам ---
	onToken := filepath.Join(t.TempDir(), "token-on")
	onAgent := s.startAgent(onToken) // startAgent сам ждёт phase=up и интерфейс
	onAgent.kill()
	waitLink(t, ifname, false)

	// --- 2. off: тем же глаголом, которым его выключит пользователь ---
	if out, err := exec.Command(hopAgent(t), "autoconnect", "off").CombinedOutput(); err != nil {
		t.Fatalf("`hop autoconnect off`: %v: %s", err, out)
	}
	// Уборка: следующий тест не должен молча унаследовать выключение, если
	// каталог стора вдруг окажется общим.
	t.Cleanup(func() {
		_ = exec.Command(hopAgent(t), "autoconnect", "on").Run()
	})

	offToken := filepath.Join(t.TempDir(), "token-off")
	cmd := commandAgent(t, s.sock, s.client, offToken)
	if err := cmd.Start(); err != nil {
		t.Fatalf("запуск hop agent: %v", err)
	}
	off := &agent{t: t, cmd: cmd, token: offToken}
	t.Cleanup(func() {
		if off.cmd.Process != nil {
			_ = off.cmd.Process.Kill()
			_, _ = off.cmd.Process.Wait()
		}
	})

	// Агент жив и отвечает на сокете клиентов §3.3 — это происходит в run()
	// до развилки shouldAutoUp, — а интерфейса при этом нет. attach-token тут
	// не годится в свидетели: он пишется только внутри Up(), то есть был бы
	// пуст и при живом агенте, и при мёртвом — не тот сигнал.
	waitUntil(t, 10*time.Second, "агент открыл сокет клиентов", func() bool {
		err := exec.Command(hopAgent(t), "status", "-client-socket", s.client, "--json").Run()
		if err == nil {
			return true
		}
		// Код 3 — fail-close (§5.9): агент ответил, узлов просто нет. Это и
		// есть штатное «жив, но не поднят» состояние этого теста.
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 3 {
			return true
		}
		return false
	})
	// Бюджет — заведомо больше времени, за которое интерфейс появился на
	// шаге 1, и заведомо меньше orphanDeadline: если бы Up() всё-таки
	// позвался, интерфейс успел бы появиться раньше, чем сервис решит, что
	// агент осиротел.
	time.Sleep(2 * time.Second) //hop:realtime
	if linkExists(ifname) {
		t.Fatal("автоподключение выключено, а `hop agent` всё равно поднял интерфейс")
	}
	if off.cmd.ProcessState != nil {
		t.Fatalf("агент уже вышел (%v) — тест проверял бы падение процесса, а не shouldAutoUp", off.cmd.ProcessState)
	}

	// --- 3. агент жив и способен: поднимаем вручную ---
	if out, err := exec.Command(hopAgent(t), "up", "-client-socket", s.client).CombinedOutput(); err != nil {
		t.Fatalf("`hop up` на живом агенте с выключенным автоподключением: %v: %s", err, out)
	}
	waitLink(t, ifname, true)

	off.kill()
	waitLink(t, ifname, false)
	s.stop()
	s.verifySnapshot()
}
