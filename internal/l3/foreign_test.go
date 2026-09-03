//go:build linux

package l3

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// W72 — hopd не отчитывается отказом за чужую работу.
//
// Половина, которую НЕ ловят модульные тесты `internal/netstate` и
// `internal/platform`: там Classify и marks проверяются как функции, и оба
// остаются зелёными, если cmd/hopd перестанет их звать. Та же дыра, что была
// у W67 до W68. Здесь запускается настоящий hopd и читается его код выхода.
//
// Чужое изменение делается ПРИ ЖИВОМ туннеле: со снятым туннелем след hop
// пуст, и тест прошёл бы, даже классифицируй мы всё подряд как чужое.
func TestW72ForeignNetworkChangeIsNotOurFailure(t *testing.T) {
	s := startService(t, orphanDeadline)
	a := s.startAgent(filepath.Join(t.TempDir(), "token"))

	// Посторонний трогает сеть, пока hopd жив, — DHCP, NetworkManager,
	// поднявшийся контейнер. Адрес заведомо не наш и не из стенда.
	sh("ip", "addr", "add", "10.99.0.1/32", "dev", "lo")

	_ = a.cmd.Process.Signal(syscall.SIGTERM)
	_, _ = a.cmd.Process.Wait()

	if code := s.stopExit(); code != 0 {
		t.Fatalf("штатная остановка вернула %d: сеть менял не hopd, а отчитался он", code)
	}

	// И собственный след при этом снят: код 0 обязан означать «убрал за
	// собой», а не «перестал смотреть».
	waitLink(t, ifname, false)
	if r := rules(); strings.Contains(r, "31000:") || strings.Contains(r, "32000:") {
		t.Fatalf("наши правила пережили штатную остановку:\n%s", r)
	}

	// Уборка чужого — за тестом: netns общий на весь файл.
	sh("ip", "addr", "del", "10.99.0.1/32", "dev", "lo")
}

// W72 — свой след в сети после teardown остаётся отказом.
//
// Негативная половина пары: без неё «не отчитываться за чужое» неотличимо от
// «не отчитываться вовсе». Течь ставится руками — правило на приоритете hop,
// заведённое мимо журнала, — потому что снапшот не умеет и не должен уметь
// отличать нашу забытую строку от нашей же подставленной.
func TestW72OwnTraceAfterTeardownStillFails(t *testing.T) {
	s := startService(t, orphanDeadline)
	a := s.startAgent(filepath.Join(t.TempDir(), "token"))

	_ = a.cmd.Process.Signal(syscall.SIGTERM)
	_, _ = a.cmd.Process.Wait()

	// Мимо журнала: hopd о нём не знает и откатить не может — ровно то, как
	// выглядит несработавший откат.
	sh("ip", "rule", "add", "to", "203.0.113.0/24", "lookup", "main", "priority", "31000")

	if code := s.stopExit(); code == 0 {
		t.Fatal("наш след остался в сети, а штатная остановка вернула 0")
	}

	dropHopRules()
}

// W72 — неполный откат остаётся отказом, даже когда снапшот сошёлся.
//
// Вторая половина той же перестановки, и до неё код выхода был устроен ровно
// наоборот: ошибка teardown уходила в журнал и терялась, а код выхода
// определяло расхождение снапшота — то есть единственное, что hop не
// принадлежит. Замер старого поведения — implementation-notes.md, «hopd и
// чужие сети», ряд 4.
//
// Течь ставится вычитанием, а не добавлением: у hop отбирают правило, которое
// он собирался снять сам. Его откат тогда отказывает, всё остальное
// откатывается (Journal.Rollback не останавливается на первой ошибке), и
// снапшот сходится. Значит, ненулевой код здесь может прийти только от
// ошибки отката — ни от чего другого он прийти не может по построению.
func TestW72IncompleteRollbackIsOurFailure(t *testing.T) {
	s := startService(t, orphanDeadline)
	a := s.startAgent(filepath.Join(t.TempDir(), "token"))

	_ = a.cmd.Process.Signal(syscall.SIGTERM)
	_, _ = a.cmd.Process.Wait()

	// То самое правило-исключение §5.6, которое hopd снимает своим откатом.
	before := rules()
	if !strings.Contains(before, "to 10.0.0.0/8 lookup main") {
		t.Fatalf("правила-исключения нет, отбирать нечего:\n%s", before)
	}
	sh("ip", "rule", "del", "to", "10.0.0.0/8", "lookup", "main", "priority", "31000")

	if code := s.stopExit(); code == 0 {
		t.Fatal("откат отказал, а штатная остановка вернула 0")
	}

	// И снапшот при этом обязан сойтись — иначе ненулевой код пришёл бы от
	// расхождения, и тест проверял бы не тот механизм.
	s.verifySnapshot()
}
