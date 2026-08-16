//go:build linux

package l3

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shafed/hop/internal/netstate"
)

// T21 — базовая проверка, на которой стоят все остальные: интерфейс есть,
// адрес назначен, маршруты и правила разложены.
func TestT21Up(t *testing.T) {
	s := startService(t, orphanDeadline)
	s.startAgent(filepath.Join(t.TempDir(), "token"))

	if !linkExists(ifname) {
		t.Fatal("интерфейс не создан")
	}
	if out := sh("ip", "-o", "addr", "show", ifname); !strings.Contains(out, "10.255.0.1/24") {
		t.Fatalf("адрес не назначен: %s", out)
	}
	if out := tunnelRoutes(); !strings.Contains(out, "default dev "+ifname) {
		t.Fatalf("маршрут туннеля отсутствует: %s", out)
	}

	r := rules()
	// §6.8: правило по UID-диапазону. Оно же — единственное, что не привязано
	// к интерфейсу, и потому предмет T29.
	if !strings.Contains(r, fmt.Sprintf("uidrange %d-%d", os.Getuid(), os.Getuid())) {
		t.Fatalf("нет правила защиты от петли §6.8: %s", r)
	}
	// §5.6: исключения выражены правилами выше туннельного, поэтому в
	// туннельную таблицу они не заходят вовсе — ни в up, ни в orphaned.
	for _, want := range []string{"192.168.0.0/16", "ipproto udp dport 67-68", "ipproto udp dport 123"} {
		if !strings.Contains(r, want) {
			t.Fatalf("нет исключения §5.6 %q: %s", want, r)
		}
	}
	// §3.4 п. 1 и §5.7: :53 заводится в таблицу туннеля, иначе запрос на
	// локальный роутер уходит в локальную сеть по исключению выше — перехват
	// формально работает, а утечка идёт.
	for _, want := range []string{"ipproto udp dport 53", "ipproto tcp dport 53"} {
		if !strings.Contains(r, want) {
			t.Fatalf("нет правила перехвата :53 %q: %s", want, r)
		}
	}
	// Порядок правил — часть контракта, и он тот же, что в §3.4: сперва свой
	// трафик мимо туннеля (§6.8), потом перехват :53, потом исключения §5.6.
	// `ip rule list` печатает правила по возрастанию приоритета, поэтому
	// порядок строк и есть порядок применения.
	loop := strings.Index(r, "uidrange")
	dns := strings.Index(r, "dport 53")
	excl := strings.Index(r, "192.168.0.0/16")
	if !(loop < dns && dns < excl) {
		t.Fatalf("порядок правил не тот: защита от петли %d, перехват :53 %d, исключения %d\n%s",
			loop, dns, excl, r)
	}
}

// T22 — общий платформенный контракт §8.4: после down снапшот совпал с
// исходным. Охраняется политикой snapshot_restore.
func TestT22UpDown(t *testing.T) {
	s := startService(t, orphanDeadline)
	tok := filepath.Join(t.TempDir(), "token")
	a := s.startAgent(tok)

	// Штатный уход агента, затем штатная остановка сервиса.
	_ = a.cmd.Process.Signal(syscall.SIGTERM)
	_, _ = a.cmd.Process.Wait()
	s.stop()

	waitLink(t, ifname, false)
	s.verifySnapshot()
}

// T23-fast — свойство безопасности: оно на ребре и не зависит ни от какого
// таймера. Приложение, ткнувшееся наружу сразу после `kill -9` агента, обязано
// получить отказ, а не повиснуть.
func TestT23FastRefusesImmediately(t *testing.T) {
	s := startService(t, 30*time.Second) // дедлайн заведомо больше измеряемого
	s.startAgent(filepath.Join(t.TempDir(), "token"))

	a := time.Now() //hop:realtime
	killAgentAndWaitOrphaned(t, s)
	edge := time.Since(a) //hop:realtime

	err, took := connect("203.0.113.7:80", time.Second)
	if err == nil {
		t.Fatal("connect прошёл: туннеля нет, а трафик ушёл")
	}
	if !isUnreachable(err) {
		t.Fatalf("ошибка %v — ожидался немедленный отказ, а не таймаут", err)
	}
	if took > 500*time.Millisecond {
		t.Fatalf("отказ занял %v — это не отказ, а ожидание", took)
	}
	t.Logf("ребро заняло %v, отказ пришёл за %v: %v", edge, took, err)
}

// T23b — того теста в спеке до §6.2 не было, и написать его было нельзя:
// на всём протяжении окна TCP даёт отказ, UDP даёт ICMP port unreachable, и
// ничто не молчит. Именно он ловит нарушение §5.3 и §5.6.
//
// Половина этого свойства проверена без прав в internal/reject
// (TestReplyRefusesInsteadOfSilence); здесь — то, что на Linux делает ядро.
func TestT23bWindowNeverGoesSilent(t *testing.T) {
	s := startService(t, 3*time.Second)
	s.startAgent(filepath.Join(t.TempDir(), "token"))
	killAgentAndWaitOrphaned(t, s)

	deadline := time.Now().Add(2 * time.Second) //hop:realtime
	probes := 0
	for time.Now().Before(deadline) { //hop:realtime
		if err, _ := connect("203.0.113.7:80", 500*time.Millisecond); !isUnreachable(err) {
			t.Fatalf("на пробе %d TCP не отказал: %v", probes, err)
		}
		if err := udpProbe("203.0.113.7:9999", 500*time.Millisecond); !isUnreachable(err) {
			t.Fatalf("на пробе %d UDP не дал ICMP unreachable: %v", probes, err)
		}
		probes++
	}
	if probes < 3 {
		t.Fatalf("проб всего %d — окно не покрыто", probes)
	}
	t.Logf("окно покрыто %d пробами, все отказали", probes)
}

// T23c — §5.7б внутри окна §6.2: DNS отказывает вместе со всем остальным.
//
// Запрос идёт на локальный роутер — самый частый случай, потому что системный
// DNS обычно и есть роутер. В туннель его заводит правило перехвата :53 (§3.4,
// п. 1); без правила он ушёл бы в локальную сеть по исключению §5.6, а внутри
// окна — молчал бы, потому что по адресу это RFC1918.
//
// Ожидается именно ECONNREFUSED: так выглядит ICMP port unreachable, который
// синтезировал наш респондер. ENETUNREACH означал бы, что до устройства запрос
// не дошёл вовсе, то есть перехват не встал, — и такой отказ теста не устроит,
// хотя формально это тоже отказ.
//
// Половина свойства проверена без прав в internal/reject
// (TestDNSInOrphanedRefusesEvenToLocalRouter).
func TestT23cDNSInWindowRefuses(t *testing.T) {
	s := startService(t, 3*time.Second)
	s.startAgent(filepath.Join(t.TempDir(), "token"))
	killAgentAndWaitOrphaned(t, s)

	err := udpProbe("192.168.1.1:53", 500*time.Millisecond)
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("DNS-запрос в окне дал %v, ожидался ICMP port unreachable от респондера", err)
	}
}

// T23-slow — свойство уборки. Длинный порог теперь безвреден именно потому,
// что окно перестало быть молчаливым.
func TestT23SlowTearsDown(t *testing.T) {
	s := startService(t, orphanDeadline)
	s.startAgent(filepath.Join(t.TempDir(), "token"))
	killAgentAndWaitOrphaned(t, s)

	waitLink(t, ifname, false)
	waitUntil(t, 5*time.Second, "исчезновения правил hop", func() bool {
		return !strings.Contains(rules(), fmt.Sprint(table))
	})
	s.verifySnapshot()
}

// T24 — агент убит и поднят внутри окна: интерфейс не менял ни имени, ни
// индекса, дескриптор тот же, отказ снят.
//
// Плюс подпроверка плана: в зазоре трафик отказывался, а не висел — тот же
// механизм, что в T23-fast, другой исход.
func TestT24ReattachWithinDeadline(t *testing.T) {
	s := startService(t, 30*time.Second)
	tok := filepath.Join(t.TempDir(), "token")
	s.startAgent(tok)

	idxBefore := linkIndex(t, ifname)
	killAgentAndWaitOrphaned(t, s)

	// Зазор: отказ, а не ожидание.
	if err, took := connect("203.0.113.7:80", time.Second); !isUnreachable(err) || took > 500*time.Millisecond {
		t.Fatalf("в зазоре трафик висел вместо отказа: %v за %v", err, took)
	}

	s.startAgent(tok) // тот же токен: реаттач, а не новый туннель

	if got := linkIndex(t, ifname); got != idxBefore {
		t.Fatalf("индекс интерфейса %s, был %s — интерфейс пересоздан", got, idxBefore)
	}
	if st := s.status(); !strings.Contains(st, "phase=up") {
		t.Fatalf("status = %q, ожидалось phase=up", st)
	}
	if !strings.Contains(tunnelRoutes(), "default dev "+ifname) {
		t.Fatalf("маршрут туннеля потерялся: %s", tunnelRoutes())
	}
	// Отказ снят: устройство снова читает агент, а не респондер сервиса.
	// Иначе оба процесса делили бы один дескриптор и растащили бы пакеты.
	if err, _ := connect("203.0.113.7:80", 500*time.Millisecond); isUnreachable(err) {
		t.Fatalf("после реаттача трафик всё ещё отвергается сервисом: %v", err)
	}
}

// Мусорный токен не продлевает окно и не забирает туннель: иначе локальный
// процесс, предъявляющий его в цикле, держит машину в отказе бесконечно
// (§3.1).
func TestAttachWithWrongTokenIsRejected(t *testing.T) {
	s := startService(t, 30*time.Second)
	good := filepath.Join(t.TempDir(), "token")
	s.startAgent(good)
	killAgentAndWaitOrphaned(t, s)

	bad := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(bad, []byte("подделка"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Агент с чужим токеном: реаттач не пройдёт, и он поднимет новый туннель —
	// но не заберёт текущий. Смотрим на то, что состояние не стало up от Attach.
	out := sh(hopAgent(t), "-socket", s.sock, "-status")
	if !strings.Contains(out, "phase=orphaned") {
		t.Fatalf("до попытки status = %q", strings.TrimSpace(out))
	}
	tryAttach(t, s.sock, bad)
	if st := s.status(); !strings.Contains(st, "phase=orphaned") {
		t.Fatalf("после мусорного Attach status = %q, ожидалось orphaned", st)
	}
}

// T29 — смерть самого владельца маршрутов. §6.2 покрывает смерть агента, но не
// смерть сервиса. Тест смотрит, что переживает `kill -9` сервиса, — и смотрит
// именно на `ip rule` с UID-диапазоном (§6.8), который от интерфейса не
// зависит.
func TestT29ServiceDeath(t *testing.T) {
	s := startService(t, orphanDeadline)
	s.startAgent(filepath.Join(t.TempDir(), "token"))

	s.kill()

	// Интерфейс уходит с последним дескриптором — это ядро, не мы.
	waitLink(t, ifname, false)

	var leaked []string
	for _, line := range strings.Split(rules(), "\n") {
		for _, prio := range []string{"30500:", "30750:", "31000:", "32000:"} {
			if strings.HasPrefix(strings.TrimSpace(line), prio) {
				leaked = append(leaked, strings.TrimSpace(line))
			}
		}
	}
	// Утверждение теста — не «ничего не осталось», а «мы знаем, что осталось».
	// Знание фиксируется здесь, а не в рассуждении (план, D11).
	t.Logf("после kill -9 сервиса пережили смерть владельца %d правил:", len(leaked))
	for _, l := range leaked {
		t.Logf("  %s", l)
	}
	uidRule := fmt.Sprintf("uidrange %d-%d", os.Getuid(), os.Getuid())
	if !strings.Contains(strings.Join(leaked, "\n"), uidRule) {
		t.Fatalf("правило §6.8 по UID-диапазону не пережило смерть сервиса — "+
			"это меняет §6.2 и §6.8, обнови документ. Осталось: %v", leaked)
	}

	// А раз остались — уборка обязана быть чьей-то. Она за следующим стартом
	// сервиса: он снимает мусор до того, как снять снапшот, иначе снапшот
	// закрепит этот мусор как «исходное состояние».
	next := startService(t, orphanDeadline)
	next.stop()
	if err := netstate.Verify(s.before, s.src); err != nil {
		t.Fatalf("следующий запуск не убрал за умершим: %v", err)
	}
}

// --- вспомогательное ---

func killAgentAndWaitOrphaned(t *testing.T, s *service) {
	t.Helper()
	a := s.agents[len(s.agents)-1]
	a.kill()
	waitUntil(t, 5*time.Second, "перехода в orphaned", func() bool {
		return strings.Contains(s.status(), "phase=orphaned")
	})
}

func tryAttach(t *testing.T, sock, tokenFile string) {
	t.Helper()
	cmd := commandAgent(t, sock, tokenFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	// Дать процессу дойти до Attach и получить отказ.
	time.Sleep(300 * time.Millisecond) //hop:realtime
}

// connect меряет, отказ это или ожидание: разница между ними — весь смысл
// §5.6 и §6.2.
func connect(addr string, limit time.Duration) (error, time.Duration) {
	start := time.Now() //hop:realtime
	c, err := net.DialTimeout("tcp", addr, limit)
	took := time.Since(start) //hop:realtime
	if err == nil {
		c.Close()
	}
	return err, took
}

// udpProbe отправляет датаграмму и читает ошибку: на связанном UDP-сокете
// ICMP unreachable приезжает как ошибка следующей операции.
func udpProbe(addr string, limit time.Duration) error {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Write([]byte("проба")); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(limit)) //hop:realtime
	buf := make([]byte, 1)
	_, err = c.Read(buf)
	return err
}

// isUnreachable — отказ ядра, а не таймаут. EHOSTUNREACH даёт unreachable-
// маршрут, ECONNREFUSED — синтезированный RST, ENETUNREACH — отсутствие
// маршрута вовсе.
func isUnreachable(err error) bool {
	if err == nil {
		return false
	}
	for _, target := range []syscall.Errno{
		syscall.EHOSTUNREACH, syscall.ENETUNREACH,
		syscall.ECONNREFUSED, syscall.EACCES, syscall.EPERM,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
