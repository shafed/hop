//go:build linux

package l3

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// hangingPeer6 — адрес в подсети пира, которого там нет: SYN уходит, ответа
// нет, сокет остаётся в SYN_SENT сколько угодно долго.
const hangingPeer6 = "fd00:9:9::3"

// W50 на уровне ядра — вторая половина того же утверждения, что и в
// internal/platform: правило §6.9 закрывает IPv6 только для НОВЫХ соединений,
// а установленное до `up` оно обрекает на молчание. §5.6 требует отказа.
//
// Почему тест обязан быть на L3: молчание отличается от отказа сроком, а срок
// определяет ядро. Замер (implementation-notes.md, «Этап 8 — отказ соединениям
// IPv6 старше туннеля»): после правила `write` в установленный сокет
// возвращает n=26 и nil, а `read` упирается в собственный таймаут; после
// SOCK_DESTROY тот же сокет отвечает `ECONNABORTED` немедленно.
//
// Три утверждения, и каждое своё:
//  1. до `up` стенд действительно даёт IPv6 — иначе краснота ничего не значит;
//  2. установленное соединение после `up` получает отказ, и получает его
//     мгновенно, а не по таймауту приложения;
//  3. соединение в SYN_SENT — тоже: оно переживает правило на закэшированном
//     маршруте, и зачистка, смотрящая только на ESTABLISHED, его пропустит
//     (замер: `ss --kill -6 -t dst [...]` пропускает ровно его).
func TestW50IPv6EstablishedIsAbortedNotSilenced(t *testing.T) {
	requireNetns(t)

	peer := startPeer(t)
	defer peer.stop()

	mustRun(t, "ip", "addr", "add", localCIDR, "dev", "veth0")
	mustRun(t, "ip", "-6", "addr", "add", local6CIDR, "dev", "veth0", "nodad")
	mustRun(t, "ip", "link", "set", "veth0", "up")
	waitAddrsSettled(t, "veth0")

	// 1. Контроль стенда: до туннеля IPv6 до пира доходит и возвращается.
	c := dialPeer6(t)
	defer c.Close()
	if err := echo(c, "до туннеля"); err != nil {
		t.Fatalf("стенд не даёт IPv6 до пира и до туннеля — проверять нечего: %v", err)
	}

	// Второй сокет — в SYN_SENT. Он существует к моменту `up`, маршрут у него
	// уже разрешён, и без зачистки он висит до собственного таймаута.
	syn := make(chan error, 1)
	go func() {
		cc, err := net.DialTimeout("tcp6", fmt.Sprintf("[%s]:%d", hangingPeer6, peerPort), 30*time.Second)
		if cc != nil {
			cc.Close()
		}
		syn <- err
	}()
	waitUntil(t, 5*time.Second, "сокета в SYN_SENT", func() bool {
		return strings.Contains(sh("ss", "-6", "-t", "-n", "state", "syn-sent"), hangingPeer6)
	})

	s := startService(t, orphanDeadline)
	s.startAgent(filepath.Join(t.TempDir(), "token"))

	// 2. Установленное соединение: отказ, а не молчание, и немедленно.
	_ = c.SetDeadline(time.Now().Add(3 * time.Second)) //hop:realtime
	start := time.Now()                                //hop:realtime
	_, werr := c.Write([]byte("после up\n"))
	var rerr error
	if werr == nil {
		buf := make([]byte, 64)
		_, rerr = c.Read(buf)
	}
	took := time.Since(start) //hop:realtime
	err := werr
	if err == nil {
		err = rerr
	}
	if err == nil {
		t.Fatalf("установленное соединение IPv6 продолжило работать при поднятом туннеле — "+
			"трафик идёт мимо туннеля: %s", sh("ip", "-6", "route", "get", peer6Addr))
	}
	if !isAborted(err) {
		t.Fatalf("соединение замолчало вместо отказа: %v за %v — §5.6 требует отказа, "+
			"а не ожидания собственного таймаута TCP", err, took)
	}
	if took > 500*time.Millisecond {
		t.Fatalf("отказ занял %v — это не отказ, а ожидание", took)
	}

	// 3. SYN_SENT — тот же отказ. Проверка отдельная, потому что промахнуться
	// мимо него можно, не заметив: соединения ещё нет, а сокет уже есть.
	select {
	case serr := <-syn:
		if !isAborted(serr) && !isUnreachable(serr) {
			t.Fatalf("сокет в SYN_SENT завершился не отказом: %v", serr)
		}
		t.Logf("SYN_SENT получил %v; установленное — %v за %v", serr, err, took)
	case <-time.After(3 * time.Second): //hop:realtime
		t.Fatal("сокет в SYN_SENT висит: зачистка смотрит только на ESTABLISHED")
	}
}

// isAborted — отказ, пришедший от разрушенного сокета, в отличие от отказа
// маршрутизации (isUnreachable). ECONNABORTED даёт чтение, EPIPE и ECONNRESET
// — запись; всё это немедленно, в отличие от i/o timeout.
func isAborted(err error) bool {
	if err == nil {
		return false
	}
	for _, target := range []syscall.Errno{
		syscall.ECONNABORTED, syscall.EPIPE, syscall.ECONNRESET,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
