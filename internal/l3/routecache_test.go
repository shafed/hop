//go:build linux

package l3

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Открытый вопрос этапа 2: даёт ли подмена маршрута на unreachable
// EHOSTUNREACH **уже установленным** соединениям, или они висят на
// закэшированном маршруте.
//
// Вопрос не риторический: если висят, то reject-маршруты закрывают только
// новые соединения, а старые молча замирают — то есть ровно тот отказ, против
// которого написан §5.6, остаётся, только сдвинутый. Ответ меняет решение
// §6.2, поэтому он получен экспериментом, а не рассуждением.
//
// Стенд туннеля не использует: он бы потребовал netstack (этап 3). Вместо
// него — veth в отдельный netns и настоящий TCP-эхосервер на том конце; вопрос
// про ядро, а не про туннель, и меряется ровно то, о чём он.
const (
	peerCIDR   = "10.9.9.2/24"
	peerAddr   = "10.9.9.2"
	localCIDR  = "10.9.9.1/24"
	peerPort   = 9099
	probeTable = 8422
	probePrio  = 1000
)

func TestRouteReplaceOnEstablishedConnection(t *testing.T) {
	requireNetns(t)

	peer := startPeer(t)
	defer peer.stop()

	// Маршрут к пиру уводится в отдельную таблицу — ровно так же, как это
	// делает туннель, чтобы подмена била по тому же месту.
	mustRun(t, "ip", "addr", "add", localCIDR, "dev", "veth0")
	mustRun(t, "ip", "link", "set", "veth0", "up")
	mustRun(t, "ip", "route", "add", peerAddr+"/32", "dev", "veth0", "table", fmt.Sprint(probeTable))
	mustRun(t, "ip", "rule", "add", "to", peerAddr+"/32", "lookup", fmt.Sprint(probeTable),
		"priority", fmt.Sprint(probePrio))
	t.Cleanup(func() {
		sh("ip", "rule", "del", "priority", fmt.Sprint(probePrio))
		sh("ip", "route", "flush", "table", fmt.Sprint(probeTable))
	})

	conn := dialPeer(t)
	defer conn.Close()
	if err := echo(conn, "до подмены"); err != nil {
		t.Fatalf("соединение не работает до подмены: %v", err)
	}

	// Та самая подмена, что делает сервис на ребре в orphaned.
	mustRun(t, "ip", "route", "replace", "unreachable", peerAddr+"/32", "table", fmt.Sprint(probeTable))

	// 1. Новое соединение — контроль: оно обязано отказать немедленно.
	newErr, newTook := connect(fmt.Sprintf("%s:%d", peerAddr, peerPort), 2*time.Second)
	if !isUnreachable(newErr) {
		t.Fatalf("новое соединение не отказало: %v", newErr)
	}

	// 2. Установленное соединение — собственно вопрос.
	estErr := echo(conn, "после подмены")
	verdict := "ВИСИТ на закэшированном маршруте (таймаут, без ошибки маршрутизации)"
	if isUnreachable(estErr) {
		verdict = "получает ошибку маршрутизации немедленно"
	}

	t.Logf("ОТВЕТ НА ОТКРЫТЫЙ ВОПРОС:")
	t.Logf("  новое соединение:       %v (за %v)", newErr, newTook)
	t.Logf("  установленное соединение: %v", estErr)
	t.Logf("  вердикт: установленное соединение %s", verdict)

	// Тест не утверждает, какой ответ правильный: он утверждает, что ответ
	// получен и записан. Провал — это когда установленное соединение
	// продолжает **работать**: значит, подмена маршрута не влияет на него
	// вообще, и §6.2 надо дописывать разрывом соединений.
	if estErr == nil {
		t.Fatal("установленное соединение продолжило работать после подмены маршрута: " +
			"reject-маршрутов недостаточно, §6.2 требует дописать разрыв")
	}
}

// echo пишет строку и читает ответ с коротким сроком: «висит» от «отказало»
// отличается именно сроком.
func echo(c net.Conn, msg string) error {
	if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil { //hop:realtime
		return err
	}
	if _, err := c.Write([]byte(msg + "\n")); err != nil {
		return err
	}
	_, err := bufio.NewReader(c).ReadString('\n')
	return err
}

func dialPeer(t *testing.T) net.Conn {
	t.Helper()
	var c net.Conn
	waitUntil(t, 5*time.Second, "соединения с пиром", func() bool {
		var err error
		c, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", peerAddr, peerPort), time.Second)
		return err == nil
	})
	return c
}

// --- пир в отдельном netns ---

type peerProc struct {
	cmd *exec.Cmd
	in  io.WriteCloser
}

func (p *peerProc) stop() {
	if p.in != nil {
		p.in.Close()
	}
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	}
	sh("ip", "link", "del", "veth0")
}

// startPeer поднимает veth-пару, уносит дальний конец в свой netns и запускает
// там эхосервер.
//
// Пир — тот же тестовый бинарь, перезапущенный с HOP_L3_PEER: отдельная
// программа ради тридцати строк эха завела бы ещё один шаг сборки в CI.
func startPeer(t *testing.T) *peerProc {
	t.Helper()
	sh("ip", "link", "del", "veth0")
	mustRun(t, "ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1")

	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(), "HOP_L3_PEER=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("не удалось создать netns для пира: %v", err)
	}
	p := &peerProc{cmd: cmd, in: in}
	t.Cleanup(p.stop)

	mustRun(t, "ip", "link", "set", "veth1", "netns", fmt.Sprint(cmd.Process.Pid))
	if _, err := io.WriteString(in, "go\n"); err != nil {
		t.Fatalf("сигнал пиру: %v", err)
	}

	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("пир не поднялся: %q, %v", line, err)
	}
	return p
}

// peerMain — точка входа пира. Живёт в своём netns, поэтому трогает интерфейсы
// без оглядки.
func peerMain() {
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		fmt.Fprintln(os.Stderr, "пир: нет сигнала:", err)
		os.Exit(1)
	}
	for _, args := range [][]string{
		{"ip", "link", "set", "lo", "up"},
		{"ip", "addr", "add", peerCIDR, "dev", "veth1"},
		{"ip", "link", "set", "veth1", "up"},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "пир: %v: %v: %s\n", args, err, out)
			os.Exit(1)
		}
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", peerAddr, peerPort))
	if err != nil {
		fmt.Fprintln(os.Stderr, "пир: listen:", err)
		os.Exit(1)
	}
	fmt.Println("ready")

	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go io.Copy(c, c)
	}
}

func mustRun(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v: %s", strings.Join(args, " "), err, out)
	}
}
