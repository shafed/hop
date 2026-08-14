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
	"sync"
	"syscall"
	"testing"
	"time"
)

// Стенд T25–T28: «интернет», «узел» и «локальный резолвер» за veth, в чужом
// netns. Именно в чужом: адрес, назначенный своему же интерфейсу, забирает
// таблица `local` с приоритетом 0, и до правил hop такой пакет не доходит
// вовсе — тест проверял бы не то.
//
// Живых узлов в стенде нет намеренно. Без узлов агент держит fail-close (§5.6):
// всё, что попало в туннель, дальше не уходит. Значит «дошло до сервера»
// однозначно означает «прошло мимо туннеля» — а это и есть предмет T25, T27 и
// T28.
const (
	netVeth  = "vhop0" // наш конец
	peerVeth = "vhop1" // конец в netns стенда

	transitOurs = "198.51.100.1/30"
	transitPeer = "198.51.100.2/30"

	// inetAddr — «IP узла» для T25 и «интернет-сервер, доступный напрямую»
	// для T27 в одном лице: адрес вне локальных сетей §5.6, до которого есть
	// прямой маршрут.
	inetAddr = "203.0.113.10"
	inetPort = 9443

	// lanResolver — «подставной системный резолвер» T26. Он же локальный
	// роутер: именно поэтому §3.4 ставит перехват :53 выше списка исключений.
	lanResolver = "192.168.66.53"

	// v6Peer — глобальный IPv6 (2000::/3) на том конце: T28 требует адреса,
	// который без блокировки ушёл бы мимо туннеля.
	v6Ours     = "2001:db8:ff::1/64"
	v6Peer     = "2001:db8:ff::2/64"
	v6PeerAddr = "2001:db8:ff::2"

	// otherUID — любой uid, кроме агентского: правило §6.8 освобождает от
	// туннеля ровно агента, и путь «обычного приложения» виден только с чужого
	// uid. В netns все процессы — root, поэтому обычное приложение приходится
	// изображать ядру вопросом, а не сокетом.
	otherUID = 65534
)

// T25 — исходящее агента к узлу не заходит обратно в туннель (§6.8).
//
// Проверяется дважды и с разных сторон: у ядра спрашивается путь для агента и
// для обычного приложения, и отдельно живым соединением — что путь агента
// действительно рабочий. Без §6.8 соединение к узлу упёрлось бы в собственный
// TUN, где узлов нет, и получило бы отказ.
func TestT25NoLoopOnNodeDial(t *testing.T) {
	peer := startNetPeer(t)
	s := startService(t, orphanDeadline)
	s.startAgent(tokenFile(t))

	agent := routeGet(t, inetAddr, "uid", fmt.Sprint(os.Getuid()))
	if !strings.Contains(agent, "dev "+netVeth) {
		t.Fatalf("трафик агента к узлу %s идёт не физическим интерфейсом: %s", inetAddr, agent)
	}
	if strings.Contains(agent, ifname) {
		t.Fatalf("петля: трафик агента к узлу %s заходит в туннель: %s", inetAddr, agent)
	}
	// Контроль: без правила §6.8 путь был бы именно таким.
	if other := routeGet(t, inetAddr, "uid", fmt.Sprint(otherUID)); !strings.Contains(other, "dev "+ifname) {
		t.Fatalf("тест вакуумен: без §6.8 трафик к %s и так не идёт в туннель: %s", inetAddr, other)
	}

	if err, took := connect(inetTarget(), 2*time.Second); err != nil {
		t.Fatalf("агент не дозвонился до узла за %v: %v", took, err)
	}
	waitUntil(t, 2*time.Second, "соединения на узле", func() bool { return peer.count("tcp") == 1 })
}

// T26 — DNS-запрос приложения не уходит на подставной системный резолвер
// (§5.7, §3.4).
//
// Резолвер здесь — локальный роутер, то есть адрес, накрытый исключением §5.6.
// Без правила выше исключений запрос ушёл бы в локальную сеть, ни разу не
// заглянув в туннель, при формально работающем перехвате в агенте.
//
// Второй половины T26 («запрос виден только на резолвере за узлом») здесь нет:
// она требует живого узла с резолвером за ним, а стенд намеренно без узлов.
func TestT26DNSDoesNotReachSystemResolver(t *testing.T) {
	peer := startNetPeer(t)
	s := startService(t, orphanDeadline)
	s.startAgent(tokenFile(t))

	app := routeGet(t, lanResolver, "ipproto", "udp", "dport", "53", "uid", fmt.Sprint(otherUID))
	if !strings.Contains(app, "dev "+ifname) {
		t.Fatalf("DNS приложения к системному резолверу %s уходит мимо туннеля: %s", lanResolver, app)
	}
	// То же самое без порта: обычный трафик на локальный роутер обязан идти в
	// локальную сеть (§5.6), иначе перехват :53 куплен ценой сломанной сети.
	if plain := routeGet(t, lanResolver, "uid", fmt.Sprint(otherUID)); strings.Contains(plain, ifname) {
		t.Fatalf("не только DNS, а весь трафик на %s уведён в туннель: %s", lanResolver, plain)
	}
	// Резолв самого агента идёт мимо туннеля всегда: иначе старт уходит в
	// петлю — чтобы поднять узел, надо резолвить его имя (§5.7а).
	if boot := routeGet(t, lanResolver, "ipproto", "udp", "dport", "53", "uid", fmt.Sprint(os.Getuid())); strings.Contains(boot, ifname) {
		t.Fatalf("bootstrap-резолв агента уходит в туннель: %s", boot)
	}

	// Контроль, что тест не вакуумен: резолвер жив и доступен напрямую —
	// запрос агента до него доходит.
	dnsProbe(t, lanResolver)
	waitUntil(t, 2*time.Second, "запроса от агента на резолвере", func() bool { return peer.count("dns") == 1 })
}

// T27 — живых узлов нет, и трафик приложения наружу упирается в туннель, а не
// уходит напрямую (§5.6, fail-close на уровне TUN).
func TestT27FailCloseKeepsTrafficOffTheWire(t *testing.T) {
	peer := startNetPeer(t)

	// Контроль до туннеля: сервер действительно доступен напрямую, иначе «ноль
	// соединений» не значило бы ничего.
	if err, _ := connect(inetTarget(), 2*time.Second); err != nil {
		t.Fatalf("интернет-сервер недоступен напрямую, тест был бы вакуумен: %v", err)
	}
	waitUntil(t, 2*time.Second, "контрольного соединения", func() bool { return peer.count("tcp") == 1 })

	s := startService(t, orphanDeadline)
	s.startAgent(tokenFile(t))

	// Путь приложения спрашивается у ядра: правило §6.8 освобождает агента, а в
	// netns и тест, и агент — один и тот же root, поэтому чужой uid можно
	// только назвать, а не занять. Отказ на том конце этого пути проверен без
	// прав в L2 (T12, T13).
	if path := routeGet(t, inetAddr, "uid", fmt.Sprint(otherUID)); !strings.Contains(path, "dev "+ifname) {
		t.Fatalf("трафик приложения к %s уходит мимо туннеля: %s", inetAddr, path)
	}
	settle()
	if n := peer.count("tcp"); n != 1 {
		t.Fatalf("на интернет-сервере %d соединений, ожидалось одно контрольное", n)
	}
}

// T28 — IPv6 заблокирован и не ушёл мимо туннеля (§6.9).
//
// Исключения из блокировки нет ни у кого, включая агента: в v1 IPv6 нет вовсе,
// и «частично поднятый» он хуже отсутствующего.
func TestT28IPv6IsBlocked(t *testing.T) {
	peer := startNetPeer(t)

	// Контроль до туннеля: стенд по IPv6 ходит, значит блокировке есть что
	// ломать.
	if err, _ := connect(v6Target(), 2*time.Second); err != nil {
		t.Fatalf("стенд без IPv6, тест был бы вакуумен: %v", err)
	}
	waitUntil(t, 2*time.Second, "контрольного IPv6-соединения", func() bool { return peer.count("tcp6") == 1 })

	s := startService(t, orphanDeadline)
	s.startAgent(tokenFile(t))

	err, took := connect(v6Target(), time.Second)
	if !isUnreachable(err) {
		t.Fatalf("IPv6 не заблокирован: %v за %v", err, took)
	}
	if took > 500*time.Millisecond {
		t.Fatalf("отказ занял %v — это ожидание, а не отказ (§5.6)", took)
	}
	settle()
	if n := peer.count("tcp6"); n != 1 {
		t.Fatalf("IPv6 ушёл мимо туннеля: соединений на стенде %d, ожидалось одно контрольное", n)
	}
}

// --- стенд ---

func inetTarget() string { return fmt.Sprintf("%s:%d", inetAddr, inetPort) }
func v6Target() string   { return fmt.Sprintf("[%s]:%d", v6PeerAddr, inetPort) }

func tokenFile(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/token"
}

// routeGet спрашивает у ядра путь пакета. Это и есть ответ на вопрос T25 и
// T27: «сколько пакетов увидит TUN» — то же самое, что «выберет ли ядро TUN»,
// но без сниффера и без прав сверх netns.
func routeGet(t *testing.T, dst string, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", append([]string{"route", "get", dst}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip route get %s %v: %v: %s", dst, args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// dnsProbe шлёт датаграмму на :53. Стенд считает датаграммы, а не вопросы:
// предмет теста — куда пакет ушёл, а не что в нём.
func dnsProbe(t *testing.T, addr string) {
	t.Helper()
	c, err := net.Dial("udp", addr+":53")
	if err != nil {
		t.Fatalf("проба DNS: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("проба")); err != nil {
		t.Fatalf("проба DNS: %v", err)
	}
}

// settle — пауза на то, чтобы утёкший пакет успел дойти. Без неё «ноль
// пакетов» означало бы всего лишь «мы посмотрели раньше, чем он пришёл».
func settle() { time.Sleep(300 * time.Millisecond) } //hop:realtime

// netPeer — стенд в чужом netns: интернет-сервер, IPv6-сервер и системный
// резолвер сразу. Обо всём, что до него дошло, он сообщает строкой в stdout.
type netPeer struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	mu   sync.Mutex
	hits map[string]int
}

func (p *netPeer) count(kind string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hits[kind]
}

func startNetPeer(t *testing.T) *netPeer {
	t.Helper()
	requireNetns(t)
	sh("ip", "link", "del", netVeth)
	mustRun(t, "ip", "link", "add", netVeth, "type", "veth", "peer", "name", peerVeth)

	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(), "HOP_L3_NETPEER=1")
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
		t.Skipf("не удалось создать netns для стенда: %v", err)
	}
	p := &netPeer{cmd: cmd, in: in, hits: map[string]int{}}
	t.Cleanup(func() {
		_ = in.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		sh("ip", "link", "del", netVeth)
	})

	mustRun(t, "ip", "link", "set", peerVeth, "netns", fmt.Sprint(cmd.Process.Pid))
	// nodad: без него глобальный адрес секунду остаётся tentative, и первое
	// соединение падает по причине, к тесту не относящейся.
	for _, args := range [][]string{
		{"ip", "addr", "add", transitOurs, "dev", netVeth},
		{"ip", "-6", "addr", "add", v6Ours, "dev", netVeth, "nodad"},
		{"ip", "link", "set", netVeth, "up"},
		{"ip", "route", "add", inetAddr + "/32", "dev", netVeth},
		{"ip", "route", "add", lanResolver + "/32", "dev", netVeth},
		{"ip", "-6", "route", "add", v6PeerAddr + "/128", "dev", netVeth},
	} {
		mustRun(t, args...)
	}

	if _, err := io.WriteString(in, "go\n"); err != nil {
		t.Fatalf("сигнал стенду: %v", err)
	}
	r := bufio.NewReader(out)
	line, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("стенд не поднялся: %q, %v", line, err)
	}
	go p.collect(r)
	return p
}

// collect читает отчёты стенда до его смерти.
func (p *netPeer) collect(r *bufio.Reader) {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		p.mu.Lock()
		p.hits[strings.TrimSpace(line)]++
		p.mu.Unlock()
	}
}

// netPeerMain — точка входа стенда. Живёт в своём netns, поэтому трогает
// интерфейсы без оглядки.
func netPeerMain() {
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		fmt.Fprintln(os.Stderr, "стенд: нет сигнала:", err)
		os.Exit(1)
	}
	for _, args := range [][]string{
		{"ip", "link", "set", "lo", "up"},
		{"ip", "addr", "add", transitPeer, "dev", peerVeth},
		{"ip", "-6", "addr", "add", v6Peer, "dev", peerVeth, "nodad"},
		{"ip", "link", "set", peerVeth, "up"},
		{"ip", "addr", "add", inetAddr + "/32", "dev", peerVeth},
		{"ip", "addr", "add", lanResolver + "/32", "dev", peerVeth},
		{"ip", "route", "add", "default", "dev", peerVeth},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "стенд: %v: %v: %s\n", args, err, out)
			os.Exit(1)
		}
	}

	report := make(chan string, 64)
	serveTCP(fmt.Sprintf("%s:%d", inetAddr, inetPort), "tcp", report)
	serveTCP(fmt.Sprintf("[%s]:%d", v6PeerAddr, inetPort), "tcp6", report)
	serveUDP(lanResolver+":53", "dns", report)

	fmt.Println("ready")
	for kind := range report {
		fmt.Println(kind)
	}
}

func serveTCP(addr, kind string, report chan<- string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "стенд: listen %s: %v\n", addr, err)
		os.Exit(1)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
			report <- kind
		}
	}()
}

func serveUDP(addr, kind string, report chan<- string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "стенд: listen udp %s: %v\n", addr, err)
		os.Exit(1)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			report <- kind
		}
	}()
}
