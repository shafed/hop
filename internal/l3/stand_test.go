//go:build linux

package l3

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/shafed/hop/internal/dnsmsg"
	"github.com/shafed/hop/internal/dnstest"
)

// Вторая половина стенда: сеть, которую туннель **забирает себе**.
//
// Первая половина (10.9.9.0/24, routecache_test.go) для T25–T27 не годится, и
// это не мелочь, а причина, по которой их нельзя было написать поверх готового
// пира. 10.0.0.0/8 стоит в platform.LocalPrefixes: §5.6 выпускает локальные
// сети мимо туннеля правилом приоритета 31000, выше туннельного. Узел на
// 10.9.9.2 обходил бы туннель по исключению, а не по защите от петли, и T25
// был бы зелен, даже если бы §6.8 не существовало вовсе.
//
// Поэтому вторая сеть — TEST-NET-2 (RFC 5737), которую ни одно исключение §5.6
// не называет: правило туннеля (31000 < 32000 < main) забирает её целиком, и
// `ip route get 198.51.100.2` при поднятом туннеле ведёт в hopt0. Это и делает
// стенд способным утечь — без чего краснота T25/T26/T27 ничего бы не значила.
const (
	siteLocalCIDR = "198.51.100.1/24" // адрес клиентской стороны на veth0
	siteLocalAddr = "198.51.100.1"
	siteCIDR      = "198.51.100.2/24" // «интернет» и узел: сторона пира
	siteAddr      = "198.51.100.2"
	// decoyCIDR — «подставной системный резолвер» T26. Отдельный адрес, а не
	// второй порт того же: T26 утверждает, что запрос ушёл НЕ туда, и
	// различать адресатов по портам одного адреса значило бы проверять
	// маршрут к адресу, который в обоих случаях один.
	decoyCIDR = "198.51.100.3/24"
	decoyAddr = "198.51.100.3"

	// nodePort — «узел» стенда. Настоящего VLESS за ним нет: T25 смотрит на
	// то, каким интерфейсом уходит пакет к узлу, а не на то, чем кончилось
	// рукопожатие. Слушатель нужен, чтобы соединение дошло до accept и его
	// адрес источника был виден.
	nodePort = 9443
	// sitePort — «интернет-сервер, доступный напрямую» (T27).
	sitePort = 8080
	dnsPort  = 53

	// standUUID — пользователь узла в ссылке. Не секрет: узел локальный и
	// VLESS на нём не поднят (§6.14 про настоящие ключи, здесь их нет).
	standUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

	// decoyAnswer — адрес, которым отвечает подставной резолвер. Отличается от
	// всего, что может ответить продукт: если клиент получил его, запрос ушёл
	// мимо перехвата, и это видно по ответу, а не только по счётчику.
	decoyAnswer = "203.0.113.253"
	// siteAnswer — то же со стороны резолвера за узлом.
	siteAnswer = "203.0.113.254"
)

// standCounts — то, что пир увидел. Списками, а не числами: «сколько» отвечает
// на вопрос T25/T26/T27 наполовину, а «с какого адреса» — целиком. Адрес
// источника и есть доказательство того, каким интерфейсом ушёл пакет.
type standCounts struct {
	NodeConns []string `json:"node_conns"`
	SiteConns []string `json:"site_conns"`
	SiteDNS   []string `json:"site_dns"`
	DecoyDNS  []string `json:"decoy_dns"`
}

// --- сторона пира ---

var stand struct {
	mu sync.Mutex
	standCounts
}

func record(dst *[]string, v string) {
	stand.mu.Lock()
	*dst = append(*dst, v)
	stand.mu.Unlock()
}

// startSiteSide поднимает вторую сеть и её четырёх слушателей внутри netns
// пира. Вызывается из peerMain.
func startSiteSide() {
	for _, args := range [][]string{
		{"ip", "addr", "add", siteCIDR, "dev", "veth1"},
		{"ip", "addr", "add", decoyCIDR, "dev", "veth1"},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "пир: %v: %v: %s\n", args, err, out)
			os.Exit(1)
		}
	}

	listenTCP(net.JoinHostPort(siteAddr, strconv.Itoa(nodePort)), &stand.NodeConns)
	listenTCP(net.JoinHostPort(siteAddr, strconv.Itoa(sitePort)), &stand.SiteConns)
	listenDNS(net.JoinHostPort(siteAddr, strconv.Itoa(dnsPort)), siteAnswer, &stand.SiteDNS)
	listenDNS(net.JoinHostPort(decoyAddr, strconv.Itoa(dnsPort)), decoyAnswer, &stand.DecoyDNS)
}

// listenTCP принимает соединения и записывает адрес источника.
//
// Соединение закрывается сразу: и «узел», и «интернет-сервер» существуют затем,
// чтобы факт прихода был виден снаружи, а не затем, чтобы что-то отдать.
func listenTCP(addr string, dst *[]string) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "пир: listen", addr, err)
		os.Exit(1)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			record(dst, c.RemoteAddr().String())
			c.Close()
		}
	}()
}

// listenDNS отвечает A-записью на всё и записывает имя вопроса.
//
// Отвечает, а не молчит, намеренно: молчащий подставной резолвер нельзя
// отличить от неперехваченного запроса, потерявшегося по дороге, — а T26
// требует различать именно это.
func listenDNS(addr, answer string, dst *[]string) {
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "пир: listen dns", addr, err)
		os.Exit(1)
	}
	ip, err := netip.ParseAddr(answer)
	if err != nil {
		fmt.Fprintln(os.Stderr, "пир: адрес ответа", answer, err)
		os.Exit(1)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q, err := dnsmsg.Parse(buf[:n])
			if err != nil {
				continue
			}
			name := q.Question.Name.String()
			record(dst, name)
			_, _ = pc.WriteTo(dnstest.ResponseA(q.Header.ID, name, 60, ip), from)
		}
	}()
}

// serveStand — управляющий протокол пира: строка «counts» в stdin, строка JSON
// в stdout.
//
// Через тот же канал, которым startPeer уже даёт сигнал и ждёт «ready», а не
// через отдельный сокет: сокет пришлось бы адресовать через ту самую сеть,
// которую тест ломает туннелем, и счётчики отвечали бы «не дошло» ровно тогда,
// когда тест их спрашивает.
func serveStand(in *bufio.Reader) {
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimSpace(line) != "counts" {
			continue
		}
		stand.mu.Lock()
		b, _ := json.Marshal(stand.standCounts)
		stand.mu.Unlock()
		fmt.Println(string(b))
	}
}

// --- сторона теста ---

// counts спрашивает пира, что он видел.
func (p *peerProc) counts(t *testing.T) standCounts {
	t.Helper()
	if _, err := io.WriteString(p.in, "counts\n"); err != nil {
		t.Fatalf("запрос счётчиков у пира: %v", err)
	}
	line, err := p.out.ReadString('\n')
	if err != nil {
		t.Fatalf("ответ пира со счётчиками: %v", err)
	}
	var c standCounts
	if err := json.Unmarshal([]byte(line), &c); err != nil {
		t.Fatalf("разбор счётчиков пира (%q): %v", line, err)
	}
	return c
}

// setupSiteNet поднимает клиентскую сторону обеих сетей стенда.
//
// Дефолтный маршрут через пира обязателен: без него outbound.Selector отдаёт
// ErrNoInterface, и §6.8 отказывает дозвону ещё до первого пакета — тест
// покраснел бы, не проверив ничего (тот же довод, что в bypass_test.go).
func setupSiteNet(t *testing.T) {
	t.Helper()
	mustRun(t, "ip", "addr", "add", localCIDR, "dev", "veth0")
	mustRun(t, "ip", "addr", "add", siteLocalCIDR, "dev", "veth0")
	mustRun(t, "ip", "link", "set", "veth0", "up")
	mustRun(t, "ip", "route", "add", "default", "via", peerAddr, "dev", "veth0")
	t.Cleanup(func() { sh("ip", "route", "del", "default", "via", peerAddr, "dev", "veth0") })
}

// addNode кладёт узел стенда в стор командой продукта.
//
// Именно командой, а не записью файла руками: стор держит эксклюзивный flock
// (§6.14), и тест, пишущий nodes.json мимо продукта, проверял бы собственное
// представление о формате.
func addNode(t *testing.T, root, host string, port int) {
	t.Helper()
	link := fmt.Sprintf("vless://%s@%s:%d?type=raw&security=none#стенд", standUUID, host, port)
	cmd := exec.Command(hopAgent(t), "node", "add", link)
	cmd.Env = append(os.Environ(), "HOP_STORE="+root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hop node add: %v: %s", err, out)
	}
}

// storeRoot — стор, который requireNetns завёл этому тесту.
func storeRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("HOP_STORE")
	if root == "" {
		t.Fatal("HOP_STORE не задан: requireNetns не вызывался")
	}
	return root
}

// probeFromCLI зовёт `hop probe` — путь §6.7 в отдельном процессе.
//
// Со своим стором, и это не обход неудобства, а следствие §6.14: стор держит
// эксклюзивный flock всё время жизни агента, и вторая команда, открывшая тот
// же каталог, отказала бы по замку (HANDOFF, «honest_gaps»). Второй стор с тем
// же узлом даёт то, что нужно T25, — ещё один дозвон продукта до узла, — не
// трогая стор агента.
//
// -ifname туннеля обязателен: без него Selector вправе выбрать сам туннель
// физическим интерфейсом, и «привязка сработала» означало бы привязку к hopt0.
func probeFromCLI(t *testing.T, root string) string {
	t.Helper()
	cmd := exec.Command(hopAgent(t), "probe", "-ifname", ifname)
	cmd.Env = append(os.Environ(), "HOP_STORE="+root)
	out, _ := cmd.CombinedOutput() // код 3 «живых узлов нет» — штатный ответ
	return strings.TrimSpace(string(out))
}

// tunPackets — сколько пакетов ядро отдало в TUN.
//
// Оба счётчика, а не один: пакет, вошедший в устройство и не забранный
// читателем, для T25 такой же пакет на TUN, как доставленный.
//
// Из /proc/net/dev, а не из sysfs: замер — /sys/class/net в этом стенде
// показывает интерфейсы ИСХОДНОГО netns, потому что `unshare -Urn` не трогает
// mount namespace и sysfs остаётся смонтированным от него; файла hopt0 там
// просто нет. /proc/net — из procfs, а он отдаёт netns вызывающего.
func tunPackets(t *testing.T, dev string) int {
	t.Helper()
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		t.Fatalf("/proc/net/dev: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) != dev {
			continue
		}
		f := strings.Fields(rest)
		// Колонки /proc/net/dev: 8 приёмных, затем 8 передающих. Передающие
		// packets — вторая из них, dropped — четвёртая.
		if len(f) < 12 {
			t.Fatalf("/proc/net/dev: строка %q короче 16 колонок", line)
		}
		total := 0
		for _, i := range []int{9, 11} {
			n, err := strconv.Atoi(f[i])
			if err != nil {
				t.Fatalf("/proc/net/dev: колонка %d в %q: %v", i, line, err)
			}
			total += n
		}
		return total
	}
	t.Fatalf("/proc/net/dev: интерфейса %s нет", dev)
	return 0
}
