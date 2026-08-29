//go:build linux

package l3

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBypassMDNSReachesPhysicalInterfaceAndReturnsViaNAT — T31 из §8.4:
// L3-версия того, что internal/agent/bypass_test.go доказывает на фейковом
// устройстве и loopback: весь путь agent → netstack (вердикт Bypass) →
// bypass.NAT → физический сокет → обратно, но здесь физический интерфейс
// настоящий (veth), а не фейковая заглушка. Симметрично тому, чем
// interrupt_test.go стал для W8/W14 (harness_test.go).
//
// В продукте mDNS до туннеля не доходит вовсе: 224.0.0.0/4 стоит правилом
// выше туннельного (internal/platform.LocalPrefixes, prioExclusions в
// internal/platform/linux.go). BypassSink существует ровно на случай, если
// это правило не встало (§6.10), и тест этот случай воспроизводит — вместо
// того, чтобы полагаться на исключение, тест добавляет для одной-единственной
// группы (224.0.0.251/32) правило выше приоритетом, уводящее её в туннельную
// таблицу, и не трогает то, что разложил hopd.
func TestBypassMDNSReachesPhysicalInterfaceAndReturnsViaNAT(t *testing.T) {
	requireNetns(t)

	peer := startPeer(t)
	defer peer.stop()

	// "Физический" интерфейс агента — veth0 с настоящим default route на
	// пира: без него outbound.Selector.Interface() отдаёт ErrNoInterface, и
	// bypass.NAT.socketFor откажет ещё до первого пакета (internal/bypass,
	// internal/outbound/selector_linux.go: findDefaultInterface читает
	// default-маршрут в main).
	mustRun(t, "ip", "addr", "add", localCIDR, "dev", "veth0")
	mustRun(t, "ip", "link", "set", "veth0", "up")
	mustRun(t, "ip", "route", "add", "default", "via", peerAddr, "dev", "veth0")
	t.Cleanup(func() { sh("ip", "route", "del", "default", "via", peerAddr, "dev", "veth0") })

	// Ни агент, ни сервис не останавливаются штатно (в отличие от T22): тест
	// проверяет доставку, а не цикл up/down, и штатный уход агента здесь не
	// нужен. Уборка — t.Cleanup сервиса и агента (harness_test.go), тот же
	// приём, что у T21/T23-fast: жёсткий kill и снятие интерфейса/правил по
	// месту, независимо от того, что успел сделать сам процесс.
	s := startService(t, orphanDeadline)
	s.startAgent(filepath.Join(t.TempDir(), "token"))

	// Замер (см. отчёт задачи 3): `ip rule add to <группа>/32 lookup <table>
	// priority <N>` с N меньше prioExclusions=31000 действительно уводит
	// именно эту группу в туннельную таблицу — `ip route get 224.0.0.251`
	// после установки правила показывает dev hopt0/table 8421, тогда как
	// `ip route get 239.255.255.250` (SSDP, той же командой) остаётся на
	// физическом пути. mdnsRulePrio выбран далеко от диапазона, которым
	// распоряжается hopd (31000/31500/32000, dropHopRules в harness_test.go),
	// чтобы уборка сервиса не могла случайно снять наше правило и наоборот.
	mustRun(t, "ip", "rule", "add", "to", mdnsGroup+"/32", "lookup", fmt.Sprint(table),
		"priority", fmt.Sprint(mdnsRulePrio))
	t.Cleanup(func() { sh("ip", "rule", "del", "priority", fmt.Sprint(mdnsRulePrio)) })

	if got := sh("ip", "route", "get", mdnsGroup); !strings.Contains(got, ifname) {
		t.Fatalf("маршрут к группе mDNS не ведёт в туннель: %s", got)
	}

	client, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("клиентский сокет: %v", err)
	}
	defer client.Close()

	payload := []byte("_services._dns-sd._udp.local")
	dst := &net.UDPAddr{IP: net.ParseIP(mdnsGroup), Port: mdnsPort}
	if _, err := client.WriteTo(payload, dst); err != nil {
		t.Fatalf("отправка mDNS-запроса: %v", err)
	}

	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil { //hop:realtime
		t.Fatalf("дедлайн: %v", err)
	}
	buf := make([]byte, 1500)
	n, from, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ответ от пира не пришёл (запрос не дошёл до физического "+
			"интерфейса или обратный NAT-путь не сработал): %v", err)
	}
	got := string(buf[:n])

	// 1. Пир получил запрос — доказано самим фактом ответа (peerMain отвечает
	// только из обработчика ReadFromUDP, см. startMDNSResponder) и тем, что
	// ответ несёт эхо присланной нагрузки.
	if !strings.Contains(got, "payload="+string(payload)) {
		t.Fatalf("пир ответил не на нашу нагрузку: %q", got)
	}

	// 2. Адрес источника, увиденный пиром, — адрес veth0 (localAddr), а не
	// адрес клиента в туннеле (addr, 10.255.0.1): путь действительно NAT, а
	// не прозрачный форвард (§6.8).
	localAddr := strings.SplitN(localCIDR, "/", 2)[0]
	tunAddr := strings.SplitN(addr, "/", 2)[0]
	if !strings.Contains(got, "src="+localAddr+":") {
		t.Fatalf("пир увидел не адрес физического интерфейса: %q (ожидался %s)", got, localAddr)
	}
	if strings.Contains(got, "src="+tunAddr+":") {
		t.Fatalf("пир увидел адрес клиента в туннеле — это форвард, а не NAT: %q", got)
	}

	// 3. Ответ клиенту пришёл с адреса самого респондера, не транслированным
	// повторно: полный круг NAT (§5.3 full-cone на обратном пути) собирает
	// bypass.NAT.receive, адресуя ответ как есть.
	if !strings.HasPrefix(from.String(), peerAddr+":") {
		t.Fatalf("ответ пришёл с %v, ожидался пир %s", from, peerAddr)
	}
}

// Группа и порт mDNS (§6.10). Совпадают с internal/netstack/verdict.go
// (addrMDNS, portMDNS), но тест не импортирует internal/netstack: пакет l3
// проверяет собранные бинари как чёрный ящик, через настоящую сеть, а не их
// внутренности.
const (
	mdnsGroup = "224.0.0.251"
	mdnsPort  = 5353
	// mdnsRulePrio — приоритет тестового правила, уводящего mDNS в туннельную
	// таблицу вместо исключения §5.6. Далеко и ниже (то есть приоритетнее)
	// prioExclusions=31000 из internal/platform/linux.go и вне диапазона,
	// которым распоряжается hopd (31000/31500/32000).
	mdnsRulePrio = 20000
)

// startMDNSResponder поднимает на veth1 (сторона пира) UDP-приёмник группы
// mDNS и отвечает на каждый пакет юникастом, вкладывая в ответ увиденный
// адрес источника и полученную нагрузку — это и есть прямая проверка того,
// что путь до пира NAT'ится, а не форвардится прозрачно (bypass_test.go,
// задача 3, §6.8: «сокет агента — не прозрачный форвард»).
//
// Вызывается из peerMain (routecache_test.go) после того, как veth1 поднят и
// адресован; TCP-эхосервер той же функции не трогает.
func startMDNSResponder() {
	// Ошибки здесь фатальны и уходят в stderr, а не в stdout: stdout несёт
	// протокол "ready\n" для startPeer, и лишняя строка там превратила бы
	// понятный отказ mDNS-приёмника в непонятный отказ разбора "ready".
	iface, err := net.InterfaceByName("veth1")
	if err != nil {
		fmt.Fprintln(os.Stderr, "пир: mdns iface:", err)
		os.Exit(1)
	}
	group := &net.UDPAddr{IP: net.ParseIP(mdnsGroup), Port: mdnsPort}
	conn, err := net.ListenMulticastUDP("udp4", iface, group)
	if err != nil {
		fmt.Fprintln(os.Stderr, "пир: mdns listen:", err)
		os.Exit(1)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			reply := fmt.Sprintf("src=%s payload=%s", from.String(), buf[:n])
			_, _ = conn.WriteToUDP([]byte(reply), from)
		}
	}()
}
