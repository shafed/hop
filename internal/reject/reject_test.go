package reject

import (
	"net/netip"
	"testing"

	"github.com/shafed/hop/internal/packettest"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

var (
	client = ap("10.255.0.2:51000")
	remote = ap("93.184.216.34:443")
)

// TestReplyRefusesInsteadOfSilence — половина T23b без прав и без TUN, на всех
// трёх ОС: приложение, ткнувшееся наружу в состоянии orphaned, обязано
// получить отказ, а не тишину (§5.6).
//
// Охраняющий тест политики orphan_reject: с выключенной политикой дренаж
// кольца остаётся, а ответов нет — устройство молчит, и тест краснеет.
func TestReplyRefusesInsteadOfSilence(t *testing.T) {
	dev := packettest.NewFake(1400)
	done := make(chan error, 1)
	go func() { done <- Serve(dev) }()

	dev.Inject(
		packettest.TCPSyn(client, remote, 1000),
		packettest.UDP(client, ap("8.8.8.8:53"), []byte("query")),
	)

	emitted := dev.WaitEmitted(t, 2)
	dev.Close()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}

	rst := header.IPv4(emitted[0])
	if header.TCP(rst.Payload()).Flags()&header.TCPFlagRst == 0 {
		t.Fatalf("первый ответ не TCP RST: % x", emitted[0])
	}
	icmp := header.ICMPv4(header.IPv4(emitted[1]).Payload())
	if icmp.Type() != header.ICMPv4DstUnreachable || icmp.Code() != header.ICMPv4PortUnreachable {
		t.Fatalf("второй ответ не ICMP port unreachable: % x", emitted[1])
	}
}

// RST обязан быть адресован обратно клиенту и в его же порт, иначе стек его
// проигнорирует и приложение всё равно повиснет — то есть отказ будет
// формальным.
func TestRSTAddressedBackToClient(t *testing.T) {
	out := Reply(packettest.TCPSyn(client, remote, 1000))
	if out == nil {
		t.Fatal("на SYN не построен RST")
	}
	ip := header.IPv4(out)
	if got := ip.SourceAddress().String(); got != remote.Addr().String() {
		t.Fatalf("src = %s, ожидался %s", got, remote.Addr())
	}
	if got := ip.DestinationAddress().String(); got != client.Addr().String() {
		t.Fatalf("dst = %s, ожидался %s", got, client.Addr())
	}
	tcp := header.TCP(ip.Payload())
	if tcp.SourcePort() != remote.Port() || tcp.DestinationPort() != client.Port() {
		t.Fatalf("порты %d→%d, ожидались %d→%d",
			tcp.SourcePort(), tcp.DestinationPort(), remote.Port(), client.Port())
	}
	// На SYN без ACK ответ — RST|ACK с ack = seq + 1 (RFC 793).
	if tcp.Flags() != header.TCPFlagRst|header.TCPFlagAck {
		t.Fatalf("флаги = %s, ожидались RST|ACK", tcp.Flags())
	}
	if tcp.AckNumber() != 1001 {
		t.Fatalf("ack = %d, ожидался 1001", tcp.AckNumber())
	}
}

// Контрольные суммы считает не ядро, а мы. Ошибка здесь не видна ни в одном
// поле — пакет просто молча отбрасывается стеком, и отказ снова превращается
// в тишину.
func TestChecksums(t *testing.T) {
	for name, out := range map[string][]byte{
		"RST":  Reply(packettest.TCPSyn(client, remote, 1000)),
		"ICMP": Reply(packettest.UDP(client, remote, []byte("x"))),
	} {
		t.Run(name, func(t *testing.T) {
			ip := header.IPv4(out)
			if ip.CalculateChecksum() != 0xffff {
				t.Fatalf("контрольная сумма IPv4 не сходится")
			}
			switch ip.Protocol() {
			case uint8(header.TCPProtocolNumber):
				got := checksum.Checksum(ip.Payload(), header.PseudoHeaderChecksum(
					header.TCPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(),
					uint16(len(ip.Payload()))))
				if got != 0xffff {
					t.Fatalf("контрольная сумма TCP не сходится: %#x", got)
				}
			case uint8(header.ICMPv4ProtocolNumber):
				if checksum.Checksum(ip.Payload(), 0) != 0xffff {
					t.Fatalf("контрольная сумма ICMP не сходится")
				}
			}
		})
	}
}

// ICMP цитирует заголовок исходного пакета и первые 8 байт нагрузки (RFC 792):
// меньше — и отправитель не сопоставит ответ со своим сокетом.
func TestICMPQuotesOriginal(t *testing.T) {
	orig := packettest.UDP(client, remote, []byte("0123456789"))
	out := Reply(orig)
	quote := header.IPv4(out).Payload()[header.ICMPv4MinimumSize:]

	want := header.IPv4MinimumSize + 8
	if len(quote) != want {
		t.Fatalf("цитата %d байт, ожидалось %d", len(quote), want)
	}
	if string(quote) != string(orig[:want]) {
		t.Fatal("цитата не совпадает с началом исходного пакета")
	}
}

// §5.6: исключения действуют и в orphaned. Без них машина теряет DHCP-аренду
// ровно в окне продления, а NTP — синхронизацию.
func TestExclusions(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkt  []byte
	}{
		{"локальная сеть, RFC1918", packettest.TCPSyn(client, ap("192.168.1.1:80"), 1)},
		{"локальная сеть, loopback", packettest.TCPSyn(client, ap("127.0.0.1:80"), 1)},
		{"link-local", packettest.TCPSyn(client, ap("169.254.169.254:80"), 1)},
		{"DHCP на broadcast", packettest.UDP(ap("0.0.0.0:68"), ap("255.255.255.255:67"), nil)},
		{"DHCP на сервер", packettest.UDP(client, ap("8.8.8.8:67"), nil)},
		{"NTP", packettest.UDP(client, ap("216.239.35.0:123"), nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !Excluded(tc.pkt) {
				t.Fatal("пакет не признан исключением §5.6")
			}
			if out := Reply(tc.pkt); out != nil {
				t.Fatalf("на исключение построен ответ: % x", out)
			}
		})
	}
}

// TestDNSInOrphanedRefusesEvenToLocalRouter — стык §5.7б с §6.2, найденный
// этапом 6, и второй охраняющий тест политики orphan_reject.
//
// Запрос к локальному роутеру заведён в туннель маршрутами (§3.4, п. 1:
// hijack-dns стоит выше bypass, иначе перехват формально работает, а запросы
// уходят провайдеру). В orphaned он приходит на устройство, и по адресу это
// ровно RFC1918 — то есть исключение §5.6. Если считать его исключением,
// приложение получает не отказ, а полный таймаут резолвера на каждое имя.
func TestDNSInOrphanedRefusesEvenToLocalRouter(t *testing.T) {
	router := ap("192.168.1.1:53")

	dev := packettest.NewFake(1400)
	done := make(chan error, 1)
	go func() { done <- Serve(dev) }()

	dev.Inject(
		packettest.UDP(client, router, []byte("query")),
		packettest.TCPSyn(client, router, 1000),
	)

	emitted := dev.WaitEmitted(t, 2)
	dev.Close()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}

	icmp := header.ICMPv4(header.IPv4(emitted[0]).Payload())
	if icmp.Type() != header.ICMPv4DstUnreachable || icmp.Code() != header.ICMPv4PortUnreachable {
		t.Fatalf("на DNS по UDP ответ не ICMP port unreachable: % x", emitted[0])
	}
	rst := header.IPv4(emitted[1])
	if header.TCP(rst.Payload()).Flags()&header.TCPFlagRst == 0 {
		t.Fatalf("на DNS по TCP ответ не RST: % x", emitted[1])
	}

	// А вот остальной локальный трафик исключением быть не перестал: иначе в
	// orphaned ломается печать, Bonjour и всё, ради чего §6.10 их выпускает.
	if !Excluded(packettest.TCPSyn(client, ap("192.168.1.1:80"), 1)) {
		t.Fatal("локальный трафик перестал быть исключением §5.6")
	}
}

// Ответ на RST породил бы петлю: наш RST вернулся бы к нам и снова вызвал RST.
func TestNoReplyToRST(t *testing.T) {
	rst := Reply(packettest.TCPSyn(client, remote, 1000))
	if out := Reply(rst); out != nil {
		t.Fatalf("на RST построен ответ — это петля: % x", out)
	}
}

// Мусор с границы не должен ронять привилегированный процесс.
func TestGarbageIsIgnored(t *testing.T) {
	for _, pkt := range [][]byte{
		nil,
		{0x45},
		make([]byte, 20),            // нулевой заголовок: версия не 4
		{0x60, 0, 0, 0, 0, 0, 0, 0}, // IPv6 — §6.9 блокирует его маршрутами
		packettest.TCPSyn(client, remote, 1)[:22], // обрезан на границе
	} {
		if out := Reply(pkt); out != nil {
			t.Fatalf("на мусор построен ответ: % x", out)
		}
	}
}
