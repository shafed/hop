package netstack

import (
	"net/netip"
	"testing"

	"github.com/shafed/hop/internal/packettest"
)

// Хост в локальной сети, до которого TCP-поток получает вердикт Bypass:
// 192.168.0.0/16 стоит в alwaysBypass правилом без протокола, то есть
// совпадает и с TCP.
var lanHost = netip.MustParseAddrPort("192.168.1.10:445")

// T33 (§8.3). TCP-поток с вердиктом bypass получает RST, а не тишину.
//
// Приёмник bypass несёт только UDP (bypass.ErrUnsupported), поэтому до этого
// теста TCP SYN на RFC1918 заканчивался счётчиком Blocked и молчаливым дропом,
// а приложение висело до собственного connect timeout — ровно тот отказ,
// который §5.6 запрещает: «закрытие — отказ, а не молчание».
//
// Стенд намеренно с живым узлом: это не fail-close. Узлы живы, туннель открыт,
// и отказ означает «этим путём такой поток не пройдёт», а не «выхода нет».
// Именно поэтому охраняет он свой флаг, bypass_tcp_reject, а не reject_mode.
//
// Охраняющий тест bypass_tcp_reject: с выключенной политикой RST не строится
// вовсе, и WaitEmitted ждёт полный таймаут — то самое поведение, ради которого
// написан §5.6.
func TestT33TCPToLocalNetworkGetsRST(t *testing.T) {
	h := newHarness(t, true)

	h.dev.Inject(packettest.TCPSyn(client, lanHost, 4242))
	h.dev.WaitEmitted(t, 1)

	rst := h.dev.ExpectRST(t)
	if src, dst := endpoints(rst); src != lanHost || dst != client {
		t.Fatalf("RST адресован %v → %v, ожидалось %v → %v", src, dst, lanHost, client)
	}

	// Отрицательная половина: пакет никуда не ушёл — ни в приёмник bypass,
	// который его всё равно не несёт, ни в туннель.
	if pkts := h.byp.Packets(); len(pkts) != 0 {
		t.Fatalf("TCP ушёл в приёмник bypass: %d пакетов", len(pkts))
	}
	if dialed := h.dialer.TCPDialed(); len(dialed) != 0 {
		t.Fatalf("TCP в локальную сеть ушёл в туннель: %v", dialed)
	}
	if st := h.st.Stats(); st.Rejected != 1 || st.Blocked != 0 {
		t.Fatalf("отказ не учтён как отказ: %+v", st)
	}
}
