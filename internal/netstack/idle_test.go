package netstack

import (
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/packettest"
)

// waitNATStats ждёт, пока снимок стека не покажет want записей и want
// сокетов NAT, и падает, если не дождался.
//
// Ожидание, а не единичный снимок сразу после Advance: фоновая уборка
// просыпается от тика инъектируемых часов, но выполняется своей горутиной
// асинхронно. Опрашиваемое — h.st.Stats(), чистое чтение (см. doc natTable.stats
// и Stack.Stats): снимок наблюдаемое не двигает, и опрос в цикле здесь не
// подменяет собой механизм.
func waitNATStats(t *testing.T, h *harness, wantEntries, wantSockets int, why string) {
	t.Helper()
	deadline := time.Now().Add(packettest.WaitTimeout) //hop:realtime
	for {
		st := h.st.Stats()
		if st.NATEntries == wantEntries && st.NATSockets == wantSockets {
			return
		}
		if time.Now().After(deadline) { //hop:realtime
			t.Fatalf("NATEntries=%d NATSockets=%d, ожидались %d/%d: %s",
				st.NATEntries, st.NATSockets, wantEntries, wantSockets, why)
		}
		time.Sleep(time.Millisecond) //hop:realtime
	}
}

// TestW59IdleEntryIsCollectedWithoutTraffic — охраняющая проверка
// nat_idle_sweep (§5.8 регистра, W59).
//
// Утверждение: запись и сокет natTable, простоявшие дольше UDPIdle, закрываются
// сами, без единого внешнего события. После первой датаграммы в этой проверке
// не зовётся ни mapping() (то есть ни один новый пакет), ни внешний Sweep(),
// ни Close() — а именно они были в продукте единственными, кто прокручивал
// уборку.
//
// Без политики проверка краснеет и краснеет по делу: клиент замолчал, запись и
// сокет остаются в снимке до close() стека — ровно та цена, которую пометил
// W51 (bypass_idle_sweep) для своей половины и которую очередь звала «долгом
// natTable».
func TestW59IdleEntryIsCollectedWithoutTraffic(t *testing.T) {
	const idle = 2 * time.Second
	clk := clock.NewFake(time.Unix(1, 0))
	h := newHarness(t, true, func(c *Config) {
		c.Clock = clk
		c.UDPIdle = idle
	})

	h.dev.Inject(packettest.UDP(client, udpPeerA, []byte("hello")))
	h.dialer.WaitConn(client)

	if st := h.st.Stats(); st.NATEntries != 1 || st.NATSockets != 1 {
		t.Fatalf("сразу после датаграммы: %+v, ожидались 1 запись и 1 сокет", st)
	}

	// Трафик прекратился. Часы идут дальше — и это всё, что происходит.
	clk.Advance(3 * idle)

	waitNATStats(t, h, 0, 0, "клиент замолчал дольше UDPIdle, а запись и сокет "+
		"всё ещё в снимке: уборка по-прежнему едет только на чужом событии")
}
