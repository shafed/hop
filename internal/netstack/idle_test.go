package netstack

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/packettest"
	"github.com/shafed/hop/internal/policy"
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

// sweepers — сколько сейчас живёт горутин фоновой уборки natTable.
//
// По стеку, а не по runtime.NumGoroutine(): счётчик горутин отвечает на другой
// вопрос. Замер (контроллер, слияние прохода W59): проверка, сравнивавшая
// NumGoroutine до и после New, оставалась зелёной даже с ЗАКОММЕНТИРОВАННЫМ
// startIdleSweeper — в счётчик попадает всё, что в этот момент заводит или
// доживает рантайм, и «горутин стало больше» не значит «завелась именно та».
// Имя функции в дампе стека — единственное, что здесь различает уборщика.
func sweepers() int {
	// Буфер растёт, пока дамп не влезет целиком: runtime.Stack молча
	// обрезает по длине, а обрезанный дамп даёт заниженное число — то есть
	// зелёную проверку там, где горутина есть. Замер: на 64 КиБ и пяти
	// прогонах подряд счёт срывался с 1 на 0 и на 3.
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), "netstack.(*natTable).sweepLoop")
		}
		buf = make([]byte, 2*len(buf))
	}
}

// waitSweepers ждёт, пока число живых уборщиков не станет want.
//
// Ожидание, а не снимок, и с обеих сторон. Замер (контроллер, слияние прохода
// W59): только что заведённая горутина в дампе появляется НЕ мгновенно —
// снимок сразу после New видел ноль примерно на одном прогоне из двадцати; а
// после Close горутина, чей `defer Done()` уже выполнен, ещё доживает
// несколько инструкций и мгновение видна. Утверждения это не ослабляет:
// незаведённая уборка не заведётся и за две секунды, пережившая владельца — не
// исчезнет.
func waitSweepers(t *testing.T, want int, why string) {
	t.Helper()
	deadline := time.Now().Add(packettest.WaitTimeout) //hop:realtime
	for {
		n := sweepers()
		if n == want {
			return
		}
		if time.Now().After(deadline) { //hop:realtime
			t.Fatalf("уборщиков %d, ожидалось %d: %s", n, want, why)
		}
		time.Sleep(time.Millisecond) //hop:realtime
	}
}

// TestW59SweepDoesNotOutliveClose — цена механизма, измеренная явно. Фоновая
// уборка — это горутина и тикер, то есть ровно та пара, которой свойственно
// пережить владельца. Стек заводится и закрывается, не отправив ни одной
// датаграммы.
//
// Проверка не охраняет политику: при выключенной она пропускается — уборщика
// нет, течь нечему. Охраняет TestW59IdleEntryIsCollectedWithoutTraffic.
func TestW59SweepDoesNotOutliveClose(t *testing.T) {
	if !policy.NATIdleSweep.On() {
		t.Skip("nat_idle_sweep выключен: фоновой уборки нет, течь нечему")
	}

	// Счёт относительный: соседние проверки этого же пакета держат свои стеки
	// живыми до своего Cleanup, и их уборщики видны в общем дампе.
	base := sweepers()

	dev := packettest.NewFake(1500)
	st, err := New(Config{
		Device:  dev,
		Clock:   clock.NewFake(time.Unix(1, 0)),
		UDPIdle: time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Часы стоят: уборщик заведён, но не тикает ни разу — здесь проверяется
	// его существование, а не работа (работу проверяет соседний тест).
	waitSweepers(t, base+1, "после New фоновая уборка не заведена")

	done := make(chan error, 1)
	go func() { done <- st.Run() }()

	dev.Close()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	st.Close()

	waitSweepers(t, base, "уборщик пережил владельца")
}
