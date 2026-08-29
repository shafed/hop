package bypass

import (
	"runtime"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/packettest"
	"github.com/shafed/hop/internal/policy"
)

// waitSockets ждёт, пока NAT не станет держать want сокетов, и падает, если не
// дождался. Ожидание по настоящим часам здесь не проверяемый интервал, а
// синхронизация с чужой горутиной: фоновая уборка просыпается от тика
// инъектируемых часов, но выполняется асинхронно, и снимок сразу после
// Advance законно застаёт её на полпути. Проверяемое время — только Fake.
func waitSockets(t *testing.T, n *NAT, want int, why string) {
	t.Helper()
	deadline := time.Now().Add(readTimeout) //hop:realtime
	for {
		got := n.Stats().Sockets
		if got == want {
			return
		}
		if time.Now().After(deadline) { //hop:realtime
			t.Fatalf("Sockets = %d, ожидался %d: %s", got, want, why)
		}
		time.Sleep(time.Millisecond) //hop:realtime
	}
}

// TestW51IdleSocketIsCollectedWithoutTraffic — охраняющая проверка
// bypass_idle_sweep (§5.8 регистра, W51).
//
// Утверждение: сокет, простоявший дольше Idle, закрывается сам, без единого
// внешнего события. Ни Send, ни Stats, ни Close в этой проверке после первой
// датаграммы не зовутся — а именно они были в продукте единственными, кто
// прокручивал уборку. Наблюдаемое — Stats().Sockets, и это чистое чтение (см.
// doc у Stats): снимок наблюдаемое не двигает, поэтому опрос в цикле здесь не
// подменяет собой механизм.
//
// Без политики проверка краснеет и краснеет по делу: клиент замолчал, сокет
// остался открытым до Close, и это ровно та цена, которую прошлый проход
// назвал вслух, вынося прокрутку из Stats().
func TestW51IdleSocketIsCollectedWithoutTraffic(t *testing.T) {
	listener := newListener(t)
	clk := clock.NewFake(time.Unix(0, 0))

	const idle = 2 * time.Second
	n, err := New(Config{
		Control: countingControl(new(int32)),
		Reply:   func([]byte) {},
		Clock:   clk,
		Idle:    idle,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.Close()

	listenerAddr := addrPortOf(t, listener.LocalAddr())
	if err := n.Send(packettest.UDP(client, listenerAddr, []byte("mdns"))); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := n.Stats().Sockets; got != 1 {
		t.Fatalf("Sockets = %d сразу после Send, ожидался 1", got)
	}

	// Трафик прекратился. Часы идут дальше — и это всё, что происходит.
	clk.Advance(3 * idle)

	waitSockets(t, n, 0, "клиент замолчал дольше Idle, а сокет всё ещё открыт: "+
		"уборка по-прежнему едет только на чужом событии")
}

// TestW51IdleSweepDoesNotOutliveClose — цена механизма, названная вслух и
// замеренная. Фоновая уборка — это горутина и тикер, то есть ровно та пара,
// которой свойственно пережить владельца. NAT заводится и закрывается, не
// отправив ни одной датаграммы: горутин чтения нет вовсе, поэтому всё, что
// видно счётчику, — это уборщик.
//
// Проверка не охраняет политику: при выключенной она пропускается, потому что
// утверждать в такой сборке нечего — уборщика нет и течь нечему. Охраняет
// TestW51IdleSocketIsCollectedWithoutTraffic.
func TestW51IdleSweepDoesNotOutliveClose(t *testing.T) {
	if !policy.BypassIdleSweep.On() {
		t.Skip("bypass_idle_sweep выключен: фоновой уборки нет, течь нечему")
	}

	before := runtime.NumGoroutine()

	n, err := New(Config{
		Control: countingControl(new(int32)),
		Reply:   func([]byte) {},
		Idle:    time.Millisecond, // тикер настоящих часов, чтобы он реально тикал
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	deadline := time.Now().Add(readTimeout) //hop:realtime
	for runtime.NumGoroutine() <= before {
		if time.Now().After(deadline) { //hop:realtime
			t.Fatalf("после New горутин %d, было %d: фоновая уборка не заведена",
				runtime.NumGoroutine(), before)
		}
		time.Sleep(time.Millisecond) //hop:realtime
	}

	n.Close()

	// Close дожидается своей WaitGroup, так что уборщик к этому моменту вернулся;
	// опрос — на гонку рантайма между Done() и снятием горутины со стека, как в
	// TestBypassCloseStopsGoroutines.
	deadline = time.Now().Add(readTimeout) //hop:realtime
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) { //hop:realtime
			t.Fatalf("горутины не остановились после Close: сейчас %d, было %d — "+
				"уборщик пережил владельца", runtime.NumGoroutine(), before)
		}
		time.Sleep(5 * time.Millisecond) //hop:realtime
	}
}
