package agent

import (
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/packettest"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/tunnel"
)

// TestW54AgentPublishesStackStats — W54: счётчики стека доходят до
// пользователя, и их отсутствие не выдаётся за нули.
//
// Проверка держит три утверждения сразу, и каждое из них — про честность, а
// не про арифметику:
//
//   - без поднятого туннеля стека нет, и второе значение ложно. Нули за
//     несуществующий стек означали бы «датаплейн работает и ничего не
//     произошло» — ровно та ложь, ради которой у `DNSStats` второе значение и
//     появилось;
//   - с поднятым туннелем числа настоящие: пакет, который стек дропнул,
//     виден снаружи;
//   - после `Down` второе значение снова ложно. Счётчики живут ровно столько,
//     сколько стек: `Up` собирает новый и обнуляет их, и молчаливое
//     «продолжение» прошлых чисел было бы вымыслом.
func TestW54AgentPublishesStackStats(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	st, err := store.Open(t.TempDir(), clk)
	if err != nil {
		t.Fatalf("стор не открылся: %v", err)
	}
	tr := newFakeTransport()

	a, err := New(Config{
		Store:   st,
		Health:  health.New(health.Config{Clock: clk}),
		Trans:   tr,
		Clock:   clk,
		Params:  tunnel.Params{Name: "hop0", MTU: 1400, Addr: "10.255.0.1/24", Table: 8420},
		NewXray: (&xrayLog{}).factory(),
	})
	if err != nil {
		t.Fatalf("связка не собралась: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	if _, ok := a.StackStats(); ok {
		t.Fatal("без туннеля StackStats отдала снимок: нулей за несобранный стек быть не должно")
	}

	if err := a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	// Пакет, который стек обязан дропнуть: версия 6 в первом полубайте,
	// разбор IPv4 его не берёт. Считается в Blocked — детерминированно и без
	// сети, в отличие от любого счётчика, которому нужен настоящий дозвон.
	bad := make([]byte, 40)
	bad[0] = 0x60
	tr.device().Inject(bad)

	// Ожидание — тем же приёмом, что у FakeDevice.WaitEmitted: потолок на
	// настоящих часах, потому что ждём мы чужую горутину, а не время.
	timeout := clock.System{}.After(packettest.WaitTimeout) //hop:realtime
	var blocked int64
poll:
	for blocked == 0 {
		s, ok := a.StackStats()
		if !ok {
			t.Fatal("с поднятым туннелем StackStats отказала")
		}
		blocked = s.Blocked
		select {
		case <-timeout:
			break poll
		case <-clock.System{}.After(time.Millisecond): //hop:realtime
		}
	}
	if blocked == 0 {
		t.Fatal("дропнутый пакет не доехал до пользователя: Blocked остался нулём")
	}

	if err := a.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if _, ok := a.StackStats(); ok {
		t.Fatal("после Down StackStats всё ещё отдаёт снимок: числа снятого стека — вымысел")
	}
}
