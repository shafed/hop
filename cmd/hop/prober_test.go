package main

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/shafed/hop/internal/health"
)

// TestW38ProberHasEveryURL — пробер собран на всех трёх адресах §5.4 (Р39).
//
// Смысл нескольких URL — пережить блокировку одного. Пробер, молча собранный на
// одном, выглядит рабочим ровно до того дня, когда домен заблокируют, и тогда
// вся подписка умирает разом.
func TestW38ProberHasEveryURL(t *testing.T) {
	p := newProber(func(context.Context, string, string, string) (net.Conn, error) {
		return nil, errors.New("не нужен")
	})
	if len(p.Targets) != len(probeURLs) {
		t.Fatalf("таргетов %d, адресов %d", len(p.Targets), len(probeURLs))
	}
	if len(probeURLs) < 2 {
		t.Fatal("адрес один: блокировка домена похоронит всю подписку (§5.4)")
	}
}

// TestW38ProbeGoesThroughOutbound — проба ходит дозвоном, который ей дали, и
// с тем узлом, который проверяют (§6.7).
//
// Проба мимо outbound меряет качество канала до провайдера, а не живость узла,
// и красит мёртвый узел зелёным. Здесь это наблюдается прямо: диалер
// записывает, кого его просили набрать.
func TestW38ProbeGoesThroughOutbound(t *testing.T) {
	var asked atomic.Value
	var calls atomic.Int64

	p := newProber(func(_ context.Context, nodeID, network, addr string) (net.Conn, error) {
		calls.Add(1)
		asked.Store(nodeID)
		// Дозвон отказывает: проверяется путь, а не сеть.
		return nil, errors.New("узел недоступен")
	})

	res := p.Probe(context.Background(), "n7")
	if res.Err == nil {
		t.Fatal("проба через отказавший дозвон удалась — значит шла не через него")
	}
	if calls.Load() == 0 {
		t.Fatal("проба не позвала дозвон: она пошла мимо outbound (§6.7) и мерила бы не узел")
	}
	if got, _ := asked.Load().(string); got != "n7" {
		t.Errorf("дозвон просили о узле %q, проверяли %q", got, "n7")
	}
}

// TestW38ProberWithoutDialRefuses — пробер без диалера отказывает, а не ходит
// напрямую.
//
// Прямая проба нарушила бы §6.7 молча: узел выглядел бы живым, потому что жив
// канал до провайдера.
func TestW38ProberWithoutDialRefuses(t *testing.T) {
	p := newProber(nil)
	res := p.Probe(context.Background(), "n1")
	if res.Err == nil {
		t.Fatal("пробер без диалера отчитался успехом: узел был бы зелёным по чужому каналу")
	}
	if !errors.Is(res.Err, health.ErrNoDial) {
		t.Errorf("ошибка %v, ожидалась ErrNoDial", res.Err)
	}
}
