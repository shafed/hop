package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/tunnel"
	"time" //hop:realtime
)

// Вторая половина W69 — та, которую L3 не достаёт.
//
// На стенде воспроизводится ровно один способ потерять туннель: файла токена
// нет вовсе. Второй способ — токен есть, а сервис его не принял (чужой сеанс,
// чужой владелец, §3.1) — на стенде стоил бы второго пользователя в netns, а
// разница между двумя отказами вся в тексте. Здесь она и проверяется: связка
// не поднимается, сервис — интерфейс `control`, тот же шов, что у W39/W40.

// orphanControl — сервис, застрявший в orphaned.
type orphanControl struct {
	phase     tunnel.Phase
	left      time.Duration
	reason    tunnel.Reason
	device    string
	attachErr error
}

func (c *orphanControl) Start(tunnel.Params) (ipc.Result, error) {
	// Дословно то, что приезжает от машины состояний через IPC: текстом, а не
	// типом, — ошибки через границу едут строкой (internal/ipc/client.go).
	return ipc.Result{}, fmt.Errorf("%v: %s, ожидалось down", tunnel.ErrWrongPhase, c.phase)
}

func (c *orphanControl) Attach(tunnel.Token) (ipc.Result, error) {
	if c.attachErr == nil {
		c.attachErr = errors.New("реаттача нет")
	}
	return ipc.Result{}, c.attachErr
}

func (c *orphanControl) Stop() error                { return nil }
func (c *orphanControl) Heartbeat() error           { return nil }
func (c *orphanControl) Detach(tunnel.Reason) error { return nil }
func (c *orphanControl) Status() (tunnel.State, error) {
	return tunnel.State{Phase: c.phase, OrphanLeft: c.left, DetachReason: c.reason, Device: c.device}, nil
}

// TestW69RefusalNamesWhyTheTunnelCannotBeTaken — отказ различает две причины,
// по которым туннель не забрали, и обе называет.
//
// Различать обязательно: «токен не найден» на месте «токен отвергнут» — это не
// неточность, а неверный совет. Пользователь, у которого файл на месте, пойдёт
// его искать, а искать нужно владельца туннеля.
func TestW69RefusalNamesWhyTheTunnelCannotBeTaken(t *testing.T) {
	dir := t.TempDir()
	orphaned := func() *orphanControl {
		return &orphanControl{
			phase:  tunnel.Orphaned,
			left:   12 * time.Second,
			reason: tunnel.ReasonClosed,
			device: "hop0",
		}
	}

	t.Run("токена нет", func(t *testing.T) {
		tr := newTransport(orphaned(), filepath.Join(dir, "нет-такого"), time.Second, quietLog())
		_, err := tr.acquire(tunnel.Params{Name: "hop0"})
		requireOrphanRefusal(t, err)
		if !strings.Contains(err.Error(), "не найден") {
			t.Errorf("отказ не сказал, что токена нет: %v", err)
		}
	})

	t.Run("токен есть, сервис его не принял", func(t *testing.T) {
		tok := filepath.Join(dir, "token")
		if err := os.WriteFile(tok, []byte("чужой"), 0o600); err != nil {
			t.Fatal(err)
		}
		cl := orphaned()
		cl.attachErr = errors.New(tunnel.ErrWrongOwner.Error())

		tr := newTransport(cl, tok, time.Second, quietLog())
		_, err := tr.acquire(tunnel.Params{Name: "hop0"})
		requireOrphanRefusal(t, err)
		if strings.Contains(err.Error(), "не найден") {
			t.Errorf("отказ соврал про отсутствие токена — файл на месте: %v", err)
		}
		if !strings.Contains(err.Error(), "другому владельцу") {
			t.Errorf("отказ не назвал, почему сервис отверг токен: %v", err)
		}
	})

	// Контроль обратной стороны: вне orphaned отказ не подменяется. Иначе
	// «туннель уже поднят этим же агентом» получил бы совет `hop down` и
	// рассказ про чужой сеанс.
	t.Run("фаза не orphaned — отказ проходит насквозь", func(t *testing.T) {
		cl := orphaned()
		cl.phase = tunnel.Up
		tr := newTransport(cl, filepath.Join(dir, "нет-такого"), time.Second, quietLog())
		_, err := tr.acquire(tunnel.Params{Name: "hop0"})
		if err == nil || !strings.Contains(err.Error(), "ожидалось down") {
			t.Fatalf("отказ вне orphaned подменён: %v", err)
		}
	})
}

// requireOrphanRefusal — общее для обеих причин: жаргона нет, смысл и выход
// есть.
func requireOrphanRefusal(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("Start отказал, а acquire вернул успех")
	}
	if strings.Contains(err.Error(), "ожидалось down") {
		t.Fatalf("в отказе осталась фраза машины состояний (§5.6): %v", err)
	}
	for _, want := range []string{"hop0", "осиротел", "`hop down`", "12 с"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("в отказе нет %q: %v", want, err)
		}
	}
}
