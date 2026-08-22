package dnstest

import (
	"testing"

	"github.com/shafed/hop/internal/phase"
)

func TestPhaseSetAndGet(t *testing.T) {
	p := NewPhase(phase.Waiting)
	if got := p.Get(); got != phase.Waiting {
		t.Fatalf("Get() = %v, хочу %v", got, phase.Waiting)
	}
	p.Set(phase.Proxied)
	if got := p.Get(); got != phase.Proxied {
		t.Fatalf("Get() = %v, хочу %v", got, phase.Proxied)
	}
}

// TestPhaseGetMatchesConfigShape проверяет то, ради чего Get — метод, а не
// поле: p.Get годится напрямую как func() phase.Traffic, без обёртки.
func TestPhaseGetMatchesConfigShape(t *testing.T) {
	p := NewPhase(phase.Bypass)
	var fn func() phase.Traffic = p.Get
	if got := fn(); got != phase.Bypass {
		t.Fatalf("fn() = %v, хочу %v", got, phase.Bypass)
	}
}
