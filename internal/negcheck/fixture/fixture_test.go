// Package fixture — материал мета-проверки negcheck, не продуктовый код.
//
// Здесь лежат ровно два теста: честный и заведомо плохой. negcheck обязан
// пропустить первый и сообщить о втором; тест на это — в internal/negcheck.
package fixture

import (
	"testing"

	"github.com/shafed/hop/internal/policy"
)

// TestFixtureGood краснеет, когда fixture_good выключена, — так и должен вести
// себя настоящий охраняющий тест.
func TestFixtureGood(t *testing.T) {
	if !policy.FixtureGood.On() {
		t.Fatal("политика выключена, тест обязан покраснеть")
	}
}

// TestFixtureBad зелен всегда. Это и есть дефект, который negcheck ищет.
func TestFixtureBad(t *testing.T) {
	_ = policy.FixtureBad.On()
}
