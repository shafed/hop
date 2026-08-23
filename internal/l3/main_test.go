//go:build linux

package l3

import (
	"os"
	"testing"
)

// TestMain даёт тестовому бинарю второе лицо: с HOP_L3_PEER он не гоняет
// тесты, а работает эхосервером в своём netns (см. routecache_test.go).
func TestMain(m *testing.M) {
	if os.Getenv("HOP_L3_PEER") != "" {
		peerMain()
		return
	}
	os.Exit(m.Run())
}
