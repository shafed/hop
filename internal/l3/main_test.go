//go:build linux

package l3

import (
	"os"
	"testing"
)

// TestMain даёт тестовому бинарю ещё два лица: с HOP_L3_PEER он работает
// эхосервером в своём netns (routecache_test.go), с HOP_L3_NETPEER — стендом
// «интернета» и локальной сети (netguard_test.go). Отдельная программа ради
// полусотни строк завела бы ещё один шаг сборки в CI.
func TestMain(m *testing.M) {
	switch {
	case os.Getenv("HOP_L3_PEER") != "":
		peerMain()
		return
	case os.Getenv("HOP_L3_NETPEER") != "":
		netPeerMain()
		return
	}
	os.Exit(m.Run())
}
