//go:build linux

package outbound

import (
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestSelectDefaultSkipsTunnelAndUsesLowestMetric(t *testing.T) {
	interfaces := map[int]*net.Interface{
		7: {Index: 7, Name: "hop0", Flags: net.FlagUp},
		8: {Index: 8, Name: "wifi0", Flags: net.FlagUp},
		9: {Index: 9, Name: "eth0", Flags: net.FlagUp},
	}
	lookup := func(index int) (*net.Interface, error) {
		iface, ok := interfaces[index]
		if !ok {
			return nil, errors.New("нет интерфейса")
		}
		return iface, nil
	}

	routes := []netlink.Route{
		{LinkIndex: 7, Priority: 1},
		{LinkIndex: 8, Priority: 600},
		{LinkIndex: 9, Priority: 100},
	}
	if got := selectDefault(routes, 7, lookup); got != "eth0" {
		t.Fatalf("выбран %q, ожидался физический default с меньшей метрикой eth0", got)
	}
}

func TestW36HTTPClientFailsClosedWithoutPhysicalInterface(t *testing.T) {
	s := &Selector{err: ErrNoInterface}
	raw := &fakeRawConn{}
	err := s.Control("tcp", "127.0.0.1:1", raw)
	if !errors.Is(err, ErrNoInterface) {
		t.Fatalf("ошибка %v, ожидался отказ Control до создания сокета", err)
	}
	if raw.controlled {
		t.Fatal("Control добрался до fd без физического интерфейса")
	}
	tr, ok := s.HTTPClient().Transport.(*http.Transport)
	if !ok || tr.DialContext == nil {
		t.Fatal("HTTP-клиент не проводит новые сокеты через bound DialContext")
	}
}

// TestFirstBindToDeviceNeedsNoCapability переносит решающий замер из scratchpad
// в репозиторий: первая привязка свежего сокета обязана работать у
// непривилегированного агента. Ядро, на котором она отказывает, нельзя объявлять
// поддержанным: Xray не сможет выполнить на нём §6.8.
func TestFirstBindToDeviceNeedsNoCapability(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("свежий сокет: %v", err)
	}
	defer unix.Close(fd)
	if err := unix.BindToDevice(fd, "lo"); err != nil {
		t.Fatalf("первая SO_BINDTODEVICE потребовала привилегий или не поддержана: %v", err)
	}
}

type fakeRawConn struct{ controlled bool }

func (c *fakeRawConn) Control(func(uintptr)) error  { c.controlled = true; return nil }
func (*fakeRawConn) Read(func(uintptr) bool) error  { return nil }
func (*fakeRawConn) Write(func(uintptr) bool) error { return nil }

func TestSelectDefaultRejectsNonDefaultDownAndLoopback(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("192.168.0.0/16")
	interfaces := map[int]*net.Interface{
		1: {Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
		2: {Index: 2, Name: "down0"},
		3: {Index: 3, Name: "wifi0", Flags: net.FlagUp},
	}
	lookup := func(index int) (*net.Interface, error) { return interfaces[index], nil }
	routes := []netlink.Route{
		{LinkIndex: 1},
		{LinkIndex: 2},
		{LinkIndex: 3, Dst: subnet},
	}
	if got := selectDefault(routes, 0, lookup); got != "" {
		t.Fatalf("выбран %q, хотя пригодного default-маршрута нет", got)
	}
}
