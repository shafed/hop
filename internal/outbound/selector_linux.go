//go:build linux

package outbound

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Selector следит за физическим default route в таблице main. Уведомления о
// маршрутах и интерфейсах — непривилегированные операции rtnetlink; capability
// агенту ради них не добавляется.
type Selector struct {
	tunName string

	mu   sync.RWMutex
	name string
	err  error

	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// New запускает слежение. Отсутствие default route — не ошибка сборки: ноутбук
// законно проходит через такое состояние. Interface тогда возвращает
// ErrNoInterface, и дозвоны отказывают, пока rtnetlink не сообщит маршрут.
func New(tunName string) (*Selector, error) {
	s := &Selector{tunName: tunName, done: make(chan struct{})}
	routes := make(chan netlink.RouteUpdate, 16)
	links := make(chan netlink.LinkUpdate, 16)
	if err := netlink.RouteSubscribe(routes, s.done); err != nil {
		return nil, fmt.Errorf("outbound: подписка на маршруты: %w", err)
	}
	if err := netlink.LinkSubscribe(links, s.done); err != nil {
		s.Close()
		return nil, fmt.Errorf("outbound: подписка на интерфейсы: %w", err)
	}

	// Подписка до первого снимка: изменение не провалится в щель между ними.
	s.refresh()
	s.wg.Add(1)
	go s.watch(routes, links)
	return s, nil
}

// Interface возвращает последний физический интерфейс по умолчанию.
func (s *Selector) Interface() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.name == "" {
		if s.err != nil {
			return "", s.err
		}
		return "", ErrNoInterface
	}
	return s.name, nil
}

// Close останавливает слежение через rtnetlink.
func (s *Selector) Close() error {
	s.closeOnce.Do(func() { close(s.done) })
	s.wg.Wait()
	return nil
}

// Control биндит свежий сокет к интерфейсу, текущему в момент создания сокета.
// unix.BindToDevice — первая установка SO_BINDTODEVICE, разрешённая
// непривилегированному агенту на поддержанном Linux (§6.8).
func (s *Selector) Control(_ string, _ string, c syscall.RawConn) error {
	name, err := s.Interface()
	if err != nil {
		return err
	}
	var bindErr error
	if err := c.Control(func(fd uintptr) {
		bindErr = unix.BindToDevice(int(fd), name)
	}); err != nil {
		return fmt.Errorf("outbound: доступ к сокету для привязки к %s: %w", name, err)
	}
	if bindErr != nil {
		return fmt.Errorf("outbound: привязка сокета к %s: %w", name, bindErr)
	}
	return nil
}

func (s *Selector) watch(routes <-chan netlink.RouteUpdate, links <-chan netlink.LinkUpdate) {
	defer s.wg.Done()
	for routes != nil || links != nil {
		select {
		case _, ok := <-routes:
			if !ok {
				routes = nil
				continue
			}
			s.refresh()
		case _, ok := <-links:
			if !ok {
				links = nil
				continue
			}
			s.refresh()
		case <-s.done:
			return
		}
	}
	s.set("", errors.New("outbound: слежение за маршрутами остановилось"))
}

func (s *Selector) refresh() {
	tunIndex := 0
	if s.tunName != "" {
		if tun, err := net.InterfaceByName(s.tunName); err == nil {
			tunIndex = tun.Index
		}
	}

	name, err := findDefaultInterface(tunIndex)
	s.set(name, err)
}

func (s *Selector) set(name string, err error) {
	s.mu.Lock()
	s.name, s.err = name, err
	s.mu.Unlock()
}

func findDefaultInterface(tunIndex int) (string, error) {
	var errs []error
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: unix.RT_TABLE_MAIN},
			netlink.RT_FILTER_TABLE,
		)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if name := selectDefault(routes, tunIndex, net.InterfaceByIndex); name != "" {
			return name, nil
		}
	}
	if len(errs) > 0 {
		return "", fmt.Errorf("%w: %v", ErrNoInterface, errors.Join(errs...))
	}
	return "", ErrNoInterface
}

type interfaceByIndex func(int) (*net.Interface, error)

// selectDefault чиста кроме поиска интерфейса, поэтому выбор маршрута
// проверяется без изменения таблицы хоста.
func selectDefault(routes []netlink.Route, tunIndex int, lookup interfaceByIndex) string {
	var selected *net.Interface
	selectedMetric := 0
	for _, route := range routes {
		if route.Dst != nil {
			ones, _ := route.Dst.Mask.Size()
			if ones != 0 {
				continue
			}
		}
		if route.LinkIndex == 0 || route.LinkIndex == tunIndex {
			continue
		}
		iface, err := lookup(route.LinkIndex)
		if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if selected == nil || route.Priority < selectedMetric {
			selected = iface
			selectedMetric = route.Priority
		}
	}
	if selected == nil {
		return ""
	}
	return selected.Name
}
