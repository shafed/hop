//go:build linux

package platform

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync/atomic"

	"github.com/shafed/hop/internal/loopguard"
	"github.com/shafed/hop/internal/netstate"
	"github.com/shafed/hop/internal/reject"
	"github.com/shafed/hop/internal/tunnel"
	"golang.org/x/sys/unix"
)

// Приоритеты правил. Порядок — часть контракта: исключения §5.6 и перехват :53
// обязаны стоять выше правила туннеля, иначе туннельная таблица заберёт их
// первой. Защита от петли §6.8 стоит выше всех и живёт в internal/loopguard
// вместе со своими приоритетами.
const (
	prioDNS        = 30500 // §3.4: перехват :53 выше списка исключений
	prioExclusions = 31000 // §5.6: локальные сети, DHCP, NTP
	prioTunnel     = 32000 // всё остальное — в таблицу туннеля
)

// Linux — привилегированная поверхность на Linux.
type Linux struct {
	j         netstate.Journal
	params    tunnel.Params
	dev       *tunDevice
	responder chan struct{} // закрывается, когда читатель-респондер вышел
}

// New создаёт платформенный слой.
func New() *Linux { return &Linux{} }

// tunDevice — дескриптор TUN, тот самый, что уезжает агенту через SCM_RIGHTS.
// Сервис держит свою копию открытой, поэтому перезапуск агента не убивает
// интерфейс (§3.2, T24). Эта же копия становится читателем в состоянии
// orphaned: агента нет, а отвечать кому-то надо.
//
// Дескриптор держится сырым int, а не os.File: os.File отдаёт его рантайму
// в netpoll, а тот же дескриптор одновременно живёт в чужом процессе после
// SCM_RIGHTS. Poll вручную снимает вопрос о том, кто владеет опросом.
type tunDevice struct {
	fd       int
	name     string
	mtu      int
	draining atomic.Bool
	closed   atomic.Bool
}

func (d *tunDevice) Ref() string { return d.name }
func (d *tunDevice) MTU() int    { return d.mtu }

// Fd — дескриптор для передачи через SCM_RIGHTS.
func (d *tunDevice) Fd() int { return d.fd }

func (d *tunDevice) Close() error {
	if d.closed.Swap(true) {
		return nil
	}
	d.draining.Store(false)
	return unix.Close(d.fd)
}

// pollTimeout — как часто читатель проверяет, не пора ли ему уйти. Ценой
// одного пробуждения в 100 мс покупается то, что реаттач не гонится с
// дренажом за пакеты: Restore дожидается выхода читателя.
const pollTimeout = 100

// ReadPackets читает по одному пакету: в orphaned поток мелкий, а батчинг на
// Linux без GSO всё равно пустышка (§4, D4).
func (d *tunDevice) ReadPackets(bufs [][]byte) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	for {
		if !d.draining.Load() {
			return 0, io.EOF
		}
		pfd := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pfd, pollTimeout)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}
		buf := bufs[0][:cap(bufs[0])]
		got, err := unix.Read(d.fd, buf)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil {
			return 0, err
		}
		bufs[0] = buf[:got]
		return 1, nil
	}
}

func (d *tunDevice) WritePackets(bufs [][]byte) error {
	for _, b := range bufs {
		if _, err := unix.Write(d.fd, b); err != nil {
			return err
		}
	}
	return nil
}

// Up создаёт интерфейс, вешает адрес и раскладывает маршруты и правила.
//
// Каждый шаг идёт через журнал вместе со своим откатом: восстановление
// снапшота (§8.4) не должно зависеть от того, на каком шаге всё сорвалось.
func (l *Linux) Up(p tunnel.Params) (tunnel.Device, error) {
	dev, err := openTUN(p.Name, p.MTU)
	if err != nil {
		return nil, err
	}
	l.params = p
	l.dev = dev

	// Дескриптор в журнал не кладётся: его закрывает машина состояний после
	// Down, и порядок ровно тот, что нужен — сначала снимаются адреса,
	// маршруты и правила, и только потом с последним дескриптором уходит сам
	// интерфейс. Закрыть его здесь значило бы закрыть дважды.
	steps := []struct {
		name     string
		add, del []string
	}{
		{"mtu", ip("link", "set", "dev", p.Name, "mtu", fmt.Sprint(p.MTU)), nil},
		{"addr", ip("addr", "add", p.Addr, "dev", p.Name), ip("addr", "del", p.Addr, "dev", p.Name)},
		{"up", ip("link", "set", "dev", p.Name, "up"), ip("link", "set", "dev", p.Name, "down")},
		// Откат удаляет маршрут по месту (таблица + префикс), а не по форме:
		// форма зависит от того, чем маршрут оказался к моменту уборки, а место
		// — нет.
		{"route", l.tunnelRoute("add"), ip("route", "del", "default", "table", fmt.Sprint(p.Table))},
	}
	// §3.4: «перехват :53 стоит выше этого списка». На уровне вердиктов агента
	// это уже так, но до вердикта пакет ещё надо довести: системный резолвер
	// обычно и есть локальный роутер, а его адрес накрыт исключением §5.6 ниже,
	// и запрос ушёл бы в локальную сеть, ни разу не заглянув в туннель.
	// Правило выше исключений возвращает порядок §3.4 в маршрутизацию — T26.
	for _, proto := range []string{"udp", "tcp"} {
		steps = append(steps, struct {
			name     string
			add, del []string
		}{
			"hijack dns/" + proto,
			ip("rule", "add", "ipproto", proto, "dport", "53", "lookup", fmt.Sprint(p.Table), "priority", fmt.Sprint(prioDNS)),
			ip("rule", "del", "ipproto", proto, "dport", "53", "lookup", fmt.Sprint(p.Table), "priority", fmt.Sprint(prioDNS)),
		})
	}
	for _, pfx := range LocalPrefixes {
		steps = append(steps, struct {
			name     string
			add, del []string
		}{
			"exclude " + pfx,
			ip("rule", "add", "to", pfx, "lookup", "main", "priority", fmt.Sprint(prioExclusions)),
			ip("rule", "del", "to", pfx, "lookup", "main", "priority", fmt.Sprint(prioExclusions)),
		})
	}
	for _, r := range ExcludedUDPPorts {
		port := fmt.Sprint(r[0])
		if r[1] != r[0] {
			port = fmt.Sprintf("%d-%d", r[0], r[1])
		}
		steps = append(steps, struct {
			name     string
			add, del []string
		}{
			"exclude udp/" + port,
			ip("rule", "add", "ipproto", "udp", "dport", port, "lookup", "main", "priority", fmt.Sprint(prioExclusions)),
			ip("rule", "del", "ipproto", "udp", "dport", port, "lookup", "main", "priority", fmt.Sprint(prioExclusions)),
		})
	}
	steps = append(steps, struct {
		name     string
		add, del []string
	}{
		"tunnel rule",
		ip("rule", "add", "lookup", fmt.Sprint(p.Table), "priority", fmt.Sprint(prioTunnel)),
		ip("rule", "del", "lookup", fmt.Sprint(p.Table), "priority", fmt.Sprint(prioTunnel)),
	})

	for _, s := range steps {
		s := s
		if err := l.j.Do(s.name, run(s.add), run(s.del)); err != nil {
			_ = l.j.Rollback()
			_ = dev.Close()
			l.dev = nil
			return nil, err
		}
	}

	if err := l.applyGuard(p.AgentUID); err != nil {
		_ = l.j.Rollback()
		_ = dev.Close()
		l.dev = nil
		return nil, err
	}
	return dev, nil
}

// applyGuard кладёт в тот же журнал план §6.8 и §6.9.
//
// Отдельным пакетом, потому что механизм защиты разный по ОС, а решение одно, и
// оно обязано проверяться без прав (internal/loopguard). Журнал тот же, потому
// что правило защиты не привязано к интерфейсу и переживает смерть сервиса
// (T29): убирать его надо тем же способом, что и всё остальное.
func (l *Linux) applyGuard(uid int) error {
	guard, err := loopguard.New(loopguard.Params{AgentUID: uid})
	if err != nil {
		return err
	}
	return loopguard.Apply(&l.j, guard, func(args []string) error { return run(args)() })
}

// Reject — ребро в orphaned (§6.2): сервис сам становится читателем устройства
// и отвечает отказом на каждый пакет.
//
// Не подмена маршрута на `unreachable`, как предполагал план. Замер
// TestRouteReplaceOnEstablishedConnection показал, что подменённый маршрут
// закрывает только **новые** соединения: у установленного сокета запись
// продолжает возвращать nil, а данные молча уходят в ретрансмиты — то самое
// молчание, против которого §5.6. Читатель-респондер закрывает оба случая
// одним механизмом и одинаково на трёх ОС. Подробности — «Deviations» в
// implementation-notes.md.
//
// Маршруты остаются туннельными: иначе пакеты не дойдут до устройства и
// отвечать будет не на что. Исключения §5.6 в туннельную таблицу и так не
// заходят — они выражены правилами более высокого приоритета.
func (l *Linux) Reject() error {
	if l.dev == nil {
		return errors.New("platform: Reject без поднятого туннеля")
	}
	if l.responder != nil {
		return nil
	}
	done := make(chan struct{})
	l.responder = done
	l.dev.draining.Store(true)
	go func() {
		defer close(done)
		_ = reject.Serve(l.dev)
	}()
	return nil
}

// Restore снимает отказ и, главное, **дожидается** выхода читателя: иначе
// вернувшийся агент и респондер сервиса делили бы один дескриптор и растащили
// бы пакеты пополам.
func (l *Linux) Restore() error {
	l.stopResponder()
	return nil
}

func (l *Linux) stopResponder() {
	if l.responder == nil {
		return
	}
	if l.dev != nil {
		l.dev.draining.Store(false)
	}
	<-l.responder
	l.responder = nil
}

// Down — полный teardown до снапшота.
func (l *Linux) Down() error {
	l.stopResponder()
	l.dev = nil
	return l.j.Rollback()
}

func (l *Linux) tunnelRoute(verb string) []string {
	return ip("route", verb, "default", "dev", l.params.Name, "table", fmt.Sprint(l.params.Table))
}

// Reclaim снимает правила, оставшиеся от предыдущего воплощения сервиса.
//
// T29 показал, что смерть сервиса переживают **все** его правила, а не только
// правило §6.8 по UID-диапазону: интерфейс уходит с последним дескриптором и
// уносит свои маршруты, но правила к интерфейсу не привязаны. Значит, у §6.2
// появляется ещё одна обязанность — убрать за собой на старте, до того как
// будет снят снапшот. Иначе «восстановление до снапшота» закрепит мусор.
//
// Опознаются правила по приоритетам, которые раскладывает только hopd. Обе
// семьи: `ip rule del` без `-6` снимает только IPv4-правила, и блокировка IPv6
// (§6.9) пережила бы уборку молча.
func Reclaim() (int, error) {
	prios := append([]int{prioDNS, prioExclusions, prioTunnel}, loopguard.Priorities...)
	dropped := 0
	for _, fam := range []string{"-4", "-6"} {
		for _, prio := range prios {
			for i := 0; i < 64; i++ {
				if err := run(ip(fam, "rule", "del", "priority", fmt.Sprint(prio)))(); err != nil {
					break // правил с этим приоритетом больше нет
				}
				dropped++
			}
		}
	}
	return dropped, nil
}

func ip(args ...string) []string { return append([]string{"ip"}, args...) }

func run(args []string) func() error {
	if args == nil {
		return func() error { return nil }
	}
	return func() error {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

func openTUN(name string, mtu int) (*tunDevice, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF %s: %w", name, err)
	}
	return &tunDevice{fd: fd, name: name, mtu: mtu}, nil
}
