//go:build linux

package platform

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync/atomic"

	"github.com/shafed/hop/internal/netstate"
	"github.com/shafed/hop/internal/policy"
	"github.com/shafed/hop/internal/reject"
	"github.com/shafed/hop/internal/tunnel"
	"golang.org/x/sys/unix"
)

// Приоритеты правил. Порядок — часть контракта: исключения §5.6 обязаны стоять
// выше правила туннеля, иначе туннельная таблица заберёт их первой.
const (
	prioExclusions = 31000 // §5.6: локальные сети, DHCP, NTP
	prioTunnel     = 32000 // всё остальное — в таблицу туннеля
	// legacyPrioLoopGuard больше не раскладывается: uid-правило выводило мимо
	// туннеля весь трафик desktop-пользователя. Одна версия Reclaim обязана
	// всё ещё подобрать его после обновления со старой сборки (§6.8).
	legacyPrioLoopGuard = 31500
)

// Linux — привилегированная поверхность на Linux.
type Linux struct {
	j         netstate.Journal
	params    tunnel.Params
	dev       *tunDevice
	responder chan struct{} // закрывается, когда читатель-респондер вышел
	log       *slog.Logger
}

// New создаёт платформенный слой.
//
// Журнал сервиса передаётся сюда, потому что один шаг Up умеет деградировать
// (§6.9, зачистка сокетов IPv6): он не роняет подъём, но обязан сказать, что
// сделал не всё. Молча деградировать — то же самое молчание, против которого
// написан §5.6, только обращённое к человеку, а не к приложению.
func New(log *slog.Logger) *Linux {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Linux{log: log}
}

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

// step — одно изменение сети вместе со своим откатом.
//
// Список шагов строится отдельно от их исполнения (upSteps) по той же
// причине, по которой §6.2 вынес респондер в чистую функцию: решение «что
// раскладывать» проверяется без прав, а раскладывание — нет. Иначе
// единственным способом убедиться, что шаг вообще есть в списке, остаётся
// привилегированный прогон в netns.
type step struct {
	name     string
	add, del []string
	// do — шаг, который командой iproute2 не выражается. Непуст ровно один
	// из do и add. Откат у такого шага может отсутствовать, и это отдельное
	// утверждение, а не забывчивость: разрушенный сокет обратно не собрать.
	do func() error
}

// apply — что журнал исполнит на этом шаге.
func (s step) apply() func() error {
	if s.do != nil {
		return s.do
	}
	return run(s.add)
}

// upSteps — что Up раскладывает и как каждый шаг откатывается. Чистая
// функция от параметров туннеля: ничего не выполняет и ни от чего не зависит,
// кроме флагов политик.
//
// Порядок значим дважды: журнал откатывает шаги в обратном порядке (LIFO,
// netstate.Journal.Rollback), поэтому первый шаг снимается последним.
func upSteps(p tunnel.Params, log *slog.Logger) []step {
	var steps []step

	// §6.9: IPv6 закрывается первым и снимается последним — при любом исходе
	// нет момента, когда туннель уже (или ещё) существует, а IPv6 открыт.
	//
	// Правило, а не маршрут в таблице туннеля, потому что утечка идёт не через
	// туннель: замер показал, что при поднятом туннеле `ip -6 route get` ведёт
	// на физический интерфейс через main, а таблица туннеля в IPv6 пуста и в
	// поиске не участвует вовсе. Тип unreachable, а не blackhole: §5.6 требует
	// отказа, а не молчания, и приложение получает ENETUNREACH мгновенно.
	// Подробности замера — implementation-notes.md.
	if policy.IPv6Block.On() {
		steps = append(steps, step{
			name: "ipv6 block",
			add:  ip6("rule", "add", "unreachable", "priority", fmt.Sprint(prioTunnel)),
			del:  ip6("rule", "del", "unreachable", "priority", fmt.Sprint(prioTunnel)),
		})
	}

	steps = append(steps,
		step{name: "mtu", add: ip("link", "set", "dev", p.Name, "mtu", fmt.Sprint(p.MTU))},
		step{name: "addr",
			add: ip("addr", "add", p.Addr, "dev", p.Name),
			del: ip("addr", "del", p.Addr, "dev", p.Name)},
		step{name: "up",
			add: ip("link", "set", "dev", p.Name, "up"),
			del: ip("link", "set", "dev", p.Name, "down")},
		// Откат удаляет маршрут по месту (таблица + префикс), а не по форме:
		// форма зависит от того, чем маршрут оказался к моменту уборки, а место
		// — нет.
		step{name: "route",
			add: ip("route", "add", "default", "dev", p.Name, "table", fmt.Sprint(p.Table)),
			del: ip("route", "del", "default", "table", fmt.Sprint(p.Table))},
	)
	for _, pfx := range LocalPrefixes {
		steps = append(steps, step{
			name: "exclude " + pfx,
			add:  ip("rule", "add", "to", pfx, "lookup", "main", "priority", fmt.Sprint(prioExclusions)),
			del:  ip("rule", "del", "to", pfx, "lookup", "main", "priority", fmt.Sprint(prioExclusions)),
		})
	}
	for _, r := range ExcludedUDPPorts {
		port := fmt.Sprint(r[0])
		if r[1] != r[0] {
			port = fmt.Sprintf("%d-%d", r[0], r[1])
		}
		steps = append(steps, step{
			name: "exclude udp/" + port,
			add:  ip("rule", "add", "ipproto", "udp", "dport", port, "lookup", "main", "priority", fmt.Sprint(prioExclusions)),
			del:  ip("rule", "del", "ipproto", "udp", "dport", port, "lookup", "main", "priority", fmt.Sprint(prioExclusions)),
		})
	}
	return append(steps, step{
		name: "tunnel rule",
		add:  ip("rule", "add", "lookup", fmt.Sprint(p.Table), "priority", fmt.Sprint(prioTunnel)),
		del:  ip("rule", "del", "lookup", fmt.Sprint(p.Table), "priority", fmt.Sprint(prioTunnel)),
	})
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
	steps := upSteps(p, l.log)

	for _, s := range steps {
		s := s
		if err := l.j.Do(s.name, s.apply(), run(s.del)); err != nil {
			_ = l.j.Rollback()
			_ = dev.Close()
			l.dev = nil
			return nil, err
		}
	}
	return dev, nil
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

// Reclaim снимает правила, оставшиеся от предыдущего воплощения сервиса.
//
// T29 показал, что смерть сервиса переживают его правила: интерфейс уходит с
// последним дескриптором и уносит свои маршруты, но правила к интерфейсу не
// привязаны. Значит, у §6.2
// появляется ещё одна обязанность — убрать за собой на старте, до того как
// будет снят снапшот. Иначе «восстановление до снапшота» закрепит мусор.
//
// Опознаются правила по приоритетам, которые раскладывает только hopd.
func Reclaim() (int, error) {
	dropped := 0
	// Оба семейства: правила IPv6 живут в собственной базе, `ip rule del` их
	// не видит, а пережить смерть сервиса они могут ровно так же (§6.9, T29).
	// Уборка идёт при любом состоянии ipv6_block: убирать за предыдущим
	// воплощением — не политика, а обязанность старта (§6.2), и прошлая
	// сборка могла разложить правило при включённой политике.
	for _, family := range [][]string{ip("rule", "del"), ip6("rule", "del")} {
		for _, prio := range []int{prioExclusions, legacyPrioLoopGuard, prioTunnel} {
			for i := 0; i < 64; i++ {
				args := append(append([]string(nil), family...), "priority", fmt.Sprint(prio))
				if err := run(args)(); err != nil {
					break // правил с этим приоритетом больше нет
				}
				dropped++
			}
		}
	}
	return dropped, nil
}

func ip(args ...string) []string { return append([]string{"ip"}, args...) }

// ip6 — тот же ip, но по семейству IPv6. Отдельная обёртка, а не аргумент:
// «-6» стоит первым и его забывчивость молча превращает правило IPv6 в
// правило IPv4 с тем же приоритетом.
func ip6(args ...string) []string { return append([]string{"ip", "-6"}, args...) }

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
