package loopguard

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/shafed/hop/internal/netstate"
)

const (
	agentUID = 4242
	// bindIface — что подставной определитель отвечает вместо ядра. Тест
	// смотрит на решение защиты, а не на сеть машины, иначе он проходил бы
	// только там, где интерфейс называется так же.
	bindIface = "en0"
)

// supported — ОС, для которых §6.8 и §6.9 решены. Каждая проверяется на любой
// из них: план — это данные.
var supported = []string{"linux", "darwin", "windows"}

func fakeLookup() (string, error) { return bindIface, nil }

// recorder — подставной исполнитель команд: запоминает, что бы ушло в систему.
type recorder struct{ done []string }

func (r *recorder) run(args []string) error {
	r.done = append(r.done, strings.Join(args, " "))
	return nil
}

// applied строит план и прогоняет его через подставного исполнителя.
func applied(t *testing.T, goos string) (Plan, *recorder, *netstate.Journal) {
	t.Helper()
	pl, err := plan(goos, Params{AgentUID: agentUID}, fakeLookup)
	if err != nil {
		t.Fatalf("%s: план не построен: %v", goos, err)
	}
	rec := &recorder{}
	j := &netstate.Journal{}
	if err := Apply(j, pl, rec.run); err != nil {
		t.Fatalf("%s: план не поставлен: %v", goos, err)
	}
	return pl, rec, j
}

func hasCmd(done []string, parts ...string) bool {
	for _, c := range done {
		ok := true
		for _, p := range parts {
			if !strings.Contains(c, p) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// T25 — исходящее агента к узлу не заходит обратно в туннель (§6.8).
//
// Без прав: проверяется решение, а не живое ядро. На Linux — какое правило
// уйдёт в систему, на macOS и Windows — к какому интерфейсу будет привязан
// сокет. L3-двойник этого теста (internal/l3) спрашивает то же самое у
// настоящего ядра, но он требует netns и в обычном прогоне пропускается —
// охранять политику §8 он поэтому не может.
func TestT25NoLoopOnNodeDial(t *testing.T) {
	for _, goos := range supported {
		t.Run(goos, func(t *testing.T) {
			pl, rec, _ := applied(t, goos)

			if goos == "linux" {
				// Правило уводит трафик агента в main — туда, где живёт
				// настоящий маршрут к узлу, а не в таблицу туннеля.
				if !hasCmd(rec.done, "rule add", "uidrange 4242-4242", "lookup main") {
					t.Fatalf("трафик агента не выведен мимо туннеля, поставлено: %v", rec.done)
				}
				if pl.Bind != "" {
					t.Fatalf("на Linux bind не нужен, а план требует %q", pl.Bind)
				}
				return
			}

			// macOS и Windows: сокет к узлу уходит через дефолтный интерфейс,
			// а не через туннельный, — и именно это уезжает в
			// engine.Options.BindInterface.
			if pl.Bind != bindIface {
				t.Fatalf("исходящий сокет не привязан к дефолтному интерфейсу: bind=%q", pl.Bind)
			}
		})
	}
}

// T28 — IPv6 заблокирован, а не выпущен мимо туннеля (§6.9).
func TestT28IPv6IsBlocked(t *testing.T) {
	for _, goos := range supported {
		t.Run(goos, func(t *testing.T) {
			_, rec, _ := applied(t, goos)
			if !hasCmd(rec.done, GlobalIPv6) {
				t.Fatalf("IPv6 ничем не заблокирован, поставлено: %v", rec.done)
			}
		})
	}

	// Что именно заблокировано — вопрос отдельный от того, чем. Утечь мимо
	// туннеля может только глобальный адрес; link-local и multicast §6.10
	// велит выпускать в локальную сеть, и блокировка их не касается.
	blocked := netip.MustParsePrefix(GlobalIPv6)
	for _, c := range []struct {
		addr string
		want bool
		why  string
	}{
		{"2606:4700:4700::1111", true, "глобальный юникаст — та самая утечка"},
		{"fe80::1", false, "link-local держит NDP"},
		{"ff02::fb", false, "mDNS, §6.10 велит выпускать"},
		{"::1", false, "loopback"},
	} {
		if got := blocked.Contains(netip.MustParseAddr(c.addr)); got != c.want {
			t.Fatalf("%s: заблокирован=%v, ожидалось %v — %s", c.addr, got, c.want, c.why)
		}
	}
}

// Откат обязан снимать ровно то, что поставил: иначе блокировка переживёт
// туннель, и снапшот §8.4 не сойдётся.
func TestRollbackRemovesEveryStep(t *testing.T) {
	for _, goos := range supported {
		_, rec, j := applied(t, goos)
		added := len(rec.done)
		if err := j.Rollback(); err != nil {
			t.Fatalf("%s: откат: %v", goos, err)
		}
		removed := rec.done[added:]
		if len(removed) != added {
			t.Fatalf("%s: поставлено %d шагов, снято %d: %v", goos, added, len(removed), rec.done)
		}
		for _, c := range removed {
			if !strings.Contains(c, "del") && !strings.Contains(c, "delete") {
				t.Fatalf("%s: откатная команда ничего не удаляет: %q", goos, c)
			}
		}
	}
}

// Восемь подсетей §5.10: они покрывают всё, что покрыл бы дефолт, но дефолтом
// не являются — иначе перебивается системный маршрут, и после падения процесса
// машина остаётся без сети вовсе.
func TestDarwinRoutesReplaceDefaultWithSubnets(t *testing.T) {
	pl, err := plan("darwin", Params{}, fakeLookup)
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Routes) != 8 {
		t.Fatalf("маршрутов %d, §5.10 требует восьми: %v", len(pl.Routes), pl.Routes)
	}
	var pfx []netip.Prefix
	for _, r := range pl.Routes {
		p := netip.MustParsePrefix(r)
		if p.Bits() == 0 {
			t.Fatalf("%s — это дефолт, а не подсеть", r)
		}
		pfx = append(pfx, p)
	}
	for _, a := range []string{"1.1.1.1", "8.8.8.8", "203.0.113.9", "129.0.0.1", "255.255.255.254"} {
		addr := netip.MustParseAddr(a)
		covered := false
		for _, p := range pfx {
			if p.Contains(addr) {
				covered = true
			}
		}
		if !covered {
			t.Fatalf("%s не покрыт восемью подсетями — трафик уйдёт мимо туннеля", a)
		}
	}
}

// Неподдержанная ОС обязана отказать вслух: молчаливая заглушка дала бы зелёный
// туннель без защиты от петли, и узнал бы об этом пользователь.
func TestUnsupportedOSFailsLoudly(t *testing.T) {
	if _, err := plan("plan9", Params{AgentUID: agentUID}, fakeLookup); err == nil {
		t.Fatal("для неизвестной ОС план построился молча")
	}
}

// Имя интерфейса для bind ищется по адресу, который ядро выбрало само.
func TestBindNamesInterfaceHoldingLocalAddress(t *testing.T) {
	ifaces := []Iface{
		{Name: "lo0", Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		{Name: bindIface, Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.7")}},
		{Name: "utun3", Addrs: []netip.Addr{netip.MustParseAddr("10.255.0.1")}},
	}
	got, err := matchInterface(netip.MustParseAddr("192.168.1.7"), ifaces)
	if err != nil || got != bindIface {
		t.Fatalf("matchInterface = %q, %v; ожидалось %q", got, err, bindIface)
	}
	if _, err := matchInterface(netip.MustParseAddr("198.51.100.1"), ifaces); err == nil {
		t.Fatal("чужой адрес нашёлся у интерфейса")
	}
}

// Ошибка определения интерфейса обязана валить план: пустое имя означало бы
// сокеты без привязки, то есть петлю (§6.8).
func TestBindLookupFailureFailsPlan(t *testing.T) {
	boom := errors.New("дефолтного маршрута нет")
	if _, err := plan("darwin", Params{}, func() (string, error) { return "", boom }); !errors.Is(err, boom) {
		t.Fatalf("план построился без имени интерфейса: %v", err)
	}
}
