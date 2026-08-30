//go:build linux

package l3

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// T25 — §8.4: `up`, считать пакеты на TUN с dst = IP узла → 0 пакетов. Падает
// без защиты от петли (§6.8).
//
// Почему тест обязан быть на L3, а не уровнем ниже. W36 закрепляет, что дозвон
// ставит `SO_BINDTODEVICE` и отказывает без интерфейса, — но привязка это
// свойство сокета, а петля это свойство **маршрутизации**: непривязанный сокет
// образует петлю ровно потому, что правило туннеля забирает адрес узла себе.
// Проверить это можно только там, где есть настоящая таблица маршрутов,
// настоящий TUN и настоящий второй интерфейс, — то есть здесь.
//
// Стенд обязан быть способен утечь, иначе тест зелен даром, и весь смысл
// адреса из TEST-NET-2 (stand_test.go) в этом: узел стоит в сети, которую
// §5.6 НЕ выпускает мимо туннеля, в отличие от 10.9.9.0/24 первой половины
// стенда. Способность стенда утечь тест не предполагает, а показывает — двумя
// проверками, до и после измерения.
//
// Четыре утверждения, и каждое своё:
//  1. адрес узла действительно забран туннелем — `ip route get` ведёт в hopt0;
//  2. дозвоны продукта до узла дошли до пира, и дошли с адреса физического
//     интерфейса, а не с адреса клиента в туннеле;
//  3. за то же окно на TUN не ушло ни одного пакета;
//  4. счётчик пакетов не сломан и не слеп: непривязанный сокет к тому же
//     адресу двигает его и до пира не доходит.
func TestT25NodeTrafficNeverReachesTUN(t *testing.T) {
	requireNetns(t)

	peer := startPeer(t)
	defer peer.stop()
	setupSiteNet(t)

	agentStore := storeRoot(t)
	addNode(t, agentStore, siteAddr, nodePort)

	// Второй стор для `hop probe`: см. probeFromCLI.
	cliStore := t.TempDir()
	addNode(t, cliStore, siteAddr, nodePort)

	s := startService(t, orphanDeadline)
	s.startAgent(filepath.Join(t.TempDir(), "token"))

	// 1. Стенд способен утечь: без §6.8 пакет к узлу ушёл бы в туннель.
	if got := sh("ip", "route", "get", siteAddr); !strings.Contains(got, ifname) {
		t.Fatalf("адрес узла не забран туннелем — проверять нечего: %s", got)
	}

	// Окно измерения открывается здесь: до подъёма туннеля интерфейса ещё нет,
	// и «0 пакетов на TUN» было бы верно даром.
	before := tunPackets(t, ifname)
	seen := len(peer.counts(t).NodeConns)

	// Дозвоны до узла. Первый раунд проб агента уже прошёл или идёт; `hop
	// probe` добавляет к нему дозвоны по требованию — иначе тест ждал бы
	// candidate-интервал §6.5 (60 с) ради второго пакета.
	t.Logf("hop probe: %s", probeFromCLI(t, cliStore))
	waitUntil(t, 10*time.Second, "дозвона продукта до узла", func() bool {
		return len(peer.counts(t).NodeConns) > seen
	})

	after := tunPackets(t, ifname)
	c := peer.counts(t)

	// 2. Дошло до пира, и дошло физическим интерфейсом.
	if len(c.NodeConns) == 0 {
		t.Fatal("пир не увидел ни одного дозвона до узла — измерять нечего")
	}
	tunAddr := strings.SplitN(addr, "/", 2)[0]
	for _, src := range c.NodeConns {
		host := src[:strings.LastIndex(src, ":")]
		if host == tunAddr {
			t.Fatalf("узел увидел адрес клиента в туннеле %s — это петля: %v", src, c.NodeConns)
		}
		if host != siteLocalAddr {
			t.Fatalf("узел увидел %s, ожидался адрес физического интерфейса %s: %v",
				src, siteLocalAddr, c.NodeConns)
		}
	}

	// 3. Собственно T25.
	if after != before {
		t.Fatalf("на TUN ушло %d пакетов за окно, в котором продукт %d раз дозвонился до узла: "+
			"трафик к узлу идёт через туннель (петля §6.8)", after-before, len(c.NodeConns))
	}
	t.Logf("дозвонов до узла: %d (все с %s), пакетов на TUN за окно: %d",
		len(c.NodeConns), siteLocalAddr, after-before)

	// 4. Контроль счётчика и маршрута. Непривязанный сокет — это и есть та
	// самая петля: он уходит в туннель, где fail-close его и отвергает.
	sawBefore := len(c.NodeConns)
	err, took := connect(fmt.Sprintf("%s:%d", siteAddr, nodePort), 5*time.Second)
	leaked := tunPackets(t, ifname)
	if leaked <= after {
		t.Fatalf("непривязанный сокет к узлу не дал ни одного пакета на TUN (%d → %d): "+
			"счётчик слеп, и нули выше ничего не значат", after, leaked)
	}
	if got := len(peer.counts(t).NodeConns); got != sawBefore {
		t.Fatalf("непривязанное соединение дошло до узла (%d → %d): "+
			"значит адрес узла достижим мимо туннеля, и пункт 2 доказывает не §6.8", sawBefore, got)
	}
	t.Logf("контроль: непривязанный сокет дал %d пакетов на TUN и до узла не дошёл (%v за %v)",
		leaked-after, err, took)
}
