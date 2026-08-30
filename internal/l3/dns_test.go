//go:build linux

package l3

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/shafed/hop/internal/dnsmsg"
	"github.com/shafed/hop/internal/dnstest"
)

// t26Name — имя, которого нет нигде, кроме этого теста: и подставной резолвер,
// и резолвер за узлом отвечают на всё, поэтому различить их можно только по
// адресу в ответе, а не по имени в вопросе.
const t26Name = "t26.hop.invalid."

// T26 — §8.4: `up`, DNS-запрос из тестового приложения → 0 запросов на
// подставной системный резолвер; запрос виден только на резолвере за узлом.
// Падает без перехвата :53.
//
// Почему тест обязан быть на L3, а не уровнем ниже. T14 и T16 (internal/l2) и
// весь `docs/verification-dns.md` проверяют перехват со стороны стека: пакет
// уже в TUN, вердикт уже принят. Обе половины T26 живут снаружи этой границы.
// «0 запросов на подставной системный резолвер» — про то, что запрос не ушёл
// на настоящий сокет к настоящему адресу; «виден только на резолвере за узлом»
// — про то, что он вышел через узел, то есть через движок и физический
// интерфейс. Ни того, ни другого в стеке не видно.
//
// Стенд обязан быть способен утечь: до подъёма туннеля тот же запрос доходит
// до подставного резолвера и получает от него ответ. Если бы не доходил, «0
// запросов» ничего бы не значило.
//
// Три утверждения, и каждое своё:
//  1. до `up` подставной резолвер отвечает — иначе ноль даётся даром;
//  2. при поднятом туннеле он не увидел ни одного нового запроса;
//  3. клиент получил ответ, и в ответе адрес резолвера ЗА УЗЛОМ, а не
//     подставного: запрос не потерялся и не был отвергнут, а прошёл весь путь
//     §5.7 — перехват, апстрим через активный узел, ответ клиенту.
func TestT26DNSIsHijackedAndLeavesThroughTheNode(t *testing.T) {
	requireNetns(t)

	peer := startPeer(t)
	defer peer.stop()
	setupSiteNet(t)

	root := storeRoot(t)
	// Апстрим §5.7 — резолвер за узлом. Один, а не два: фора второму (§5.7)
	// здесь ничего не проверяет, а второй адрес пришлось бы объяснять.
	writeUpstreams(t, root, net.JoinHostPort(siteAddr, "53"))
	addNode(t, root, siteAddr, vlessPort)

	decoy := net.JoinHostPort(decoyAddr, "53")

	// 1. Контроль стенда: подставной системный резолвер жив и достижим.
	got, err := askDNS(t, decoy, t26Name, 2*time.Second)
	if err != nil {
		t.Fatalf("подставной резолвер не отвечает до туннеля — проверять нечего: %v", err)
	}
	if got != decoyAnswer {
		t.Fatalf("до туннеля пришёл ответ %s, а подставной резолвер отвечает %s", got, decoyAnswer)
	}
	before := peer.counts(t)
	if len(before.DecoyDNS) != 1 {
		t.Fatalf("подставной резолвер насчитал %d запросов до туннеля, ожидался 1", len(before.DecoyDNS))
	}

	s := startService(t, orphanDeadline)
	s.startAgent(filepath.Join(t.TempDir(), "token"))

	// Узел обязан ожить: без живого узла §5.7(б) отказывает по fail-close, и
	// до апстрима запрос не доходит — тогда проверялась бы первая половина
	// T26 и не проверялась бы вторая. Ждём именно ответа, а не таймера:
	// «узел жив» наружу видно ровно тем, что путь §5.7 заработал.
	var answer string
	waitUntil(t, 40*time.Second, "живого узла и ответа резолвера §5.7", func() bool {
		a, err := askDNS(t, decoy, t26Name, 3*time.Second)
		if err != nil {
			return false
		}
		answer = a
		return true
	})

	after := peer.counts(t)

	// 2. Собственно первая половина T26.
	if len(after.DecoyDNS) != len(before.DecoyDNS) {
		t.Fatalf("подставной системный резолвер увидел %d запросов вместо %d: "+
			"перехват :53 не сработал, запрос ушёл мимо туннеля (%v)",
			len(after.DecoyDNS), len(before.DecoyDNS), after.DecoyDNS)
	}

	// 3. Вторая половина: запрос виден на резолвере за узлом, и клиент получил
	// именно его ответ.
	if answer == decoyAnswer {
		t.Fatalf("клиент получил ответ подставного резолвера (%s): запрос перехвачен не был", answer)
	}
	if answer != siteAnswer {
		t.Fatalf("клиент получил %s, а резолвер за узлом отвечает %s", answer, siteAnswer)
	}
	if len(after.SiteDNS) == 0 {
		t.Fatal("резолвер за узлом не увидел ни одного запроса, а ответ пришёл его: " +
			"адрес в ответе взялся не из стенда")
	}
	t.Logf("подставной резолвер: %d запросов (все до туннеля); резолвер за узлом: %d; "+
		"клиент получил %s", len(after.DecoyDNS), len(after.SiteDNS), answer)
}

// askDNS шлёт A-запрос на указанный адрес и возвращает адрес из первой
// A-записи ответа.
//
// Своим сокетом, а не через net.Resolver: тестовое приложение §8.4 обязано
// спрашивать конкретный адрес конкретным пакетом, а системный резолвер Go
// читает /etc/resolv.conf, который netns не меняет.
func askDNS(t *testing.T, server, name string, limit time.Duration) (string, error) {
	t.Helper()
	c, err := net.Dial("udp", server)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(limit)); err != nil { //hop:realtime
		return "", err
	}
	q := dnstest.BuildQuery(dnstest.QueryOpts{ID: 0x2626, Name: name, Type: dnstest.TypeA})
	if _, err := c.Write(q); err != nil {
		return "", err
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return "", err
	}
	m, err := dnsmsg.Parse(buf[:n])
	if err != nil {
		return "", fmt.Errorf("ответ не разобран: %w", err)
	}
	if rc := m.Header.Rcode(); rc != 0 {
		return "", fmt.Errorf("rcode %d", rc)
	}
	sc := m.Scan()
	for sc.Next() {
		rr := sc.RR()
		if rr.Section != dnsmsg.SectionAnswer || rr.Type != dnstest.TypeA || rr.RDLength() != 4 {
			continue
		}
		a, _ := netip.AddrFromSlice(m.Raw[rr.RDStart:rr.RDEnd])
		return a.String(), nil
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("разбор записей: %w", err)
	}
	return "", fmt.Errorf("в ответе нет A-записи")
}
