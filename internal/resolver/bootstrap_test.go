package resolver

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time" //hop:realtime

	"golang.org/x/net/dns/dnsmessage"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dnstest"
)

const nodeHost = "node.example.test"

// systemViaTunnel — системный резолвер в том виде, в каком он существует после
// поднятия туннеля: DNS выставлен на адаптере (§8.4), то есть указывает на нас
// же. Ровно во что вырождается bootstrap при выключенной политике.
type systemViaTunnel struct{ res *Resolver }

func (s systemViaTunnel) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	q, err := dnsmessage.NewName(fqdn(host))
	if err != nil {
		return nil, err
	}
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 1, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: q, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	wire, err := m.Pack()
	if err != nil {
		return nil, err
	}
	raw, err := s.res.Query(wire, netip.AddrPort{}, netip.AddrPort{})
	if err != nil {
		return nil, err
	}
	var out dnsmessage.Message
	if err := out.Unpack(raw); err != nil {
		return nil, err
	}
	if out.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, errors.New("системный резолвер: " + out.Header.RCode.String())
	}
	var addrs []netip.Addr
	for _, a := range out.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			addrs = append(addrs, netip.AddrFrom4(r.A))
		}
	}
	return addrs, nil
}

func newBootstrapFixture(t *testing.T) (*Bootstrap, *dnstest.Server) {
	t.Helper()
	srv, err := dnstest.New()
	if err != nil {
		t.Fatalf("сервер: %v", err)
	}
	t.Cleanup(srv.Close)
	srv.Set(nodeHost, time.Minute, ip("203.0.113.7"))

	clk := clock.NewFake(time.Unix(1700000000, 0))
	// Туннельный резолвер: узлов нет, потому что имя узла ещё не разрешено.
	// Это и есть та сторона замыкания, о которую разбивается bootstrap=off.
	tunnel := New(Config{
		Transport: NewNodeTransport(Direct{}),
		Servers:   []netip.AddrPort{srv.Addr()},
		Clock:     clk,
		Healthy:   func() bool { return false },
	})

	b := NewBootstrap(BootstrapConfig{
		Servers:   []netip.AddrPort{srv.Addr()},
		Transport: NewNodeTransport(Direct{}),
		System:    systemViaTunnel{tunnel},
		Clock:     clk,
	})
	return b, srv
}

// TestBootstrapBreaksStartupLoop — §5.7а и охраняющий тест политики bootstrap.
//
// Хостнейм узла разрешается мимо туннеля. При выключенной политике вопрос
// уходит системному резолверу, который после up указывает на туннель, а
// туннель отвечает только при живом узле, которого ещё нет: имя узла ждёт
// узла, узел ждёт имени.
func TestBootstrapBreaksStartupLoop(t *testing.T) {
	b, srv := newBootstrapFixture(t)

	addrs, err := b.Lookup(context.Background(), nodeHost)
	if err != nil {
		t.Fatalf("хостнейм узла не разрешился: %v", err)
	}
	if got := onlyAddr(t, addrs); got != ip("203.0.113.7") {
		t.Fatalf("bootstrap дал %v", got)
	}
	if udp, _ := srv.Queries(); udp != 1 {
		t.Fatalf("bootstrap спросил апстрим %d раз, ожидался один", udp)
	}
}

// TestBootstrapPassesLiteralAddressThrough — адрес, записанный в ссылке
// числом, спрашивать не у кого (§6.8: от того, во что резолвится хостнейм
// узла, не зависит ничего).
func TestBootstrapPassesLiteralAddressThrough(t *testing.T) {
	b, srv := newBootstrapFixture(t)

	addrs, err := b.Lookup(context.Background(), "203.0.113.9")
	if err != nil {
		t.Fatalf("литерал не прошёл: %v", err)
	}
	if got := onlyAddr(t, addrs); got != ip("203.0.113.9") {
		t.Fatalf("литерал превратился в %v", got)
	}
	if udp, tcp := srv.Queries(); udp != 0 || tcp != 0 {
		t.Fatalf("на литерал ушёл запрос: udp=%d tcp=%d", udp, tcp)
	}
}

// TestBootstrapSurvivesDeadServer — первый сервер не отвечает, второй отвечает.
// Один недоступный резолвер не должен означать отсутствие DNS.
func TestBootstrapSurvivesDeadServer(t *testing.T) {
	b, srv := newBootstrapFixture(t)

	dead, err := dnstest.New()
	if err != nil {
		t.Fatalf("сервер: %v", err)
	}
	dead.Close() // порт больше никто не слушает

	b.servers = []netip.AddrPort{dead.Addr(), srv.Addr()}
	b.timeout = 300 * time.Millisecond

	addrs, err := b.Lookup(context.Background(), nodeHost)
	if err != nil {
		t.Fatalf("не разрешилось через живой сервер: %v", err)
	}
	if got := onlyAddr(t, addrs); got != ip("203.0.113.7") {
		t.Fatalf("пришло %v", got)
	}
}
