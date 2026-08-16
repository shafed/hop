package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/policy"
)

// SystemResolver — системный резолвер процесса. Интерфейс, а не *net.Resolver,
// ровно ради теста про петлю: подставить туда «наш собственный резолвер» иначе
// нечем. *net.Resolver ему удовлетворяет.
type SystemResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DefaultBootstrapTimeout — бюджет одного разрешения хостнейма узла.
const DefaultBootstrapTimeout = 3 * time.Second

// BootstrapConfig — как разрешать хостнеймы узлов.
type BootstrapConfig struct {
	// Servers — куда спрашивать напрямую. Пусто — DefaultServers.
	Servers []netip.AddrPort
	// Transport — путь к этим серверам мимо туннеля. nil — обычные сокеты
	// процесса (Direct).
	Transport Transport
	// System — системный резолвер: то, во что вырождается bootstrap при
	// выключенной политике. nil — net.DefaultResolver.
	System  SystemResolver
	Clock   clock.Clock
	Timeout time.Duration
}

// Bootstrap — резолв хостнеймов самих узлов, мимо туннеля (§5.7а).
//
// Зачем отдельный резолвер, если у агента уже есть свой. Затем, что после
// поднятия туннеля системный резолвер указывает на туннель (§8.4: «DNS
// выставлен на адаптере»), а туннельный резолвер отвечает только при живом
// узле (§5.7б). Узел при этом задан хостнеймом, который ещё не разрешён.
// Замыкание: имя узла → живой узел → имя узла. Bootstrap разрывает его тем,
// что спрашивает публичные адреса напрямую, обычными сокетами процесса, —
// трафик агента в туннель не попадает по построению (§6.8).
//
// Политика §8: при bootstrap=off вопрос уходит системному резолверу, то есть
// в это самое замыкание. Краснеет TestBootstrapBreaksStartupLoop.
type Bootstrap struct {
	servers []netip.AddrPort
	tr      Transport
	system  SystemResolver
	clk     clock.Clock
	timeout time.Duration
}

// NewBootstrap собирает bootstrap-резолвер.
func NewBootstrap(cfg BootstrapConfig) *Bootstrap {
	b := &Bootstrap{
		servers: cfg.Servers,
		tr:      cfg.Transport,
		system:  cfg.System,
		clk:     cfg.Clock,
		timeout: cfg.Timeout,
	}
	if len(b.servers) == 0 {
		b.servers = DefaultServers
	}
	if b.tr == nil {
		b.tr = NewNodeTransport(Direct{})
	}
	if b.system == nil {
		b.system = net.DefaultResolver
	}
	if b.clk == nil {
		b.clk = clock.System{}
	}
	if b.timeout <= 0 {
		b.timeout = DefaultBootstrapTimeout
	}
	return b
}

// Lookup разрешает хостнейм узла в адреса.
//
// Адрес, записанный в ссылке числом, возвращается как есть: спрашивать про
// него некого, и §6.8 прямо говорит, что от того, во что резолвится хостнейм
// узла, не зависит ничего.
func (b *Bootstrap) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	if !policy.Bootstrap.On() {
		return b.system.LookupNetIP(ctx, "ip4", host)
	}

	name, err := dnsmessage.NewName(fqdn(host))
	if err != nil {
		return nil, fmt.Errorf("resolver: негодный хостнейм %q: %w", host, err)
	}
	q := question{name: name, typ: dnsmessage.TypeA, class: dnsmessage.ClassINET, rd: true}

	var lastErr error
	for _, srv := range b.servers {
		addrs, err := b.ask(ctx, srv, q)
		if err != nil {
			lastErr = err
			continue
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
		lastErr = fmt.Errorf("resolver: %q не имеет адресов", host)
	}
	if lastErr == nil {
		lastErr = errors.New("resolver: некого спросить")
	}
	return nil, lastErr
}

func (b *Bootstrap) ask(ctx context.Context, srv netip.AddrPort, q question) ([]netip.Addr, error) {
	wire, id, err := q.wire()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	raw, err := b.tr.Exchange(ctx, srv, wire, false)
	if err != nil {
		return nil, err
	}
	msg, err := q.accept(raw, id)
	if err != nil {
		return nil, err
	}
	if msg.Header.Truncated {
		raw, err = b.tr.Exchange(ctx, srv, wire, true)
		if err != nil {
			return nil, err
		}
		if msg, err = q.accept(raw, id); err != nil {
			return nil, err
		}
	}

	var out []netip.Addr
	for _, a := range msg.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			out = append(out, netip.AddrFrom4(r.A))
		}
	}
	return out, nil
}

// fqdn — имя с точкой на конце: в таком виде его требует dnsmessage.NewName.
func fqdn(name string) string {
	if name == "" || name[len(name)-1] != '.' {
		return name + "."
	}
	return name
}
