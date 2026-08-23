package engine

import (
	"context"
	"errors"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
)

type recordingSystemDialer struct {
	called  int
	sockopt *internet.SocketConfig
}

func (d *recordingSystemDialer) Dial(_ context.Context, _ xnet.Address, _ xnet.Destination, sockopt *internet.SocketConfig) (xnet.Conn, error) {
	d.called++
	d.sockopt = sockopt
	return nil, nil
}

func (*recordingSystemDialer) DestIpAddress() xnet.IP { return nil }

func nodeDialContext(id string) context.Context {
	return session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Tag: OutboundTag(id)}})
}

// TestW36NodeDialBindsCurrentPhysicalInterface — W36: защита от петли стоит на
// каждом сокете Xray, а не на всех процессах с uid агента. Интерфейс спрашивается
// в момент dial, поэтому смена сети действует на следующий сокет.
func TestW36NodeDialBindsCurrentPhysicalInterface(t *testing.T) {
	inner := &recordingSystemDialer{}
	interfaces := []string{"wifi0", "eth0"}
	n := 0
	physical := func() (string, error) {
		name := interfaces[n]
		n++
		return name, nil
	}
	hook := watchNode("n", nil, physical)
	defer unwatchNode("n", hook)

	d := &nodeDialer{inner: inner}
	original := &internet.SocketConfig{TcpKeepAliveIdle: 23}
	if _, err := d.Dial(nodeDialContext("n"), nil, xnet.Destination{}, original); err != nil {
		t.Fatalf("первый дозвон: %v", err)
	}
	if inner.sockopt.Interface != "wifi0" || inner.sockopt.TcpKeepAliveIdle != 23 {
		t.Fatalf("socket config = %+v, ожидался wifi0 с сохранёнными опциями", inner.sockopt)
	}
	if original.Interface != "" {
		t.Fatal("диалер изменил общий SocketConfig транспорта: параллельные дозвоны получили бы гонку")
	}

	if _, err := d.Dial(nodeDialContext("n"), nil, xnet.Destination{}, nil); err != nil {
		t.Fatalf("второй дозвон: %v", err)
	}
	if inner.sockopt == nil || inner.sockopt.Interface != "eth0" {
		t.Fatalf("после смены сети interface = %v, ожидался eth0", inner.sockopt)
	}
}

func TestW36NodeDialFailsClosedWithoutPhysicalInterface(t *testing.T) {
	inner := &recordingSystemDialer{}
	hook := watchNode("n", nil, func() (string, error) { return "", errors.New("нет default route") })
	defer unwatchNode("n", hook)

	_, err := (&nodeDialer{inner: inner}).Dial(nodeDialContext("n"), nil, xnet.Destination{}, nil)
	if err == nil {
		t.Fatal("дозвон ушёл без интерфейса: непривязанный сокет вернулся бы в TUN петлёй")
	}
	if inner.called != 0 {
		t.Fatalf("внутренний диалер вызван %d раз: fail-close произошёл после создания сокета", inner.called)
	}
}

func TestDrainingEngineCannotUnbindReplacementNode(t *testing.T) {
	old := watchNode("same", nil, func() (string, error) { return "old0", nil })
	next := watchNode("same", nil, func() (string, error) { return "new0", nil })
	defer unwatchNode("same", next)

	// Пересборки по подписке пересекаются, пока старый Xray дренируется. Его
	// поздний Close не должен удалить привязку нового инстанса для того же
	// стабильного id узла.
	unwatchNode("same", old)
	inner := &recordingSystemDialer{}
	if _, err := (&nodeDialer{inner: inner}).Dial(nodeDialContext("same"), nil, xnet.Destination{}, nil); err != nil {
		t.Fatalf("новый инстанс потерял привязку после закрытия старого: %v", err)
	}
	if inner.sockopt.Interface != "new0" {
		t.Fatalf("interface = %q, ожидался новый provider", inner.sockopt.Interface)
	}
}
