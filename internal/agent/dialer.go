package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/shafed/hop/internal/netstack"
)

// ErrNoNode — дозвониться некуда: живого узла нет. Netstack превращает это в
// отказ (§5.6), а не в молчание.
var ErrNoNode = errors.New("agent: живого узла нет")

// picker — то, что связка спрашивает у живости на каждом дозвоне.
//
// Узкий интерфейс, а не *health.Manager: во-первых, на этом пути лежит каждое
// исходящее соединение, и таскать снимок всех узлов ради одной строки дорого;
// во-вторых, фейк в тесте выражается двумя функциями.
type picker interface {
	// Active — id узла, которому принадлежат новые соединения, или пусто.
	Active() string
	// Healthy — различает «узла нет, потому что все мертвы» и «узла нет,
	// потому что ещё не проверяли». Без второго стартовое окно §5.6
	// неотличимо от fail-close, и трафик получает RST там, где обязан ждать.
	Healthy() bool
}

// dialer соединяет netstack с движком. Реализует netstack.Dialer.
//
// Узел выбирается **на момент дозвона** (Р30): диалер спрашивает живость, когда
// открывает соединение, и дальше поток принадлежит этому узлу до конца. Смерть
// узла посреди установленного соединения рвёт его (§5.5, reason: dead), но не
// передозванивает: повтор означал бы либо буфер неограниченного размера, либо
// TLS-сессию, начатую с одним собеседником и продолженную с другим.
//
// Чего диалер не делает: он не зовёт health.ReportFailure. Классификация отказа
// живёт в engine/classify.go и больше нигде (§6.15, D10), а сюда приезжает уже
// готовое соединение или готовая ошибка.
type dialer struct {
	pick   picker
	engine *holder
}

func newDialer(p picker, h *holder) *dialer { return &dialer{pick: p, engine: h} }

// DialTCP — исходящее TCP через активный узел.
func (d *dialer) DialTCP(dst netip.AddrPort) (net.Conn, error) {
	in, node, err := d.route()
	if err != nil {
		return nil, err
	}

	c, err := in.x.DialTCP(context.Background(), node, dst.String())
	if err != nil {
		in.release()
		return nil, err
	}
	return &countedConn{Conn: c, in: in}, nil
}

// DialUDP — исходящее UDP через активный узел.
//
// src — исходный адрес клиента, а не назначение: core.DialUDP отдаёт один
// PacketConn на исходный порт, и это ровно то, из чего получается full-cone
// (§5.3). Сюда он приходит уже как ключ NAT-таблицы netstack.
func (d *dialer) DialUDP(src netip.AddrPort) (net.PacketConn, error) {
	in, node, err := d.route()
	if err != nil {
		return nil, err
	}

	pc, err := in.x.DialUDP(context.Background(), node)
	if err != nil {
		in.release()
		return nil, err
	}
	return &countedPacketConn{PacketConn: pc, in: in}, nil
}

// route выбирает инстанс и узел и занимает место в счётчике дренажа.
//
// Занимает до дозвона, а не после: иначе между удачным дозвоном и инкрементом
// лежит окно, в котором дренаж считает инстанс свободным и закрывает его из-под
// только что выданного соединения.
func (d *dialer) route() (*instance, string, error) {
	node := d.pick.Active()
	if node == "" {
		// Различие §5.6, и оно наблюдаемо клиентом: в стартовом окне поток
		// придерживается (netstack не отвечает на SYN, клиент повторит), при
		// fail-close — отвергается RST'ом.
		if d.pick.Healthy() {
			return nil, "", netstack.ErrNotReady
		}
		return nil, "", ErrNoNode
	}
	in := d.engine.current()
	if in == nil {
		return nil, "", ErrNoNode
	}
	in.acquire()
	return in, node, nil
}
