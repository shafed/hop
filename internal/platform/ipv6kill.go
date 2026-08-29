//go:build linux

package platform

import (
	"encoding/binary"
	"errors"
	"log/slog"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Зачистка соединений IPv6, переживших установку правила §6.9.
//
// Правило `ip -6 rule add unreachable` закрывает только НОВЫЕ соединения:
// у установленного сокета TCP маршрут уже разрешён и закэширован, и замер это
// показывает прямо — после правила `write` возвращает успех (n=26, err=nil), а
// `read` упирается в собственный таймаут приложения. Наружу при этом не уходит
// ничего (проверено на пире), то есть утечки нет; есть молчание, а §5.6
// требует отказа. Разрушение сокета переводит его в `ECONNABORTED` мгновенно.
//
// Механизм — SOCK_DESTROY по netlink, не `ss --kill`. Довод несущий и
// измеренный: `ss --kill` возвращает код 0 и тогда, когда не убил ничего, —
// замер без CAP_NET_ADMIN дал «SOCK_DESTROY answers: Operation not permitted»
// на stdout и код возврата 0. Решение «падать или деградировать» на таком коде
// возврата принять нельзя, а различать состояния по английской строке
// диагностики iproute2 — значит завести интерфейс там, где его никто не
// обещал. Второй замер того же рода: `ss --kill -6 -t dst [...]` фильтрует
// состояния по умолчанию и пропускает SYN_SENT, то есть ровно тот сокет,
// который переживает правило и без зачистки повиснет. Netlink даёт и errno, и
// явную маску состояний. Подробности — implementation-notes.md.

// stepKillIPv6 — имя шага Up, разрушающего соединения IPv6, установленные до
// подъёма туннеля.
const stepKillIPv6 = "ipv6 kill established"

// tcpListen — TCP_LISTEN в нумерации inet_diag. Слушателя ядро разрушать
// отказывается (замер: EINVAL, слушатель жив), и он ничего никуда не
// отправляет — отбирать его значило бы только сочинять себе ошибки.
const tcpListen = 10

// sweepRounds — сколько раз повторить дамп.
//
// Один проход почти достаточен: после правила новое соединение IPv6 не
// устанавливается вовсе (замер: ENETUNREACH за 45 мкс), значит множество целей
// не пополняется. Почти — потому что connect() разрешает маршрут ДО того, как
// вставит сокет в хэш-таблицу, и дамп, попавший ровно в этот зазор, сокета не
// увидит. Повтор его подберёт: к следующему дампу он уже в SYN_SENT. Цикл
// кончается, как только раунд не разрушил ничего, а предел стоит на случай
// ошибки, которая повторяется бесконечно.
const sweepRounds = 4

// killOutcome — как трактовать ответ ядра на одно разрушение.
type killOutcome int

const (
	killDone        killOutcome = iota // сокет разрушен
	killGone                           // сокета уже нет: закрылся между дампом и разрушением
	killUnsupported                    // ядро не умеет SOCK_DESTROY вовсе
	killRefused                        // всё остальное
)

// classifyKill разбирает errno netlink.
//
// ENOENT — не ошибка: между дампом и разрушением сокет мог закрыться сам, и
// это обычная гонка, а не отказ. Замер: тот же ENOENT приходит и на протокол,
// у которого обработчика diag нет вовсе, — значит EOPNOTSUPP ни одним из этих
// путей не приходит и свободен под «ядро собрано без CONFIG_INET_DIAG_DESTROY»
// (net/ipv4/tcp_diag.c: обработчик .destroy существует только под этим
// параметром). Проверить это замером здесь нельзя — нужно другое ядро, — но и
// решение от него не зависит: ни одна из веток Up не роняет, различается
// только текст в журнале.
func classifyKill(err error) killOutcome {
	switch {
	case err == nil:
		return killDone
	case errors.Is(err, unix.ENOENT):
		return killGone
	case errors.Is(err, unix.EOPNOTSUPP):
		return killUnsupported
	default:
		return killRefused
	}
}

// silencedIPv6 отбирает из дампа сокеты, которые правило §6.9 обрекло на
// молчание, — и ровно их.
//
// Границы отбора — замеры, а не намерение:
//   - `::1` и любой СВОЙ адрес машины забирает таблица `local` приоритетом 0,
//     выше нашего правила: соединение к своему же адресу после правила
//     продолжает работать, и разрушать его значило бы ломать работающее;
//   - соединение IPv4, принятое dual-stack слушателем, приезжает в дампе
//     AF_INET6 с адресом вида ::ffff:10.0.0.1 — это IPv4, правило его не
//     касается;
//   - слушатель ничего не отправляет, и ядро на его разрушение отвечает
//     EINVAL.
//
// Всё остальное — маршрутизируемый unicast, ULA и fe80:: unicast — лежит в
// `main` ниже правила (§6.9) и после правила молчит.
func silencedIPv6(socks []*netlink.Socket, own map[string]bool) []*netlink.Socket {
	var out []*netlink.Socket
	for _, s := range socks {
		d := s.ID.Destination
		switch {
		case s.State == tcpListen:
		case len(d) == 0 || d.IsUnspecified() || d.To4() != nil:
		case d.IsLoopback() || own[d.String()]:
		default:
			out = append(out, s)
		}
	}
	return out
}

// ownIPv6 — адреса IPv6 самой машины: ровно то, что лежит в таблице `local`.
func ownIPv6() (map[string]bool, error) {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V6)
	if err != nil {
		return nil, err
	}
	own := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		if a.IP != nil {
			own[a.IP.String()] = true
		}
	}
	return own, nil
}

// diagRequest — inet_diag_req_v2 (linux/inet_diag.h).
//
// Пишется руками, потому что netlink.SocketDestroy из библиотеки умеет только
// IPv4: замер — на паре адресов IPv6 она возвращает ErrNotImplemented, и в
// исходнике семейство запроса зашито как AF_INET. Дамп (SocketDiagTCP) при
// этом библиотечный и IPv6 разбирает правильно, включая cookie.
type diagRequest struct {
	family, proto uint8
	states        uint32
	id            netlink.SocketID
}

func (r *diagRequest) Len() int { return 56 }

func (r *diagRequest) Serialize() []byte {
	b := make([]byte, r.Len())
	b[0] = r.family
	b[1] = r.proto
	binary.NativeEndian.PutUint32(b[4:8], r.states)
	// Порты в сетевом порядке, адреса — как есть, остальное в порядке хоста.
	binary.BigEndian.PutUint16(b[8:10], r.id.SourcePort)
	binary.BigEndian.PutUint16(b[10:12], r.id.DestinationPort)
	copy(b[12:28], r.id.Source.To16())
	copy(b[28:44], r.id.Destination.To16())
	binary.NativeEndian.PutUint32(b[44:48], r.id.Interface)
	binary.NativeEndian.PutUint32(b[48:52], r.id.Cookie[0])
	binary.NativeEndian.PutUint32(b[52:56], r.id.Cookie[1])
	return b
}

// destroyTCP6 разрушает один сокет.
//
// Адресуется он тем же cookie, что приехал в дампе, а не одной пятёркой:
// cookie — это идентификатор конкретного сокета, и он снимает гонку, в которой
// между дампом и разрушением сокет закрылся, а его пятёрку занял новый.
func destroyTCP6(s *netlink.Socket) error {
	req := nl.NewNetlinkRequest(nl.SOCK_DESTROY, unix.NLM_F_ACK)
	req.AddData(&diagRequest{
		family: unix.AF_INET6,
		proto:  unix.IPPROTO_TCP,
		states: 1 << s.State,
		id:     s.ID,
	})
	_, err := req.Execute(unix.NETLINK_INET_DIAG, 0)
	return err
}

// sweepSilencedIPv6 — сам шаг Up.
//
// Он не возвращает ошибку и не роняет Up ни при каком исходе. Довод — §5.6, и
// именно в его пользу: правило §6.9 к этому моменту уже стоит, значит наружу
// не утекает ничего в любом случае, и без зачистки теряется только СРОК
// отказа. Уронить `Up` значило бы обменять ограниченный изъян (сокеты IPv6
// старше туннеля висят до собственного таймаута) на неограниченный: туннеля
// нет вовсе, и наружу в открытую идёт всё, включая IPv4. Тот же §5.6,
// обращённый на сам инструмент, требует второго: молчаливая деградация — это
// молчание, поэтому всё, что не вышло, уходит в журнал.
func sweepSilencedIPv6(log *slog.Logger) {
	own, err := ownIPv6()
	if err != nil {
		log.Warn("зачистка IPv6: не прочитаны свои адреса, соединения старше туннеля останутся молчать",
			"ошибка", err)
		return
	}

	killed, gone, refused := 0, 0, 0
	var firstErr error
	for round := 0; round < sweepRounds; round++ {
		socks, err := netlink.SocketDiagTCP(unix.AF_INET6)
		if err != nil {
			log.Warn("зачистка IPv6: дамп сокетов не удался, соединения старше туннеля останутся молчать",
				"ошибка", err, "раунд", round)
			return
		}
		targets := silencedIPv6(socks, own)
		if len(targets) == 0 {
			break
		}
		before := killed
		for i, s := range targets {
			derr := destroyTCP6(s)
			switch classifyKill(derr) {
			case killDone:
				killed++
			case killGone:
				gone++
			case killUnsupported:
				log.Warn("зачистка IPv6: ядро не умеет SOCK_DESTROY (нет CONFIG_INET_DIAG_DESTROY), "+
					"соединения IPv6 старше туннеля повиснут до своего таймаута TCP вместо отказа (§5.6)",
					"разрушено", killed, "осталось", len(targets)-i)
				return
			case killRefused:
				refused++
				if firstErr == nil {
					firstErr = derr
				}
			}
		}
		// Раунд, не разрушивший ничего, — признак того, что оставшееся не
		// разрушается в принципе. Повторять его нечем.
		if killed == before {
			break
		}
	}

	if refused > 0 {
		log.Warn("зачистка IPv6: часть соединений старше туннеля не разрушена и осталась молчать",
			"разрушено", killed, "не вышло", refused, "первая ошибка", firstErr)
		return
	}
	if killed > 0 || gone > 0 {
		log.Info("зачистка IPv6: соединения старше туннеля получили отказ",
			"разрушено", killed, "закрылись сами", gone)
	}
}
