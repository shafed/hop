package netstack

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/shafed/hop/internal/policy"
)

// Протоколы для правил §6.10. Вынесены сюда, чтобы тот, кто пишет конфигурацию
// снаружи netstack, не тянул gvisor ради двух чисел.
const (
	ProtoTCP = uint8(header.TCPProtocolNumber)
	ProtoUDP = uint8(header.UDPProtocolNumber)
)

// Rule — одна строка списков §6.10.
//
// Ноль в каждом поле означает «любой», и это не удобство, а требование: DHCP
// DISCOVER уходит широковещательно, до всякого адреса, а «локальная сеть»
// описывается адресом без порта. Правило целиком нулевое совпадает со всем —
// выразить «выпустить наружу вообще всё» конфигурацией можно, и это осознанно:
// решение снять защиту принимает человек, а §5.6 отвечает за то, чтобы оно было
// явным, а не молчаливым.
//
// Сравнивается только назначение. Источник в §6.10 не участвует ни в одном
// правиле: за туннелем стоит один клиент, и разбирать его адрес нечем.
type Rule struct {
	// Prefix — куда. Нулевой (невалидный) префикс означает любой адрес.
	// Префикс другого семейства не совпадает никогда, поэтому список IPv4
	// не может случайно выпустить IPv6 (§6.9).
	Prefix netip.Prefix
	// Proto — ProtoTCP, ProtoUDP или 0 (любой).
	Proto uint8
	// Port — порт назначения или 0 (любой).
	Port uint16
}

func (r Rule) matches(f flow) bool {
	if r.Proto != 0 && r.Proto != f.proto {
		return false
	}
	if r.Port != 0 && r.Port != f.dst.Port() {
		return false
	}
	if r.Prefix.IsValid() && !r.Prefix.Contains(f.dst.Addr()) {
		return false
	}
	return true
}

// Routing — списки §6.10, пришедшие из конфигурации: что выпустить в локальную
// сеть и что заблокировать. Всё остальное идёт в туннель.
//
// Порядок между списками задан §3.4 и живёт в classify, а не здесь: bypass
// проверяется раньше block, поэтому пересечение списков разрешается в пользу
// bypass. Внутри одного списка порядок правил не значит ничего — совпадение
// любого правила решает.
type Routing struct {
	Bypass []Rule
	Block  []Rule
}

// DefaultRouting — умолчания §6.10 плюс исключения §5.6. Ровно тот набор,
// который до появления конфигурации был зашит в verdict.go.
//
// Возвращается копия: список — значение конфигурации, и вызывающий вправе его
// дополнить, не задев ничьё чужое умолчание.
func DefaultRouting() *Routing {
	return &Routing{
		Bypass: append(alwaysBypass(), serviceDiscovery()...),
		Block:  defaultBlock(),
	}
}

// alwaysBypass — исключения §5.6, «разрешённые всегда»: локальные сети (RFC1918
// и аналоги), DHCP, NTP. Без них fail-close ломает саму сеть, а не только выход
// в интернет, — поэтому конфигурация их не убирает (resolveRouting).
//
// Диапазоны выписаны префиксами, а не вызовами netip.Addr.IsPrivate и соседей:
// список обязан быть данными, иначе он не может прийти из конфигурации. Для
// IPv4 набор совпадает с прежними предикатами один в один; про IPv6 см.
// «Deviations» — до classify он не доходит вовсе (§6.9).
func alwaysBypass() []Rule {
	return []Rule{
		{Prefix: netip.MustParsePrefix("127.0.0.0/8")},    // loopback
		{Prefix: netip.MustParsePrefix("10.0.0.0/8")},     // RFC1918
		{Prefix: netip.MustParsePrefix("172.16.0.0/12")},  // RFC1918
		{Prefix: netip.MustParsePrefix("192.168.0.0/16")}, // RFC1918
		{Prefix: netip.MustParsePrefix("169.254.0.0/16")}, // link-local
		{Proto: ProtoUDP, Port: portDHCPSv},               // DHCP, до всякого адреса
		{Proto: ProtoUDP, Port: portDHCPCl},
		{Proto: ProtoUDP, Port: portNTP},
	}
}

// serviceDiscovery — обнаружение служб §6.10. Блокировать нельзя: сломаются
// Bonjour, AirPlay, AirPrint и поиск принтеров, заметнее всего на macOS.
//
// В отличие от alwaysBypass, это умолчание, а не пол: §5.6 их не перечисляет,
// и конфигурация вправе их убрать — тому, у кого в сети нет ни одного принтера,
// незачем выпускать multicast мимо туннеля.
func serviceDiscovery() []Rule {
	return []Rule{
		{Prefix: netip.PrefixFrom(addrMDNS, 32), Proto: ProtoUDP, Port: portMDNS},
		{Prefix: netip.PrefixFrom(addrSSDP, 32), Proto: ProtoUDP, Port: portSSDP},
	}
}

// defaultBlock — «Блокируем» из §6.10: широковещательный NetBIOS и прочий
// multicast и broadcast за пределами разрешённого выше.
//
// 224.0.0.0/4, а не 224.0.0.0/3 из текста §6.10: /3 захватывает ещё и
// 240.0.0.0/4, зарезервированный, который прежний код (Addr.IsMulticast) не
// блокировал. Расширять блокировку заодно с переводом списка в данные — значит
// прятать изменение поведения внутри рефакторинга; см. «Deviations».
func defaultBlock() []Rule {
	return []Rule{
		{Prefix: netip.PrefixFrom(addrBcast, 32)},
		{Prefix: netip.MustParsePrefix("224.0.0.0/4")},
		{Proto: ProtoUDP, Port: 135},
		{Proto: ProtoUDP, Port: 137},
		{Proto: ProtoUDP, Port: 138},
		{Proto: ProtoUDP, Port: 139},
	}
}

// resolveRouting — что стек на самом деле применит.
//
// Пустая конфигурация означает умолчания §6.10 — тот же приём, что у
// Config.DNSUpstreams в связке. Непустая применяется как есть, но исключения
// §5.6 подмешиваются к ней всегда: «разрешены всегда» — это про право
// конфигурации, а не только про фазу fail-close, иначе один неудачный конфиг
// оставляет машину без DHCP и без локальной сети.
//
// Здесь же живёт политика routing_lists: с выключенной политикой конфигурация
// игнорируется целиком и стек ведёт себя ровно как до её появления.
func resolveRouting(r *Routing) *Routing {
	if r == nil || !policy.RoutingLists.On() {
		return DefaultRouting()
	}
	return &Routing{
		Bypass: append(alwaysBypass(), r.Bypass...),
		Block:  append([]Rule(nil), r.Block...),
	}
}

func matchAny(rules []Rule, f flow) bool {
	for _, r := range rules {
		if r.matches(f) {
			return true
		}
	}
	return false
}
