// Package loopguard — защита от петли (§6.8) и блокировка IPv6 (§6.9).
//
// Механизмы разные по ОС, решение одно: трафик, которым держится сам туннель,
// не должен попасть внутрь туннеля, а IPv6 не должен уйти мимо него.
//
//   - Linux — `ip rule` с UID-диапазоном агента. Bind не годится:
//     SO_BINDTODEVICE исторически требует CAP_NET_RAW, а агент непривилегирован.
//     Правило ставит сервис, агенту не нужно ничего, и правило переживает смену
//     интерфейса, в отличие от bind-to-device.
//   - macOS и Windows — sockopt.interface (IP_BOUND_IF, IP_UNICAST_IF):
//     исходящие сокеты биндятся к текущему дефолтному интерфейсу. Привилегий
//     обе опции не требуют, поэтому от сервиса нужно только имя интерфейса, а
//     ставит опцию сам движок (engine.Options.BindInterface).
//
// Решение здесь отделено от исполнения намеренно. Пакет строит **план** —
// список команд вместе с откатом, имя интерфейса для bind и форму туннельных
// маршрутов, — а выполняет план платформенный слой через журнал netstate.
// Поэтому §6.8 и §6.9 проверяются без root и на любой ОС: тест смотрит на
// решение, а не на живое ядро. Тест, которому нужен root, в CI не запустится,
// а значит не охранит политику §8.
package loopguard

import (
	"fmt"
	"runtime"

	"github.com/shafed/hop/internal/netstate"
	"github.com/shafed/hop/internal/policy"
)

// Приоритеты правил, которые раскладывает этот пакет.
//
// Порядок — часть контракта. Защита от петли стоит выше всего, что раскладывает
// сервис: попади она ниже перехвата :53, и собственный резолв агента (§5.7а)
// ушёл бы в туннель, то есть в ту самую петлю. Блокировка IPv6, наоборот, стоит
// ниже — исключений из неё нет, включая агента: в v1 IPv6 нет вовсе (§6.9).
const (
	prioLoopGuard = 30000 // §6.8: трафик агента мимо туннеля
	prioIPv6Block = 31700 // §6.9: глобальный IPv6 — отказ
)

// Priorities — приоритеты, по которым уборка за умершим сервисом опознаёт
// правила этого пакета (§6.2, T29). Правило по UID-диапазону не привязано к
// интерфейсу и потому переживает смерть владельца.
var Priorities = []int{prioLoopGuard, prioIPv6Block}

// GlobalIPv6 — то, что блокирует §6.9: глобальный юникаст IPv6 (RFC 4291).
//
// Не `::/0` намеренно. Link-local (fe80::/10) держит NDP, без которого рушится
// вся IPv6-часть локальной сети, а ff00::/8 несёт mDNS и SSDP, которые §6.10
// велит выпускать в локальную сеть, а не блокировать. Утечь мимо туннеля может
// только глобально маршрутизируемый адрес — его и блокируем.
const GlobalIPv6 = "2000::/3"

// Subnets — восемь подсетей §5.10 вместо одного `0.0.0.0/0`.
//
// Только macOS: два дефолтных маршрута там конфликтуют, и после падения
// процесса система остаётся без маршрута вовсе. Восемь подсетей покрывают всё
// адресное пространство, выигрывают по longest-prefix и оставляют системный
// дефолт нетронутым.
var Subnets = []string{
	"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5",
	"16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1",
}

// Params — то, от чего зависит план.
type Params struct {
	// AgentUID — чей трафик выводится мимо туннеля (§6.8, Linux). Сервис знает
	// его из учётных данных пира на управляющем сокете, а не со слов агента.
	AgentUID int
	// SystemUIDMax — SYS_UID_MAX машины: последний UID служебных учёток.
	// Отдаёт сервис (SysUIDMax), а не план: план — данные, и читать файлы
	// машины он не должен, иначе решение перестанет проверяться где угодно.
	SystemUIDMax int
}

// Step — одно изменение сети и то, чем оно снимается.
type Step struct {
	Name string
	Add  []string
	Del  []string
}

// Plan — решение защиты для одной ОС.
type Plan struct {
	// Bind — имя дефолтного интерфейса для sockopt.interface (§6.8). Пусто на
	// Linux: там петлю режет правило маршрутизации, и сокетам агента не нужно
	// ничего.
	Bind string
	// Routes — что уводится в туннель: восемь подсетей на macOS (§5.10), один
	// дефолт на Linux и Windows.
	Routes []string
	// Steps — изменения сети вместе с откатом.
	Steps []Step
}

// Runner выполняет одну команду. В продукте это exec.Command, в тесте —
// запись: проверяется решение, а не сеть машины.
type Runner func(args []string) error

// New — план защиты для текущей ОС. Имя дефолтного интерфейса спрашивается у
// ядра (§6.8, macOS и Windows).
func New(p Params) (Plan, error) { return plan(runtime.GOOS, p, DefaultInterface) }

// plan — то же решение с подставным определителем интерфейса.
//
// ОС здесь аргумент, а не build tag: план — это данные, и решение для всех трёх
// ОС обязано проверяться на любой из них. Под тегами оно проверялось бы только
// на своей, то есть в CI — только на Linux.
func plan(goos string, p Params, lookup func() (string, error)) (Plan, error) {
	switch goos {
	case "linux":
		return linuxPlan(p)
	case "darwin":
		return bindPlan(Subnets, lookup, darwinIPv6Block())
	case "windows":
		return bindPlan([]string{"0.0.0.0/0"}, lookup, windowsIPv6Block())
	default:
		return Plan{}, fmt.Errorf("loopguard: защиты от петли для %s нет (§6.8)", goos)
	}
}

// systemUID — годится ли UID в правило §6.8.
//
// Правило выводит мимо туннеля всех, кто работает под этим UID, поэтому UID
// обязан принадлежать служебной учётке: UID человека увёл бы мимо туннеля
// пользователя целиком (C25). Граница служебных учёток — SYS_UID_MAX машины.
//
// Порог не задан — отказ: забытое поле обязано закрывать туннель, а не
// открывать дыру молча. Root (0) порог проходит — интерактивным пользователем
// он не является, и под ним работает агент стенда L3. То, что агент продукта
// не должен быть root, закрепляет упаковка (§1 С1, §5.2), а не этот план.
func systemUID(uid, max int) bool { return max > 0 && uid >= 0 && uid <= max }

// linuxPlan — правило по UID-диапазону плюс отказ для глобального IPv6.
func linuxPlan(p Params) (Plan, error) {
	pl := Plan{Routes: []string{"0.0.0.0/0"}}

	// Политика §8: без развилки трафик агента к узлу возвращается в
	// собственный TUN и наматывается сам на себя — T25.
	if policy.LoopGuard.On() {
		if !systemUID(p.AgentUID, p.SystemUIDMax) {
			// Отказ вслух, а не правило мимо: поставленное на UID человека,
			// оно уводит мимо туннеля весь его трафик — правило §6.8 стоит
			// выше туннельного и совпадает первым (C25).
			return Plan{}, fmt.Errorf(
				"loopguard: UID агента %d не служебный при SYS_UID_MAX=%d — "+
					"правило §6.8 увело бы мимо туннеля весь трафик этого UID; "+
					"агент обязан работать под системным пользователем hop (§1 С1)",
				p.AgentUID, p.SystemUIDMax)
		}
		uid := fmt.Sprintf("%d-%d", p.AgentUID, p.AgentUID)
		pl.Steps = append(pl.Steps, Step{
			Name: "loop guard uidrange " + uid,
			Add:  ip("rule", "add", "uidrange", uid, "lookup", "main", "priority", fmt.Sprint(prioLoopGuard)),
			Del:  ip("rule", "del", "uidrange", uid, "lookup", "main", "priority", fmt.Sprint(prioLoopGuard)),
		})
	}

	// Отказ, а не blackhole: правило-blackhole на Linux даёт EINVAL, а
	// unreachable — EHOSTUNREACH, то есть внятный отказ вместо молчания (§5.6).
	if policy.IPv6Block.On() {
		pl.Steps = append(pl.Steps, Step{
			Name: "ipv6 block " + GlobalIPv6,
			Add:  ip("-6", "rule", "add", "to", GlobalIPv6, "unreachable", "priority", fmt.Sprint(prioIPv6Block)),
			Del:  ip("-6", "rule", "del", "to", GlobalIPv6, "unreachable", "priority", fmt.Sprint(prioIPv6Block)),
		})
	}
	return pl, nil
}

// bindPlan — macOS и Windows: защита от петли выражена не правилом, а привязкой
// сокетов, поэтому шагов у неё нет вовсе — только имя интерфейса наверх.
func bindPlan(routes []string, lookup func() (string, error), block Step) (Plan, error) {
	pl := Plan{Routes: routes}
	if policy.LoopGuard.On() {
		name, err := lookup()
		if err != nil {
			return Plan{}, err
		}
		pl.Bind = name
	}
	if policy.IPv6Block.On() {
		pl.Steps = append(pl.Steps, block)
	}
	return pl, nil
}

// darwinIPv6Block — reject-маршрут через loopback: BSD-маршрут с флагом
// `-reject` отвечает EHOSTUNREACH, а `-blackhole` молчит (§5.6).
func darwinIPv6Block() Step {
	return Step{
		Name: "ipv6 block " + GlobalIPv6,
		Add:  []string{"route", "-n", "add", "-inet6", "-net", GlobalIPv6, "::1", "-reject"},
		Del:  []string{"route", "-n", "delete", "-inet6", "-net", GlobalIPv6},
	}
}

// windowsIPv6Block — правило файрвола, а не маршрут: reject-маршрутов у Windows
// нет, а маршрут в никуда молчал бы. Заблокированное соединение приложение
// видит ошибкой сразу.
func windowsIPv6Block() Step {
	const name = "name=hop-ipv6-block"
	return Step{
		Name: "ipv6 block " + GlobalIPv6,
		Add: []string{"netsh", "advfirewall", "firewall", "add", "rule", name,
			"dir=out", "action=block", "remoteip=" + GlobalIPv6},
		Del: []string{"netsh", "advfirewall", "firewall", "delete", "rule", name},
	}
}

// Apply ставит шаги плана через журнал: изменение и его откат ложатся одним
// вызовом, иначе однажды изменение случится без отката и снапшот §8.4 будет не
// вернуть.
func Apply(j *netstate.Journal, p Plan, run Runner) error {
	for _, s := range p.Steps {
		s := s
		add := func() error { return run(s.Add) }
		del := func() error { return run(s.Del) }
		if err := j.Do(s.Name, add, del); err != nil {
			return err
		}
	}
	return nil
}

func ip(args ...string) []string { return append([]string{"ip"}, args...) }
