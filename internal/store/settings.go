package store

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"

	"github.com/shafed/hop/internal/netstack"
	"github.com/shafed/hop/internal/policy"
)

// settingsFile — четвёртый файл раскладки §2. Публичный, 0644: секретов в нём
// нет по построению — это правила маршрутизации и адреса резолверов, всё то,
// что человек и должен править руками.
const settingsFile = "settings.json"

// Settings — настройки продукта, лежащие рядом с узлами: списки §6.10 и
// апстримы §5.7.
//
// Оба поля необязательны, и nil у каждого значит «умолчания», а не «пусто»:
// netstack.resolveRouting и agent.wire трактуют пустое поле именно так, и
// формат обязан уметь выразить ту же разницу. Отсюда указатель у Routing:
// раздела нет — умолчания §6.10; раздел есть и пуст — пустые списки, то есть
// человек убрал обнаружение служб (§6.10 разрешает: это умолчание, а не пол).
type Settings struct {
	Routing      *netstack.Routing
	DNSUpstreams []netip.AddrPort
}

func (s Settings) clone() Settings {
	if s.Routing != nil {
		s.Routing = &netstack.Routing{
			Bypass: slices.Clone(s.Routing.Bypass),
			Block:  slices.Clone(s.Routing.Block),
		}
	}
	s.DNSUpstreams = slices.Clone(s.DNSUpstreams)
	return s
}

// Settings отдаёт настройки, прочитанные при Open.
//
// Копия, а не то, что лежит в сторе: списки — значения конфигурации, и
// вызывающий вправе их дополнить, не задев ничьё чужое (тот же довод, что у
// cloneNode и у netstack.DefaultRouting).
func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.clone()
}

type diskSettings struct {
	Version int          `json:"version"`
	Routing *diskRouting `json:"routing,omitempty"`
	// DNSUpstreams — «адрес:порт» строками, а не парой полей: файл читают
	// глазами, и «1.1.1.1:53» узнаётся мгновенно.
	DNSUpstreams []string `json:"dns_upstreams,omitempty"`
}

type diskRouting struct {
	Bypass []diskRule `json:"bypass"`
	Block  []diskRule `json:"block"`
}

// diskRule — правило §6.10 на диске. Протокол словом, а не числом (приём
// unsup_reason и state: перенумерование не должно молча переназначать смысл),
// порт числом типа int, а не uint16, — чтобы «70000» дало внятный отказ про
// диапазон, а не про то, что JSON не лёг в поле.
type diskRule struct {
	Prefix string `json:"prefix,omitempty"`
	Proto  string `json:"proto,omitempty"`
	Port   int    `json:"port,omitempty"`
}

// readSettings читает настройки. Отсутствующий файл — не ошибка: он означает
// умолчания и будет заведён пустым, как остальные три (§6.14 — про права
// существующего каталога, а не про будущее его состояние).
//
// Порча симметрична nodes.json, а не health.json (Р13): потерянная живость
// стоит одного раунда проб, а молча потерянное правило «блокировать 137» —
// это исчезнувшее решение пользователя, о котором он узнает только по чужому
// трафику. §5.6 требует отказа, а не молчания, и здесь тот же выбор, только
// обращённый к человеку.
//
// Политика settings_file гасит именно чтение: с выключенной файл не читается и
// не проверяется, и продукт живёт ровно как до её появления.
func (s *Store) readSettings() error {
	if !policy.SettingsFile.On() {
		return nil
	}
	raw, ok, err := readFile(filepath.Join(s.root, settingsFile))
	if err != nil || !ok {
		return err
	}
	set, err := decodeSettings(raw)
	if err != nil {
		return fmt.Errorf("store: %s нечитаем (%w); файл не тронут — почините или удалите его вручную, молча вернуться к умолчаниям значило бы отменить ваши правила, не сказав ни слова", settingsFile, err)
	}
	s.settings = set
	return nil
}

func encodeSettings(s Settings) ([]byte, error) {
	d := diskSettings{Version: diskVersion}
	if s.Routing != nil {
		d.Routing = &diskRouting{
			Bypass: encodeRules(s.Routing.Bypass),
			Block:  encodeRules(s.Routing.Block),
		}
	}
	for _, up := range s.DNSUpstreams {
		d.DNSUpstreams = append(d.DNSUpstreams, up.String())
	}
	return marshal(d)
}

func encodeRules(rules []netstack.Rule) []diskRule {
	out := make([]diskRule, 0, len(rules))
	for _, r := range rules {
		d := diskRule{Port: int(r.Port)}
		if r.Prefix.IsValid() {
			d.Prefix = r.Prefix.String()
		}
		switch r.Proto {
		case netstack.ProtoTCP:
			d.Proto = "tcp"
		case netstack.ProtoUDP:
			d.Proto = "udp"
		}
		out = append(out, d)
	}
	return out
}

func decodeSettings(raw []byte) (Settings, error) {
	var d diskSettings
	if err := json.Unmarshal(raw, &d); err != nil {
		return Settings{}, err
	}
	// Версия из будущего — отказ, а не «прочитаем что поймём»: файл новее нас
	// может означать полями то, чего мы не знаем, и разобранная половина
	// выглядела бы как полностью применённая конфигурация.
	if d.Version > diskVersion {
		return Settings{}, fmt.Errorf("версия %d новее известной %d — этот файл писала сборка новее вашей", d.Version, diskVersion)
	}

	var set Settings
	if d.Routing != nil {
		bypass, err := decodeRules("bypass", d.Routing.Bypass)
		if err != nil {
			return Settings{}, err
		}
		block, err := decodeRules("block", d.Routing.Block)
		if err != nil {
			return Settings{}, err
		}
		set.Routing = &netstack.Routing{Bypass: bypass, Block: block}
	}

	for i, up := range d.DNSUpstreams {
		ap, err := netip.ParseAddrPort(up)
		if err != nil {
			// Имя, а не адрес, — самая частая ошибка здесь, и отказ обязан
			// объяснять почему: §5.7(а) резолвит имена через резолвер,
			// который сам собирается из этого списка.
			return Settings{}, fmt.Errorf("dns_upstreams[%d] = %q: нужен адрес с портом вида 1.1.1.1:53 (%w); имя разрешать нечем — резолвер §5.7 собирается как раз из этого списка", i, up, err)
		}
		if ap.Port() == 0 {
			return Settings{}, fmt.Errorf("dns_upstreams[%d] = %q: порт 0 никуда не ведёт, для DNS это 53 или 853", i, up)
		}
		set.DNSUpstreams = append(set.DNSUpstreams, ap)
	}
	return set, nil
}

func decodeRules(list string, rules []diskRule) ([]netstack.Rule, error) {
	out := make([]netstack.Rule, 0, len(rules))
	for i, r := range rules {
		rule, err := decodeRule(r)
		if err != nil {
			return nil, fmt.Errorf("routing.%s[%d]: %w", list, i, err)
		}
		out = append(out, rule)
	}
	return out, nil
}

// decodeRule — вся проверка пользовательского ввода §6.10 в одном месте.
//
// Пустое правило отвергается, хотя §6.10 и разрешает выразить конфигурацией
// «выпустить наружу вообще всё»: разрешено там именно явное решение человека, а
// `{}` в списке — это опечатка, неотличимая от решения. Явная форма остаётся —
// prefix «0.0.0.0/0», — и она же говорит сама за себя при чтении файла глазами.
// IPv6 в v1 до вердикта не доходит вовсе (§6.9), поэтому «всё» тут и есть /0.
func decodeRule(r diskRule) (netstack.Rule, error) {
	var out netstack.Rule

	if r.Prefix != "" {
		p, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			return out, fmt.Errorf("prefix %q не разбирается: %w", r.Prefix, err)
		}
		// Немаскированный префикс работал бы молча и не так, как написан:
		// Contains смотрит только на биты маски, то есть «192.168.10.5/24»
		// совпадает со всей подсетью, а читается как один адрес.
		if masked := p.Masked(); masked != p {
			return out, fmt.Errorf("prefix %q задан не по маске: биты за маской ни на что не влияют, напишите %s или %s/%d", r.Prefix, masked, p.Addr(), p.Addr().BitLen())
		}
		out.Prefix = p
	}

	switch r.Proto {
	case "":
	case "tcp":
		out.Proto = netstack.ProtoTCP
	case "udp":
		out.Proto = netstack.ProtoUDP
	default:
		return out, fmt.Errorf("proto %q неизвестен: бывает tcp, udp или пусто (любой)", r.Proto)
	}

	if r.Port < 0 || r.Port > 65535 {
		return out, fmt.Errorf("port %d вне диапазона 0..65535 (0 означает любой)", r.Port)
	}
	out.Port = uint16(r.Port)

	if !out.Prefix.IsValid() && out.Proto == 0 && out.Port == 0 {
		return out, fmt.Errorf("правило без единого поля совпадает со всем; если это и имелось в виду, напишите его явно: prefix \"0.0.0.0/0\"")
	}
	return out, nil
}
