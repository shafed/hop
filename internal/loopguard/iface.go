package loopguard

import (
	"fmt"
	"net"
	"net/netip"
)

// probeTarget — адрес, которым спрашивают ядро о дефолтном маршруте.
// TEST-NET-1 из RFC 5737: он не принадлежит никому, и по нему не уйдёт ни
// одного пакета, даже если что-то пойдёт не так.
const probeTarget = "192.0.2.1:9"

// DefaultInterface — имя интерфейса, которым ядро выпускает трафик наружу.
//
// Не разбор таблицы маршрутов, а вопрос к самому ядру: UDP-сокет, «соединённый»
// с внешним адресом, не отправляет ни одного пакета, но получает локальный
// адрес, выбранный маршрутизацией. Это ответ на тот самый вопрос, который ядро
// задаст себе для настоящего соединения, и он одинаков на трёх ОС, не требует
// прав и не зависит от формата вывода чужой утилиты.
func DefaultInterface() (string, error) {
	c, err := net.Dial("udp", probeTarget)
	if err != nil {
		return "", fmt.Errorf("loopguard: дефолтного маршрута нет: %w", err)
	}
	defer c.Close()

	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", fmt.Errorf("loopguard: локальный адрес %v не UDP", c.LocalAddr())
	}
	local, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return "", fmt.Errorf("loopguard: локальный адрес %v не разбирается", ua.IP)
	}

	ifaces, err := hostInterfaces()
	if err != nil {
		return "", err
	}
	return matchInterface(local.Unmap(), ifaces)
}

// Iface — интерфейс в том виде, в каком его знает поиск: имя и адреса.
type Iface struct {
	Name  string
	Addrs []netip.Addr
}

// matchInterface — чей это адрес. Отделено от опроса системы, чтобы решение
// проверялось на списке из теста, а не на сети машины.
func matchInterface(local netip.Addr, ifaces []Iface) (string, error) {
	for _, i := range ifaces {
		for _, a := range i.Addrs {
			if a.Unmap() == local {
				return i.Name, nil
			}
		}
	}
	return "", fmt.Errorf("loopguard: адрес %s не принадлежит ни одному интерфейсу", local)
}

func hostInterfaces() ([]Iface, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("loopguard: список интерфейсов: %w", err)
	}
	out := make([]Iface, 0, len(list))
	for _, i := range list {
		addrs, err := i.Addrs()
		if err != nil {
			continue // интерфейс исчез между двумя вызовами — не наше дело
		}
		f := Iface{Name: i.Name}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if addr, ok := netip.AddrFromSlice(n.IP); ok {
					f.Addrs = append(f.Addrs, addr.Unmap())
				}
			}
		}
		out = append(out, f)
	}
	return out, nil
}
