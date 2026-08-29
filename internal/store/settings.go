package store

import (
	"net/netip"

	"github.com/shafed/hop/internal/netstack"
)

// Settings — заготовка: настройки §6.10 и §5.7 пока не читаются с диска.
type Settings struct {
	Routing      *netstack.Routing
	DNSUpstreams []netip.AddrPort
}

// Settings отдаёт настройки стора. До реализации — пусто всегда.
func (s *Store) Settings() Settings { return Settings{} }
