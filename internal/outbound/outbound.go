// Package outbound находит физический путь и привязывает к нему сокеты,
// которые не должны вернуться в туннель (§6.8).
package outbound

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
)

// ErrNoInterface означает, что остался только непривязанный сокет. В таком
// состоянии вызывающий обязан отказать: этот путь может вернуться прямо в TUN.
var ErrNoInterface = errors.New("outbound: физический интерфейс по умолчанию не определён")

// HTTPClient возвращает клиент, чьи новые сокеты биндятся так же, как Xray.
// Клон сохраняет proxy, HTTP/2, пул и таймауты стандартного транспорта; меняется
// только создание сокета.
func (s *Selector) HTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	d := &net.Dialer{Control: s.Control}
	tr.DialContext = d.DialContext
	return &http.Client{Transport: tr}
}

// DialDirect открывает соединение мимо туннеля, привязав сокет к текущему
// физическому интерфейсу (§6.8).
//
// Этим ходят bootstrap-резолвер (§5.7а) и перехваченный DNS в фазе bypass.
// Голый net.Dialer здесь запрещён: на Linux он ушёл бы в туннель по общим
// маршрутам, а на macOS и Windows петлю закрывает sockopt.interface, который
// ставит Xray, — то есть непривязанный сокет вернулся бы обратно в TUN.
//
// Интерфейс не определён — Control отказывает, и отказывает весь дозвон. Это
// намеренно: непривязанный fallback здесь и есть петля, ради предотвращения
// которой §6.8 написан.
func (s *Selector) DialDirect(ctx context.Context, network string, dst netip.AddrPort) (net.Conn, error) {
	d := &net.Dialer{Control: s.Control}
	return d.DialContext(ctx, network, dst.String())
}
