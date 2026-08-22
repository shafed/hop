// Package outbound находит физический путь и привязывает к нему сокеты,
// которые не должны вернуться в туннель (§6.8).
package outbound

import (
	"errors"
	"net"
	"net/http"
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
