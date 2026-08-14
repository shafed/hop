package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/policy"
)

// nodeFault — отказ, про который Xray сказал, что он с пути к узлу.
//
// Разделение проходит здесь, а не по тексту ошибки: узел сообщает о своих
// провалах через session.SubmitOutboundErrorToOriginator, а обрыв, устроенный
// целевым хостом, доезжает до нас обычным EOF на трубе и никем не сообщается.
// То есть «чей отказ» — это факт, а не догадка по строке.
type nodeFault struct{ err error }

func (f *nodeFault) Error() string { return f.err.Error() }
func (f *nodeFault) Unwrap() error { return f.err }

// classify раскладывает ошибку исходящего по перечислению §6.15.
//
// Второе значение — «это смерть узла». false означает, что отказ пришёл от
// целевого хоста, а не от узла: connection refused от сайта, 5xx, NXDOMAIN. Их
// в §6.15 нет, и узел они не убивают.
//
// Это единственное место классификации во всём продукте (D10). Стоит завести
// второе — и однажды упавший сайт тихо начнёт считаться смертью узла; §6.15
// написан ровно про этот сценарий.
//
// Политика error_classify: при выключении развилка исчезает — смертью
// становится любая ошибка, и T20 краснеет (502 от сайта убивает живой узел).
func classify(err error) (health.FailureKind, bool) {
	if err == nil {
		return 0, false
	}

	if !policy.ErrorClassify.On() {
		// Перечисления §6.15 нет: всякий отказ на пути трафика считается
		// смертью узла. Это та самая реализация «по замыслу», от которой
		// §6.15 предостерегает, — сайт уносит с собой живой узел.
		return health.ProxyRefused, true
	}

	var fault *nodeFault
	if !errors.As(err, &fault) {
		// Отказ не с пути к узлу: сайт закрыл соединение, ответил 5xx, имя не
		// разрешилось, поток кончился штатным EOF. Узел жив.
		return 0, false
	}

	switch inner := fault.err; {
	case isUnreachable(inner):
		return health.DialTimeout, true
	case isTLS(inner):
		return health.TLSError, true
	case isTorn(inner):
		return health.HandshakeFailed, true
	default:
		// Узел соединение принял, но проксировать не стал. Открытого «прочее»
		// в перечислении нет намеренно: §6.15 замкнут, и всякий отказ узла
		// обязан получить один из четырёх видов.
		return health.ProxyRefused, true
	}
}

// report — единственный call-site health.ReportFailure и health.ReportSuccess
// (D10, за этим следит линт).
//
// err == nil означает успех: уходит ReportSuccess с rtt. Иначе ошибка идёт в
// classify, и ReportFailure зовётся, только если это смерть узла.
//
// Возвращает err как есть, чтобы вызывающий писал `return c, e.report(id, err,
// rtt)` и не мог случайно проглотить ошибку по пути.
func (e *Engine) report(nodeID string, err error, rtt time.Duration) error {
	if err == nil {
		e.rep.ReportSuccess(nodeID, rtt)
		return nil
	}
	if kind, dead := classify(err); dead {
		e.rep.ReportFailure(nodeID, kind)
	}
	return err
}

// isUnreachable — до узла не дошли вовсе: таймаут, отказ, недостижимость,
// неразрешимое имя. Всё это §6.15 зовёт DialTimeout.
func isUnreachable(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, os.ErrDeadlineExceeded),
		errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETUNREACH):
		return true
	}
	return anyOf(err, "i/o timeout", "connection refused", "actively refused",
		"unreachable", "no such host", "network is down")
}

// isTLS — рукопожатие дошло до шифрования и там сломалось.
func isTLS(err error) bool {
	var (
		rec     *tls.RecordHeaderError
		verify  *tls.CertificateVerificationError
		alert   tls.AlertError
		auth    x509.UnknownAuthorityError
		host    x509.HostnameError
		invalid x509.CertificateInvalidError
	)
	switch {
	case errors.As(err, &rec), errors.As(err, &verify), errors.As(err, &alert),
		errors.As(err, &auth), errors.As(err, &host), errors.As(err, &invalid):
		return true
	}
	// REALITY собирает свои отказы строками и типа не оставляет.
	return anyOf(err, "tls:", "x509:", "reality", "certificate")
}

// isTorn — соединение с узлом установилось и оборвалось до того, как узел
// начал проксировать. Для §6.15 это HandshakeFailed.
func isTorn(err error) bool {
	switch {
	case errors.Is(err, io.EOF),
		errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.EPIPE):
		return true
	}
	return anyOf(err, "eof", "connection reset", "forcibly closed", "broken pipe", "handshake")
}

// anyOf — страховка к проверкам по типу: Xray собирает свои ошибки
// конкатенацией строк (common/errors.Error.Error), и исходный тип переживает
// не всякую обёртку. Основной путь — типы выше, сюда доходит остаток.
func anyOf(err error, subs ...string) bool {
	msg := strings.ToLower(err.Error())
	for _, s := range subs {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
