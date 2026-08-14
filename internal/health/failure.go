package health

import (
	"time" //hop:realtime
)

// FailureKind — замкнутое перечисление §6.15. Смертью узла считаются только
// отказы на пути к узлу и внутри него. Тип, а не строка: строка позволила бы
// расползтись классификации по коду, и однажды кто-нибудь тихо начал бы
// считать смертью упавший сайт.
type FailureKind int

const (
	// DialTimeout — соединение с узлом не установилось: таймаут, refused,
	// unreachable, неразрешимое имя.
	DialTimeout FailureKind = iota + 1
	// HandshakeFailed — разрыв во время рукопожатия с узлом.
	HandshakeFailed
	// TLSError — ошибка TLS или REALITY от узла.
	TLSError
	// ProxyRefused — узел принял соединение, но отказался проксировать.
	ProxyRefused
)

func (k FailureKind) String() string {
	switch k {
	case DialTimeout:
		return "dial-timeout"
	case HandshakeFailed:
		return "handshake-failed"
	case TLSError:
		return "tls-error"
	case ProxyRefused:
		return "proxy-refused"
	}
	return "unknown"
}

// Reporter — куда движок сообщает исход попытки. Вызывать ReportFailure
// разрешено ровно из одной функции классификации в internal/engine; за этим
// следит cmd/reportlint (D10). Любой другой call-site — это начало того самого
// расползания, против которого написан §6.15.
type Reporter interface {
	ReportFailure(nodeID string, kind FailureKind)
	ReportSuccess(nodeID string, rtt time.Duration)
}

// NopReporter — заглушка для путей, где health ещё не подключён.
type NopReporter struct{}

func (NopReporter) ReportFailure(string, FailureKind)   {}
func (NopReporter) ReportSuccess(string, time.Duration) {}
