package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	xerrors "github.com/xtls/xray-core/common/errors"

	"github.com/shafed/hop/internal/health"
)

// Перечисление §6.15 замкнуто: у каждого отказа узла ровно один вид, и
// «прочее» из него не выпадает. Ошибки взяты в той форме, в какой их приносит
// Xray, — обёрнутыми в common/errors и склеенными в строку.
func TestClassifyEnumeratesNodeFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want health.FailureKind
	}{
		{"до узла не достучались", dialErr(syscall.ECONNREFUSED), health.DialTimeout},
		{"узел не ответил вовремя", dialErr(os.ErrDeadlineExceeded), health.DialTimeout},
		{"имя узла не разрешилось", &net.DNSError{Err: "no such host", Name: "node.example"}, health.DialTimeout},
		{"TLS не сошёлся", &tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, health.TLSError},
		{"REALITY отказал", errors.New("REALITY: processed invalid connection"), health.TLSError},
		{"рукопожатие оборвалось", io.ErrUnexpectedEOF, health.HandshakeFailed},
		{"узел сбросил соединение", syscall.ECONNRESET, health.HandshakeFailed},
		{"узел не стал проксировать", errors.New("invalid user"), health.ProxyRefused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Так ошибка и приезжает: узел сообщил о своём провале, Xray
			// обернул её своим типом по дороге.
			wrapped := &nodeFault{err: xerrors.New("failed to process outbound traffic").Base(tc.err)}
			kind, dead := classify(wrapped)
			if !dead {
				t.Fatalf("отказ узла %v не признан смертью", tc.err)
			}
			if kind != tc.want {
				t.Fatalf("вид %v, ожидался %v", kind, tc.want)
			}
		})
	}
}

// Обратная половина §6.15: всё, о чём узел не сообщал, приходит с пути к
// целевому хосту и узел не убивает.
func TestClassifySpareSiteFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"поток кончился", io.EOF},
		{"труба закрыта", io.ErrClosedPipe},
		{"сайт отказал", dialErr(syscall.ECONNREFUSED)},
		{"имя сайта не разрешилось", &net.DNSError{Err: "no such host", Name: "site.example"}},
		{"локальная отмена", context.Canceled},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, dead := classify(tc.err); dead {
				t.Fatalf("%v засчитан смертью узла", tc.err)
			}
		})
	}
	if _, dead := classify(nil); dead {
		t.Fatal("отсутствие ошибки засчитано смертью узла")
	}
}

// report — единственный вход в health, и он обязан звать ReportFailure только
// на смерти узла, а ReportSuccess — только на успехе.
func TestReportPassesOnlyNodeDeaths(t *testing.T) {
	rec := &recorder{}
	e := &Engine{rep: rec}

	if err := e.report("n1", nil, 42); err != nil {
		t.Fatalf("успех вернул ошибку: %v", err)
	}
	if rec.successes() != 1 {
		t.Fatalf("успехов %d, ожидался 1", rec.successes())
	}

	site := io.EOF
	if err := e.report("n1", site, 0); !errors.Is(err, site) {
		t.Fatalf("report подменил ошибку: %v", err)
	}
	if got := rec.failures(); len(got) != 0 {
		t.Fatalf("отказ сайта дошёл до health: %v", got)
	}

	e.report("n1", &nodeFault{err: dialErr(syscall.ECONNREFUSED)}, 0)
	if got := rec.failures(); len(got) != 1 || got[0] != health.DialTimeout {
		t.Fatalf("отказ узла в health: %v", got)
	}
}

func dialErr(err error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: err}
}
