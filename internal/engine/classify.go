package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/policy"
)

// Kind — вид отказа по §6.15, плюс KindNone для отказов, которые узел не
// убивают.
//
// Перечисление берётся из health, а не заводится своё: §6.15 требует одного
// замкнутого перечисления на продукт, а два — это два места, которые однажды
// разъедутся. Направление импорта при этом единственно возможное: health не
// знает про Xray (§3.4), engine про health знать может.
type Kind = health.FailureKind

// KindNone — отказ, который узел не убивает: ошибка вызывающего, закрытый
// движок, отменённый контекст, отказ целевого хоста.
const KindNone Kind = 0

// DialError — отказ исходящего соединения вместе с уже принятым вердиктом.
//
// Вердикт ставится здесь и больше нигде. §6.15: «иначе классификация
// расползётся по коду и однажды тихо начнёт считать смертью упавший сайт».
// Проверяет это TestReportFailureHasOneCallSite.
type DialError struct {
	NodeID string
	Kind   Kind
	Err    error
}

func (e *DialError) Error() string {
	if e.Kind == KindNone {
		return fmt.Sprintf("engine: узел %s: %v", e.NodeID, e.Err)
	}
	return fmt.Sprintf("engine: узел %s: %s: %v", e.NodeID, e.Kind, e.Err)
}

func (e *DialError) Unwrap() error { return e.Err }

// Fatal сообщает, убивает ли этот отказ узел (§6.15).
func (e *DialError) Fatal() bool { return e.Kind != KindNone }

// Report отдаёт вердикт в health. Единственное место в продукте, откуда
// вызывается ReportFailure: всё остальное обязано ходить сюда.
func (e *DialError) Report(h interface {
	ReportFailure(nodeID string, kind health.FailureKind)
}) {
	if h == nil || e.Kind == KindNone {
		return
	}
	h.ReportFailure(e.NodeID, e.Kind)
}

// classifyDial — та самая одна функция. Всё, что приходит из core.Dial,
// проходит через неё.
//
// Xray отдаёт ошибки текстом: `common/errors` склеивает цепочку строк, и
// типизированной причины в ней обычно нет. Поэтому классификация идёт в два
// прохода — сперва по типам, какие есть (syscall, net, context), потом по
// тексту. Второй проход — заведомо хрупкая часть, и он написан так, чтобы
// ошибаться в сторону KindNone: ложная смерть узла хуже пропущенной, потому
// что уводит пользователя с работающего узла (§6.3 держит порог k из n именно
// на этот случай).
func classifyDial(nodeID string, err error) *DialError {
	return &DialError{NodeID: nodeID, Kind: classify(err), Err: err}
}

func classify(err error) Kind {
	if err == nil {
		return KindNone
	}

	// error_classify выключена — смертью считается любой отказ, включая отказ
	// целевого хоста. Ровно та ошибка, от которой §6.15 и защищает: живой узел
	// умирает за чужой 502. Краснит T20.
	if !policy.ErrorClassify.On() {
		return health.DialTimeout
	}

	// Отмена сверху — не отказ узла. Пользователь закрыл приложение, истёк
	// таймаут пробы, свернулся netstack: узел тут ни при чём.
	if errors.Is(err, context.Canceled) {
		return KindNone
	}

	// Типизированные причины — там, где Xray их доносит.
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		// Узел отказал в соединении: он есть, но не слушает. Это отказ на
		// пути к узлу, а не отказ сайта, — сайт за узлом мы ещё не видели.
		return health.DialTimeout
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return health.HandshakeFailed
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return health.DialTimeout
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return health.DialTimeout
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return health.DialTimeout
	}

	// Текстовый проход. Ключи выбраны по тому, что Xray действительно пишет:
	// см. proxy/vless/outbound, transport/internet/tls и reality.
	s := strings.ToLower(err.Error())
	switch {
	case contains(s, "reality", "authentication failed"),
		contains(s, "reality", "verify"),
		strings.Contains(s, "tls: "),
		strings.Contains(s, "x509"),
		strings.Contains(s, "certificate"),
		strings.Contains(s, "handshake failure"):
		return health.TLSError

	case strings.Contains(s, "handshake"),
		strings.Contains(s, "unexpected eof"),
		errors.Is(err, io.ErrUnexpectedEOF):
		return health.HandshakeFailed

	case strings.Contains(s, "timeout"),
		strings.Contains(s, "timed out"),
		strings.Contains(s, "i/o timeout"),
		strings.Contains(s, "connection refused"),
		strings.Contains(s, "no route to host"),
		strings.Contains(s, "dial tcp"),
		strings.Contains(s, "failed to dial"):
		return health.DialTimeout

	case strings.Contains(s, "rejected"),
		strings.Contains(s, "not enough data"),
		strings.Contains(s, "invalid response"),
		strings.Contains(s, "unexpected response"),
		strings.Contains(s, "invalid user"),
		strings.Contains(s, "not found in userlist"):
		return health.ProxyRefused
	}

	// Не опознали — не убиваем. Неизвестная ошибка, посчитанная смертью,
	// уводит пользователя с работающего узла; неизвестная ошибка, посчитанная
	// пустяком, стоит одной неудачной пробы (§6.3).
	return KindNone
}

func contains(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
