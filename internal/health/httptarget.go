package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
)

// DialFunc — как health получает соединение через outbound конкретного узла.
//
// Диалер приходит снаружи, а не создаётся здесь, ровно из-за §6.7: проба
// обязана идти тем же путём, что и трафик, — через outbound проверяемого узла и
// тот же роутинг. Проба мимо outbound измеряет качество канала до провайдера, а
// не живость узла, и красит мёртвый узел зелёным. nodeID передаётся первым
// аргументом, потому что маршрут выбирается по узлу, а не по адресу (A33, A34).
type DialFunc func(ctx context.Context, nodeID, network, addr string) (net.Conn, error)

// ErrNoDial — HTTPTarget без диалера. Поломка сборки, а не смерть узла: без
// диалера проба ушла бы напрямую и нарушила §6.7, поэтому лучше отказ.
var ErrNoDial = errors.New("health: у HTTP-таргета нет диалера, проба пошла бы мимо outbound (§6.7)")

// StatusError — тестовый URL ответил, но не тем кодом. Отдельный тип, а не
// строка: вызывающему иногда нужно отличить «ответили не так» (узел жив, домен
// заблокирован посредником) от «не ответили вовсе».
//
// Код ответа в текст входит, URL — нет: §6.14 запрещает утечку секретов, а
// ошибка доезжает до `hop status` через NodeHealth.LastError, и токен в query
// тестового URL оказался бы в выводе.
type StatusError struct{ Code int }

func (e *StatusError) Error() string {
	return fmt.Sprintf("health: тестовый URL ответил %d, а не 2xx/3xx", e.Code)
}

// HTTPTarget — Target поверх настоящего HTTP через outbound узла (§5.4, §6.7).
// Один экземпляр — один тестовый URL; несколько URL сводит MultiProber (Р3).
type HTTPTarget struct {
	// URL — тестовый адрес, обычно отдающий 204 (`generate_204`).
	URL string
	// Dial — выход в сеть через outbound узла. Обязателен.
	Dial DialFunc
	// Clock — часы для замера латентности. Пусто — системные: rtt меряет
	// настоящий сетевой путь, и фейковые часы намеряли бы здесь ноль. Поле
	// существует ради тестов вокруг, а не ради подмены времени сети.
	Clock clock.Clock
	// Label — имя таргета для Name(). Пусто — берётся хост URL.
	Label string
	// Method — метод запроса. Пусто — GET: пробе нужен именно тот путь, каким
	// ходит браузер за `generate_204`, а HEAD посредники обрабатывают иначе.
	Method string
}

// Name реализует Target. Отдаёт хост без пути, query и userinfo: имя таргета
// попадает в диагностику, а секреты в неё попадать не должны (§6.14).
func (t *HTTPTarget) Name() string {
	if t.Label != "" {
		return t.Label
	}
	if u, err := url.Parse(t.URL); err == nil && u.Host != "" {
		return u.Host
	}
	return "http-target"
}

// Check реализует Target: один запрос через outbound узла nodeID.
//
// Успех — код 2xx или 3xx, всё остальное неудача. Почему так:
//   - 204 от `generate_204` — норма, и весь класс 2xx означает, что запрос
//     дошёл до настоящего сервера и вернулся;
//   - 3xx тоже доказывает сквозной путь: тестовые домены переезжают и отвечают
//     редиректом на канонический адрес, и считать это смертью узла значит
//     хоронить всю подписку из-за чужой смены конфигурации. Редирект при этом
//     **не** выполняется (см. CheckRedirect ниже): пройти по нему — значит
//     померить другой хост и потерять смысл замера;
//   - 403 обязан быть неудачей: это ровно сценарий T5/A30 — заблокированный
//     тестовый домен, где посредник отвечает вместо сервера. Соединение при
//     этом устанавливается прекрасно, поэтому единственный признак — код;
//   - 4xx и 5xx считаются неудачей по той же причине, что и 403: со стороны
//     пробы «сервер сломался» и «нас подменили» неразличимы, а страховка от
//     сломавшегося тестового домена — не мягкий критерий, а второй URL (§5.4,
//     Р3). Мягкий критерий страхует ровно тот случай, ради которого мульти-URL
//     и заведён, и заодно пропускает блокировку.
//
// Смертью узла по §6.15 неудачная проба сама по себе не является: она кладётся
// в окно проб, и решение принимает манагер по k-из-n.
func (t *HTTPTarget) Check(ctx context.Context, nodeID string) (time.Duration, error) {
	if t.Dial == nil {
		return 0, ErrNoDial
	}
	clk := t.Clock
	if clk == nil {
		clk = clock.System{}
	}
	method := t.Method
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, t.URL, nil)
	if err != nil {
		// URL в текст не попадает (§6.14): он приходит из подписки и вполне
		// может нести токен.
		return 0, errors.New("health: тестовый URL нельзя запросить")
	}

	// Транспорт создаётся на каждую пробу и уничтожается вместе с ней.
	// Keep-alive прячет мёртвый узел: соединение уже установлено и живёт в
	// пуле, поэтому проба меряет не установку соединения через outbound, а
	// только обратный путь по уже поднятому туннелю — узел, переставший
	// принимать новые соединения, остаётся зелёным до истечения idle-таймаута.
	// Ровно то, что обязано ловиться за один раунд (§5.4, У3).
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return t.Dial(ctx, nodeID, network, addr)
		},
		DisableKeepAlives: true,
		// Ни системного прокси, ни переменных окружения: проба обязана идти
		// через outbound узла, а не через то, что настроено на машине (§6.7).
		Proxy: nil,
		// Сжатие ответа замеряемому пути ничего не добавляет, а разбор тела
		// удлиняет.
		DisableCompression: true,
	}
	defer tr.CloseIdleConnections()

	cli := &http.Client{
		Transport: tr,
		// Редирект — это ответ, а не приглашение: см. обоснование выше.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := clk.Now()
	resp, err := cli.Do(req)
	rtt := clk.Now().Sub(start)
	if err != nil {
		return 0, probeError(err)
	}
	// Тело не читается: у 204 его нет, а у прочих кодов оно нам не интересно —
	// латентность уже измерена по заголовкам. Закрыть обязаны всё равно, иначе
	// соединение останется висеть до сборки мусора.
	_ = resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, &StatusError{Code: resp.StatusCode}
	}
	return rtt, nil
}

// probeError снимает с ошибки обёртку *url.Error. Обёртка тащит в текст полный
// URL запроса (§6.14: он может нести токен), а причина под ней — та же самая, и
// errors.Is по context.Canceled и context.DeadlineExceeded через неё проходит.
func probeError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		err = ue.Err
	}
	// Отмена и таймаут возвращаются как есть: манагер отличает Timeout от Fail
	// именно по ctx.Err(), и подмена типа сломала бы эту классификацию.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("health: проба не дошла: %w", err)
}
