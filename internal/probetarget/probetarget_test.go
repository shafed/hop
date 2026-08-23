package probetarget

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time" //hop:realtime
)

// Стенд §8.1 живёт в настоящей сети, поэтому и время здесь настоящее: сокет
// нельзя двигать фейковыми часами. Каждое обращение к time помечено и объяснено
// на месте; в логику продукта это время не попадает.

// watchdog — предел ожидания в тесте. Не модельное время: он существует, чтобы
// красный тест падал за секунды, а не висел до таймаута go test.
const watchdog = 10 * time.Second

// get дёргает таргет обычным HTTP-клиентом без keep-alive: каждый запрос —
// новое соединение, иначе счётчик запросов проверял бы пул, а не таргет.
func get(t *testing.T, ctx context.Context, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("запрос не собрался: %v", err)
	}
	cli := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	defer cli.CloseIdleConnections()
	return cli.Do(req)
}

func newTarget(t *testing.T) *Target {
	t.Helper()
	tgt := New()
	t.Cleanup(tgt.Close)
	return tgt
}

// По умолчанию таргет — это generate_204 (§8.1), и счётчик запросов растёт на
// каждом обращении: без него тест не отличит «проба сходила» от «проба не
// состоялась, а зелёный пришёл откуда-то ещё» (A33).
func TestDefaultIsNoContent(t *testing.T) {
	tgt := newTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()

	for i := 1; i <= 3; i++ {
		resp, err := get(t, ctx, tgt.URL())
		if err != nil {
			t.Fatalf("запрос %d не прошёл: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("запрос %d: код %d, ждали 204", i, resp.StatusCode)
		}
		if got := tgt.Requests(); got != i {
			t.Fatalf("после %d запросов счётчик = %d", i, got)
		}
	}
}

// 403 — заблокированный тестовый домен (§5.4, T5/A30). Ключевое здесь: код
// меняется на лету, соединение при этом устанавливается как ни в чём не бывало.
func TestForbiddenMode(t *testing.T) {
	tgt := newTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()

	tgt.SetMode(StatusForbidden)
	resp, err := get(t, ctx, tgt.URL())
	if err != nil {
		t.Fatalf("403 обязан приехать ответом, а не ошибкой сети: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("код %d, ждали 403", resp.StatusCode)
	}

	// Обратно на 204 — тем же таргетом: сценарии Р3 переключают домен между
	// раундами, а не поднимают новый сервер.
	tgt.SetMode(StatusNoContent)
	resp, err = get(t, ctx, tgt.URL())
	if err != nil {
		t.Fatalf("после возврата в 204 запрос не прошёл: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("код %d, ждали 204", resp.StatusCode)
	}
	if got := tgt.Requests(); got != 2 {
		t.Fatalf("счётчик = %d, ждали 2", got)
	}
}

// Hang: запрос принят и посчитан, ответа нет. Именно этим он отличается от 403
// — неудача видна только по таймауту, и путь в коде клиента другой (§8.1).
func TestHangMode(t *testing.T) {
	tgt := newTarget(t)
	tgt.SetMode(Hang)

	// Короткий предел вместо watchdog: тест утверждает «ответа нет», и ждать
	// его отсутствия десять секунд незачем.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond) //hop:realtime
	defer cancel()

	if _, err := get(t, ctx, tgt.URL()); err == nil {
		t.Fatal("зависший таргет ответил, хотя обязан молчать")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ждали истечения контекста, получили %v", err)
	}
	if got := tgt.Requests(); got != 1 {
		t.Fatalf("счётчик = %d, ждали 1: запрос обязан считаться на входе, до ответа", got)
	}
}

// Close обязан вынимать зависший запрос, иначе стенд не закрывается, пока
// клиент не сдастся сам — а тест ждал бы Close.
func TestHangReleasedByClose(t *testing.T) {
	tgt := New()
	tgt.SetMode(Hang)

	errs := make(chan error, 1)
	go func() {
		resp, err := get(t, context.Background(), tgt.URL())
		if resp != nil {
			_ = resp.Body.Close()
		}
		errs <- err
	}()

	// Ждём, пока запрос дойдёт до обработчика: закрывать раньше — значит
	// проверять закрытие пустого сервера.
	waitRequests(t, tgt, 1)
	tgt.Close()

	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("после Close зависший запрос обязан оборваться, а не ответить 200")
		}
	case <-time.After(watchdog): //hop:realtime сторож, чтобы красный тест не висел
		t.Fatal("Close не вынул зависший запрос")
	}
}

// Slow: ответ 204 приходит, но не раньше заданной задержки. На этом стоят A31
// (минимальный rtt из успешных) и A35 (rtt меряет путь трафика).
func TestSlowMode(t *testing.T) {
	tgt := newTarget(t)
	const delay = 150 * time.Millisecond
	tgt.SetSlow(delay)

	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()

	start := time.Now() //hop:realtime замеряем настоящую сеть, фейковые часы её не двигают
	resp, err := get(t, ctx, tgt.URL())
	if err != nil {
		t.Fatalf("медленный таргет обязан ответить: %v", err)
	}
	_ = resp.Body.Close()
	elapsed := time.Since(start) //hop:realtime то же самое

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("код %d, ждали 204", resp.StatusCode)
	}
	if elapsed < delay {
		t.Fatalf("ответ пришёл за %v, задержка %v не сработала", elapsed, delay)
	}
	if got := tgt.Requests(); got != 1 {
		t.Fatalf("счётчик = %d, ждали 1", got)
	}
}

// Отмена контекста обязана прерывать и медленный ответ: иначе раунд проб
// растягивается на задержку самого тормозного URL (A32).
func TestSlowInterruptedByContext(t *testing.T) {
	tgt := newTarget(t)
	tgt.SetSlow(watchdog) // заведомо дольше, чем длится тест

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		waitRequests(t, tgt, 1)
		cancel()
	}()

	if _, err := get(t, ctx, tgt.URL()); err == nil {
		t.Fatal("отменённый запрос обязан вернуть ошибку")
	} else if !errors.Is(err, context.Canceled) {
		t.Fatalf("ждали отмену контекста, получили %v", err)
	}
}

// Режим переключается под параллельной нагрузкой: гонка режима — это то, что
// -race обязан ловить здесь, а не в тестах health.
func TestConcurrentModeSwitch(t *testing.T) {
	tgt := newTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			if i%2 == 0 {
				tgt.SetMode(StatusForbidden)
			} else {
				tgt.SetMode(StatusNoContent)
			}
		}
	}()
	for i := 0; i < 20; i++ {
		resp, err := get(t, ctx, tgt.URL())
		if err != nil {
			t.Fatalf("запрос %d не прошёл: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusForbidden {
			t.Fatalf("запрос %d: неожиданный код %d", i, resp.StatusCode)
		}
	}
	<-done
	if got := tgt.Requests(); got != 20 {
		t.Fatalf("счётчик = %d, ждали 20", got)
	}
}

// waitRequests ждёт, пока до таргета дойдёт n запросов. Опрос со сном, а не
// подписка: у стенда нет и не нужно наблюдаемого события «запрос принят», а
// сторож не даёт зависнуть.
func waitRequests(t *testing.T, tgt *Target, n int) {
	t.Helper()
	deadline := time.After(watchdog)               //hop:realtime сторож красного теста
	tick := time.NewTicker(200 * time.Microsecond) //hop:realtime опрос счётчика
	defer tick.Stop()
	for {
		if tgt.Requests() >= n {
			return
		}
		select {
		case <-deadline:
			t.Errorf("до таргета не дошло %d запросов (дошло %d)", n, tgt.Requests())
			return
		case <-tick.C:
		}
	}
}
