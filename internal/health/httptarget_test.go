package health

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/probetarget"
)

// Здесь стенд не L1, а настоящий HTTP через локальный сокет (§8.1,
// «Управляемый пробе-таргет»): проверяется ровно то, что фейком не проверишь —
// разбор кода ответа, отмена контекста и факт похода через переданный диалер
// (§6.7). Время поэтому настоящее; каждое обращение к нему помечено.

// countingDialer — диалер, считающий походы и запоминающий, за какой узел его
// дёрнули. Без него §6.7 на L1 недоказуем: «тот же путь» — это утверждение об
// аргументе, и проверяется оно только тем, что аргумент доехал (A33).
type countingDialer struct {
	mu      sync.Mutex
	calls   int
	nodeIDs []string
	addrs   []string
}

func (d *countingDialer) dial(ctx context.Context, nodeID, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.calls++
	d.nodeIDs = append(d.nodeIDs, nodeID)
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	var std net.Dialer
	return std.DialContext(ctx, network, addr)
}

func (d *countingDialer) snapshot() (int, []string, []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls, append([]string(nil), d.nodeIDs...), append([]string(nil), d.addrs...)
}

// httpStand поднимает управляемый таргет и HTTPTarget поверх него.
func httpStand(t *testing.T) (*probetarget.Target, *HTTPTarget, *countingDialer) {
	t.Helper()
	tgt := probetarget.New()
	t.Cleanup(tgt.Close)
	d := &countingDialer{}
	return tgt, &HTTPTarget{URL: tgt.URL(), Dial: d.dial}, d
}

// 204 — успех, и проба обязана дойти до таргета через переданный диалер именно
// за тот узел, который проверяется (§6.7, A33).
func TestHTTPTargetSuccessGoesThroughDial(t *testing.T) {
	tgt, ht, d := httpStand(t)
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()

	rtt, err := ht.Check(ctx, "node-X")
	if err != nil {
		t.Fatalf("204 обязан быть успехом: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("rtt = %v, обязан быть положительным", rtt)
	}
	if got := tgt.Requests(); got != 1 {
		t.Fatalf("до таргета дошло %d запросов, ждали 1", got)
	}
	calls, ids, addrs := d.snapshot()
	if calls != 1 {
		t.Fatalf("диалер дёрнут %d раз, ждали 1", calls)
	}
	if ids[0] != "node-X" {
		t.Fatalf("диалер получил узел %q, ждали node-X: проба обязана идти через outbound проверяемого узла", ids[0])
	}
	if addrs[0] != tgt.Addr() {
		t.Fatalf("диалер получил адрес %q, ждали %q", addrs[0], tgt.Addr())
	}
}

// Соединения между пробами не переиспользуются: иначе живой пул прячет узел,
// переставший принимать новые соединения, и проба меряет не тот путь.
func TestHTTPTargetDoesNotReuseConnections(t *testing.T) {
	_, ht, d := httpStand(t)
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()

	for i := 0; i < 3; i++ {
		if _, err := ht.Check(ctx, "A"); err != nil {
			t.Fatalf("проба %d: %v", i, err)
		}
	}
	if calls, _, _ := d.snapshot(); calls != 3 {
		t.Fatalf("диалер дёрнут %d раз на 3 пробы: соединение переиспользуется, узел проверяется не целиком", calls)
	}
}

// 403 — неудача. Это сценарий T5/A30: тестовый домен заблокирован, соединение
// при этом устанавливается, и единственный признак — код ответа.
func TestHTTPTargetForbiddenIsFailure(t *testing.T) {
	tgt, ht, _ := httpStand(t)
	tgt.SetMode(probetarget.StatusForbidden)
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()

	rtt, err := ht.Check(ctx, "A")
	if err == nil {
		t.Fatal("403 обязан быть неудачей, иначе заблокированный домен красит узлы зелёными")
	}
	if rtt != 0 {
		t.Fatalf("у неудачи rtt = %v, ждали 0", rtt)
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 403 {
		t.Fatalf("ждали StatusError{403}, получили %#v (%v)", err, err)
	}
	if got := tgt.Requests(); got != 1 {
		t.Fatalf("до таргета дошло %d запросов, ждали 1", got)
	}
}

// Отмена контекста обязана прерывать зависшую пробу: на этом стоит A32 —
// раунд не растягивается на таймаут молчащего URL, — и на этом же стоит
// таймаут пробы в манагере, который отменяет ctx по своим часам.
func TestHTTPTargetContextCancelsHang(t *testing.T) {
	tgt, ht, _ := httpStand(t)
	tgt.SetMode(probetarget.Hang)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := ht.Check(ctx, "A")
		done <- err
	}()

	waitProbeArrived(t, tgt)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("зависшая проба вернула успех")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ждали context.Canceled, получили %v", err)
		}
	case <-time.After(watchdog): //hop:realtime сторож: красный тест обязан падать, а не висеть
		t.Fatal("отмена контекста не прервала пробу")
	}
}

// Латентность меряется, а не выдумывается: задержка таргета обязана быть видна
// в rtt (A31, A35 — «проба измеряет путь трафика»).
func TestHTTPTargetMeasuresLatency(t *testing.T) {
	tgt, ht, _ := httpStand(t)
	const delay = 150 * time.Millisecond
	tgt.SetSlow(delay)
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()

	rtt, err := ht.Check(ctx, "A")
	if err != nil {
		t.Fatalf("медленный, но живой таргет обязан быть успехом: %v", err)
	}
	if rtt < delay {
		t.Fatalf("rtt = %v при задержке %v: замер идёт мимо ответа", rtt, delay)
	}
}

// Диалера нет — отказ, а не поход напрямую: проба мимо outbound меряет канал до
// провайдера и красит мёртвый узел зелёным (§6.7).
func TestHTTPTargetRequiresDial(t *testing.T) {
	tgt := probetarget.New()
	t.Cleanup(tgt.Close)
	ht := &HTTPTarget{URL: tgt.URL()}

	if _, err := ht.Check(context.Background(), "A"); !errors.Is(err, ErrNoDial) {
		t.Fatalf("ждали ErrNoDial, получили %v", err)
	}
	if got := tgt.Requests(); got != 0 {
		t.Fatalf("без диалера запрос всё же ушёл (%d)", got)
	}
}

// Имя таргета не тащит путь и query: оно попадает в диагностику, а там могут
// оказаться токены (§6.14).
func TestHTTPTargetNameHidesSecrets(t *testing.T) {
	ht := &HTTPTarget{URL: "https://example.org/generate_204?token=SECRET"}
	if got := ht.Name(); got != "example.org" {
		t.Fatalf("Name() = %q, ждали example.org без пути и query", got)
	}
	labelled := &HTTPTarget{URL: "https://example.org/x?token=SECRET", Label: "чек-1"}
	if got := labelled.Name(); got != "чек-1" {
		t.Fatalf("Name() = %q, ждали заданную метку", got)
	}
}

// Ошибка неудачной пробы не тащит URL: она доезжает до `hop status` через
// NodeHealth.LastError (§6.14).
func TestHTTPTargetErrorHidesURL(t *testing.T) {
	// Заведомо мёртвый адрес: диалер отказывает, не выходя в сеть.
	ht := &HTTPTarget{
		URL: "http://example.org/generate_204?token=SECRET",
		Dial: func(context.Context, string, string, string) (net.Conn, error) {
			return nil, errors.New("отказ исходящего")
		},
	}
	_, err := ht.Check(context.Background(), "A")
	if err == nil {
		t.Fatal("отказ диалера обязан быть неудачей")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("URL с секретом утёк в текст ошибки: %v", err)
	}
	if !strings.Contains(err.Error(), "отказ исходящего") {
		t.Fatalf("причина потерялась: %v", err)
	}
}

// MultiProber поверх настоящего HTTP сводит URL по Р3: один заблокирован,
// второй жив — узел жив (T5). Проверяется здесь, а не в multi_test, потому что
// только здесь «заблокирован» означает настоящий 403 от настоящего сервера.
func TestHTTPTargetsUnderMultiProber(t *testing.T) {
	blocked, htBlocked, _ := httpStand(t)
	alive, htAlive, _ := httpStand(t)
	blocked.SetMode(probetarget.StatusForbidden)

	p := &MultiProber{Targets: []Target{htBlocked, htAlive}}
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()

	if res := p.Probe(ctx, "A"); res.Err != nil {
		t.Fatalf("узел обязан быть жив: заблокирован только один URL (T5): %v", res.Err)
	}

	// А когда 403 отдают все — узел мёртв. Без этого проверка проходит и в
	// реализации, где успех ставится безусловно (A30).
	alive.SetMode(probetarget.StatusForbidden)
	if res := p.Probe(ctx, "A"); res.Err == nil {
		t.Fatal("все URL отдают 403, а узел жив — мульти-URL не означает «всегда жив» (A30)")
	}
}

// waitProbeArrived ждёт, пока проба дойдёт до таргета. Опрос со сторожем:
// двигать сценарий раньше прихода запроса — значит проверять не тот момент.
func waitProbeArrived(t *testing.T, tgt *probetarget.Target) {
	t.Helper()
	deadline := time.After(watchdog)               //hop:realtime сторож красного теста
	tick := time.NewTicker(200 * time.Microsecond) //hop:realtime опрос счётчика
	defer tick.Stop()
	for {
		if tgt.Requests() > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("проба не дошла до таргета")
		case <-tick.C:
		}
	}
}
