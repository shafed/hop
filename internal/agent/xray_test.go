package agent

import (
	"net/netip"
	"testing"
	"time"

	"github.com/shafed/hop/internal/engine"
)

// Шаг 4 регистра: дренаж прежнего инстанса Xray (У4, Р32).

// waitFor ждёт условия и падает, а не виснет.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second) //hop:realtime
	for time.Now().Before(deadline) {           //hop:realtime
		if cond() {
			return
		}
		time.Sleep(time.Millisecond) //hop:realtime
	}
	t.Fatalf("не дождались: %s", what)
}

// TestW18SubscriptionUpdateKeepsConnection — W18 (он же T30 из §8.3):
// обновление подписки не рвёт живое соединение.
//
// Охраняет xray_drain. С выключенной политикой прежний инстанс закрывается
// сразу, и соединение через него умирает — а §5.5 обещает рвать соединения
// только по причине dead, каковой обновление подписки не является.
func TestW18SubscriptionUpdateKeepsConnection(t *testing.T) {
	r := newRig(t, "a")
	r.start()

	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	d := newDialer(r.hm, r.a.engine)
	conn, err := d.DialTCP(netip.MustParseAddrPort("93.184.216.34:443"))
	if err != nil {
		t.Fatalf("дозвон через первый инстанс: %v", err)
	}
	defer conn.Close()

	first := r.xrays.at(0)
	if first == nil {
		t.Fatal("первый инстанс не поднимался")
	}

	// Подписка обновилась: узел b добавился, a остался.
	r.seedStore("g1", "a", "b")
	if err := r.a.ReloadNodes(); err != nil {
		t.Fatalf("ReloadNodes: %v", err)
	}
	r.a.WaitRebuild(2)

	// Смотрим на соединение, а не на флаг: §5.5 обещает именно его, и к
	// возврату из ReloadNodes судьба прежнего инстанса уже решена.
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil { //hop:realtime
		t.Fatalf("дедлайн записи: %v", err)
	}
	if _, err := conn.Write([]byte("живо?")); err != nil {
		t.Fatalf("соединение через прежний инстанс оборвалось на обновлении "+
			"подписки, хотя это не причина dead (§5.5): %v", err)
	}
	if first.closed.Load() {
		t.Fatal("прежний инстанс закрыт, хотя через него ещё говорят")
	}
}

// TestW20DrainEndsWithLastConnection — W20: дренаж кончается, как только
// закрылось последнее соединение, а не по истечении потолка.
//
// Часы при этом не двигаются вовсе: если бы дренаж держался на одном таймере,
// инстанс остался бы жив и тест покраснел бы.
func TestW20DrainEndsWithLastConnection(t *testing.T) {
	r := newRig(t, "a")
	r.start()

	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	d := newDialer(r.hm, r.a.engine)
	conn, err := d.DialTCP(netip.MustParseAddrPort("93.184.216.34:443"))
	if err != nil {
		t.Fatalf("дозвон: %v", err)
	}
	first := r.xrays.at(0)

	r.seedStore("g1", "a", "b")
	if err := r.a.ReloadNodes(); err != nil {
		t.Fatalf("ReloadNodes: %v", err)
	}
	r.a.WaitRebuild(2)

	if first.closed.Load() {
		t.Fatal("инстанс закрыт до закрытия соединения")
	}
	// Часы не двигаются: если бы дренаж держался на одном таймере, инстанс
	// остался бы жив и следующее ожидание не дождалось бы.
	_ = conn.Close()
	waitFor(t, "дренаж кончился по последнему соединению",
		func() bool { return first.closed.Load() })
	waitFor(t, "инстанс убран из списка дренируемых",
		func() bool { return r.a.engine.liveInstances() == 1 })
}

// TestW21DrainStopsAtCeiling — W21: соединение, не закрывшееся за потолок
// §5.8, обрывается вместе с инстансом.
func TestW21DrainStopsAtCeiling(t *testing.T) {
	r := newRig(t, "a")
	r.start()

	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	d := newDialer(r.hm, r.a.engine)
	conn, err := d.DialTCP(netip.MustParseAddrPort("93.184.216.34:443"))
	if err != nil {
		t.Fatalf("дозвон: %v", err)
	}
	defer conn.Close()
	first := r.xrays.at(0)

	r.seedStore("g1", "a", "b")
	if err := r.a.ReloadNodes(); err != nil {
		t.Fatalf("ReloadNodes: %v", err)
	}
	r.a.WaitRebuild(2)

	if first.closed.Load() {
		t.Fatal("инстанс закрыт до потолка и без закрытия соединения")
	}
	// Соединение никто не закрывает — кончиться дренаж обязан по времени.
	r.clk.Advance(drainTimeout)
	waitFor(t, "дренаж кончился по потолку",
		func() bool { return first.closed.Load() })
}

// TestW22UnchangedNodeSetDoesNotRebuild — W22: обновление, не изменившее набор
// узлов, инстанс не пересобирает.
//
// Автообновление подписки идёт по таймеру; пересборка на каждом тике —
// самый дешёвый способ незаметно нарушить §5.5, ничего при этом не сломав.
func TestW22UnchangedNodeSetDoesNotRebuild(t *testing.T) {
	r := newRig(t, "a", "b")
	r.start()

	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	before := r.a.Snapshot().Rebuilds

	// Тот же состав, тот же порядок, ещё раз.
	r.seedStore("g1", "a", "b")
	if err := r.a.ReloadNodes(); err != nil {
		t.Fatalf("ReloadNodes: %v", err)
	}

	if after := r.a.Snapshot().Rebuilds; after != before {
		t.Fatalf("инстанс пересобран на неизменившемся наборе: было %d, стало %d",
			before, after)
	}
	if n := r.xrays.count(); n != 1 {
		t.Fatalf("поднято инстансов: %d, ожидался один", n)
	}
}

// TestW22OrderChangeDoesNotRebuild — та же W22 с другой стороны: перестановка
// узлов — дело node_order (Р8 регистра стора), а не движка.
func TestW22OrderChangeDoesNotRebuild(t *testing.T) {
	r := newRig(t, "a", "b")
	r.start()

	before := r.a.Snapshot().Rebuilds
	r.seedStore("g1", "b", "a")
	if err := r.a.ReloadNodes(); err != nil {
		t.Fatalf("ReloadNodes: %v", err)
	}

	if after := r.a.Snapshot().Rebuilds; after != before {
		t.Fatalf("перестановка узлов пересобрала инстанс: было %d, стало %d",
			before, after)
	}
}

// TestW23AtMostTwoInstances — W23: два обновления подряд не копят инстансы.
func TestW23AtMostTwoInstances(t *testing.T) {
	r := newRig(t, "a")
	r.start()

	if err := r.a.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	d := newDialer(r.hm, r.a.engine)
	c1, err := d.DialTCP(netip.MustParseAddrPort("93.184.216.34:443"))
	if err != nil {
		t.Fatalf("дозвон: %v", err)
	}
	defer c1.Close()

	r.seedStore("g1", "a", "b")
	if err := r.a.ReloadNodes(); err != nil {
		t.Fatalf("ReloadNodes 1: %v", err)
	}
	r.a.WaitRebuild(2)

	if n := r.a.engine.liveInstances(); n > 2 {
		t.Fatalf("живых инстансов %d после первого обновления", n)
	}

	r.seedStore("g1", "a", "b", "c")
	if err := r.a.ReloadNodes(); err != nil {
		t.Fatalf("ReloadNodes 2: %v", err)
	}
	r.a.WaitRebuild(3)

	// Второй прежний инстанс соединений не держал, поэтому его дренаж кончается
	// сразу; первый держит c1 и потому жив. Больше двух одновременно быть не
	// должно ни в какой момент после того, как дренаж отработал.
	waitFor(t, "инстансы не копятся",
		func() bool { return r.a.engine.liveInstances() <= 2 })
}

// TestFingerprintIgnoresOrdering — отпечаток набора не зависит ни от порядка
// узлов, ни от порядка ключей в params: обе перестановки законны и пересборкой
// быть не должны. Это и есть механизм W22.
func TestFingerprintIgnoresOrdering(t *testing.T) {
	a := engine.Node{
		ID: "a", Protocol: "vless", Server: "a.example", Port: 443,
		Transport: "raw", Security: "none",
		Params: map[string]string{"uuid": "u-a", "sni": "a.example", "fp": "chrome"},
	}
	b := engine.Node{
		ID: "b", Protocol: "vless", Server: "b.example", Port: 443,
		Transport: "raw", Security: "none",
		Params: map[string]string{"uuid": "u-b"},
	}

	if fingerprint([]engine.Node{a, b}) != fingerprint([]engine.Node{b, a}) {
		t.Fatal("отпечаток зависит от порядка узлов")
	}

	// Та же карта, собранная в другом порядке вставки: в Go порядок обхода
	// карты не определён, и отпечаток обязан это переживать.
	a2 := a
	a2.Params = map[string]string{"fp": "chrome", "sni": "a.example", "uuid": "u-a"}
	if fingerprint([]engine.Node{a}) != fingerprint([]engine.Node{a2}) {
		t.Fatal("отпечаток зависит от порядка ключей в params")
	}

	// А вот значение параметра менять обязано: другой ключ доступа — другой
	// outbound, и пересобрать его надо.
	a3 := a
	a3.Params = map[string]string{"uuid": "u-other", "sni": "a.example", "fp": "chrome"}
	if fingerprint([]engine.Node{a}) == fingerprint([]engine.Node{a3}) {
		t.Fatal("отпечаток не заметил смены uuid")
	}
}
