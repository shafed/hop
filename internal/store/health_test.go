// Живость на диске — docs/verification-store.md §5.6, шаг 6 регистра. S35–S39.
// Уровень L1: диск здесь — t.TempDir(), время — фейковые часы.
package store

import (
	"strings"
	"testing"
	"time" //hop:realtime — длительности модельного времени и один замер, что тест не стоит по-настоящему

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/health"
)

// newTimedStore — стор вместе с его часами: дебаунс идёт по ним, и проверять
// его иначе как прокруткой модельного времени нельзя (требование 4, §2
// регистра).
func newTimedStore(t *testing.T) (*Store, string, *clock.Fake) {
	t.Helper()
	dir := t.TempDir()
	clk := clock.NewFake(testEpoch)
	s, err := Open(dir, clk)
	if err != nil {
		t.Fatalf("стор не открылся: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir, clk
}

// alive — живость проверенного узла: срез плюс окно, traffic_failures и
// last_error, то есть ровно то, что health отдаёт наружу.
func alive(id string, rtt time.Duration, at time.Time) health.NodeHealth {
	return health.NodeHealth{
		NodeID:          id,
		State:           health.Alive,
		RTT:             rtt,
		Window:          []health.Outcome{health.Fail, health.OK, health.OK},
		TrafficFailures: 2,
		LastProbeAt:     at,
		LastError:       "dial timeout к a.example:443",
	}
}

// TestS35SliceSurvivesRestart — S35: Close, затем Open — state, rtt и
// last_probe_at восстановлены.
func TestS35SliceSurvivesRestart(t *testing.T) {
	s, dir, _ := newTimedStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))

	probedAt := testEpoch.Add(17 * time.Second)
	s.PutHealth([]health.NodeHealth{alive("n1", 42*time.Millisecond, probedAt)})
	if err := s.Close(); err != nil {
		t.Fatalf("закрытие не прошло: %v", err)
	}

	s2 := openStore(t, dir)
	h, ok := s2.Health("n1")
	if !ok {
		t.Fatal("живость не пережила рестарт, хотя §2 обещает срез")
	}
	if h.State != health.Alive {
		t.Errorf("состояние %v, ожидалось alive", h.State)
	}
	if h.RTT != 42*time.Millisecond {
		t.Errorf("rtt %v, ожидалось 42ms", h.RTT)
	}
	if !h.LastProbeAt.Equal(probedAt) {
		t.Errorf("last_probe_at %v, ожидалось %v", h.LastProbeAt, probedAt)
	}
	if _, ok := s2.Health("нет такого узла"); ok {
		t.Error("живость несуществующего узла нашлась")
	}
}

// TestS36RestoredHealthHasNoWindow — S36: окно, traffic_failures и last_error
// рестарт не переживают (§2). Окно, пролежавшее выключенным час, воскресило бы
// узел по §6.3 из записей, которым час.
//
// Краснеет без политики health_slice.
func TestS36RestoredHealthHasNoWindow(t *testing.T) {
	s, dir, _ := newTimedStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))

	s.PutHealth([]health.NodeHealth{alive("n1", 42*time.Millisecond, testEpoch)})
	if err := s.Close(); err != nil {
		t.Fatalf("закрытие не прошло: %v", err)
	}

	// Ни в файле, ни в восстановленной живости: файл — потому что записанное
	// однажды прочтёт и следующая версия.
	if raw := string(readRaw(t, dir, healthFile)); strings.Contains(raw, "window") ||
		strings.Contains(raw, "traffic_failures") || strings.Contains(raw, "last_error") {
		t.Errorf("окно уехало на диск, хотя §2 пишет только срез:\n%s", raw)
	}

	s2 := openStore(t, dir)
	h, ok := s2.Health("n1")
	if !ok {
		t.Fatal("живость не пережила рестарт")
	}
	if len(h.Window) != 0 {
		t.Errorf("окно восстановлено (%v), а после паузы оно врёт (§2)", h.Window)
	}
	if h.TrafficFailures != 0 {
		t.Errorf("traffic_failures восстановлен (%d), а он про «прямо сейчас» (§2)", h.TrafficFailures)
	}
	if h.LastError != "" {
		t.Errorf("last_error восстановлен (%q), а он про «прямо сейчас» (§2)", h.LastError)
	}
}

// TestS37RestoredAliveNodeCarriesNoProbe — S37: узел, восстановленный в
// состоянии alive, не несёт ни одного свидетельства пробы.
//
// **Это половина шва, а не весь S37.** Регистр требует, чтобы восстановленный
// alive не считался проверенным и стартовый бюджет §5.6 шёл заново. Считает
// узлы проверенными health: nodeState.probed выставляется только внутри record,
// то есть ровно тогда, когда в окно кладётся исход. Здесь проверяется сторона
// стора — что после рестарта окна нет, traffic_failures нулевой и на диске нет
// поля, способного пронести признак пробы. Вторая половина — что health по
// пустому окну действительно держит probed == false — проверяется там, где стор
// соединяется с живостью, то есть на этапе 8: API засева состояния у
// health.Manager сейчас нет вовсе (Config.Nodes принимает {ID, Supported}), и
// изобразить сквозную проверку можно было бы только дописав его.
//
// Краснеет без политики health_slice.
func TestS37RestoredAliveNodeCarriesNoProbe(t *testing.T) {
	s, dir, _ := newTimedStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))

	s.PutHealth([]health.NodeHealth{alive("n1", 42*time.Millisecond, testEpoch)})
	if err := s.Close(); err != nil {
		t.Fatalf("закрытие не прошло: %v", err)
	}

	s2 := openStore(t, dir)
	h, ok := s2.Health("n1")
	if !ok {
		t.Fatal("живость не пережила рестарт")
	}
	// Состояние — да: на него опирается первый выбор после рестарта (§2).
	if h.State != health.Alive {
		t.Fatalf("состояние %v, а срез обязан пережить рестарт", h.State)
	}
	// Свидетельство пробы — нет. Единственное, что делает узел проверенным в
	// health, — исход, положенный в окно (nodeState.record); пустое окно
	// означает probed == false и стартовый бюджет §5.6 заново.
	if len(h.Window) != 0 || h.TrafficFailures != 0 {
		t.Errorf("восстановленный alive несёт свидетельство пробы: окно %v, traffic_failures %d",
			h.Window, h.TrafficFailures)
	}

	// И пронести его нечем: в файле нет поля, которое дошло бы до health как
	// «этот узел уже пробовали».
	if raw := string(readRaw(t, dir, healthFile)); strings.Contains(raw, "window") {
		t.Errorf("на диске есть окно — восстановленный узел выдаст себя за проверенный:\n%s", raw)
	}
}

// TestS38DebounceCollapsesUpdates — S38: десять обновлений живости за тридцать
// секунд модельного времени дают одну запись на диск.
//
// Вторая половина проверки — что после тридцати секунд запись всё-таки
// случается. Без неё дебаунс на настоящем времени прошёл бы её насквозь: десять
// вызовов подряд укладываются в миллисекунды, и «записей одна» вышло бы само
// собой.
func TestS38DebounceCollapsesUpdates(t *testing.T) {
	started := time.Now() //hop:realtime — тест не имеет права стоять тридцать секунд

	s, _, clk := newTimedStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))
	// Отсчёт от того, что уже записал Open: пустые файлы он создаёт сразу, и
	// эта запись к дебаунсу отношения не имеет.
	base := s.w.writes(healthFile)

	// Каждое обновление отличается от предыдущего: дебаунс проверяется на
	// изменившейся живости, а не на повторе, который и так никого не пачкает.
	for i := range 10 {
		if i > 0 {
			clk.Advance(3 * time.Second)
		}
		s.PutHealth([]health.NodeHealth{alive("n1", time.Duration(40+i)*time.Millisecond, clk.Now())})
	}
	if got := s.w.writes(healthFile) - base; got != 1 {
		t.Errorf("записей живости %d, а за тридцать секунд дебаунс §2 разрешает одну", got)
	}

	// Тридцать секунд прошли — следующее обновление идёт на диск.
	clk.Advance(4 * time.Second)
	s.PutHealth([]health.NodeHealth{alive("n1", 99*time.Millisecond, clk.Now())})
	if got := s.w.writes(healthFile) - base; got != 2 {
		t.Errorf("записей живости %d, а после истечения дебаунса ожидалась вторая", got)
	}

	if elapsed := time.Since(started); elapsed > 5*time.Second { //hop:realtime — см. выше
		t.Errorf("проверка заняла %v настоящего времени: дебаунс идёт не по часам стора", elapsed)
	}
}

// TestS39CloseWritesBeforeDebounceExpires — S39: обновление живости, затем
// Close до истечения дебаунса — запись состоялась. Тридцать секунд — это про
// частоту, а не про право потерять последнее состояние (§4 регистра).
func TestS39CloseWritesBeforeDebounceExpires(t *testing.T) {
	s, dir, clk := newTimedStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))

	s.PutHealth([]health.NodeHealth{alive("n1", 42*time.Millisecond, clk.Now())})
	writes := s.w.writes(healthFile)

	// Второе обновление приходит внутри окна дебаунса и на диск само не идёт.
	clk.Advance(5 * time.Second)
	s.PutHealth([]health.NodeHealth{alive("n1", 77*time.Millisecond, clk.Now())})
	if got := s.w.writes(healthFile); got != writes {
		t.Fatalf("записей %d при %d до обновления — дебаунса нет вовсе", got, writes)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("закрытие не прошло: %v", err)
	}
	if got := s.w.writes(healthFile); got != writes+1 {
		t.Fatalf("Close не записал живость: записей %d, было %d", got, writes)
	}

	s2 := openStore(t, dir)
	h, ok := s2.Health("n1")
	if !ok {
		t.Fatal("живость не пережила рестарт")
	}
	if h.RTT != 77*time.Millisecond {
		t.Errorf("на диске rtt %v, а последним было 77ms — Close потерял состояние", h.RTT)
	}
}

// TestPutHealthIgnoresUnknownNodes — живость узла, которого в сторе нет, не
// записывается. Та же причина, по которой Apply удаляет живость ушедших: id
// выдаются заново, и переживший рестарт мусор однажды приклеится к чужому узлу.
func TestPutHealthIgnoresUnknownNodes(t *testing.T) {
	s, _, _ := newTimedStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))

	s.PutHealth([]health.NodeHealth{
		alive("n1", 42*time.Millisecond, testEpoch),
		alive("удалённый", 10*time.Millisecond, testEpoch),
		{NodeID: "", State: health.Alive},
	})
	if _, ok := s.Health("удалённый"); ok {
		t.Error("живость узла, которого в сторе нет, записана")
	}
	if _, ok := s.Health("n1"); !ok {
		t.Error("живость известного узла потеряна заодно с чужой")
	}
}

// TestPutHealthWithoutChangesDoesNotWrite — повтор той же живости не переписывает
// файл: та же бережность, которой требует S8 от обновления без изменений.
func TestPutHealthWithoutChangesDoesNotWrite(t *testing.T) {
	s, _, clk := newTimedStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))

	h := alive("n1", 42*time.Millisecond, testEpoch)
	s.PutHealth([]health.NodeHealth{h})
	writes := s.w.writes(healthFile)

	clk.Advance(time.Hour) // дебаунс давно истёк, дело только в содержимом
	s.PutHealth([]health.NodeHealth{h})
	if got := s.w.writes(healthFile); got != writes {
		t.Errorf("записей %d при %d: неизменившаяся живость переписала файл", got, writes)
	}
}

// TestHealthIsACopy — отданная живость не разделяет окно со стором.
func TestHealthIsACopy(t *testing.T) {
	s, _, _ := newTimedStore(t)
	seed(t, s, Group{ID: "g", Name: "подписка"}, node("n1", "g", "a.example"))
	s.PutHealth([]health.NodeHealth{alive("n1", 42*time.Millisecond, testEpoch)})

	h, ok := s.Health("n1")
	if !ok {
		t.Fatal("живость не найдена")
	}
	h.Window = append(h.Window, health.Fail)
	h.State = health.Dead

	again, _ := s.Health("n1")
	if again.State == health.Dead {
		t.Error("правка отданной копии изменила стор")
	}
}
