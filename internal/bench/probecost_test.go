package bench

import (
	"testing"
	"time"

	"github.com/shafed/hop/internal/health"
)

// B2 меряет ровно то, что §8.6 называет ценой проб: число исходящих соединений.
// Один узел и окно в десять периодов активного яруса — расписание обязано
// попросить ровно десять соединений, по одному на период.
func TestProbeCostCountsEveryOutgoingConnection(t *testing.T) {
	sched := health.DefaultScheduleConfig()
	got, err := ProbeCost(ProbeCostConfig{
		Nodes:  1,
		Window: 10 * sched.Active,
		Step:   time.Second,
		Sched:  sched,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Conns != 10 {
		t.Fatalf("за десять периодов активного яруса насчитано %d исходящих соединений, ожидалось 10", got.Conns)
	}
	if got.Probes != got.Conns {
		t.Fatalf("проб %d, соединений %d: на здоровой подписке успех приходит с первого таргета (§5.4)",
			got.Probes, got.Conns)
	}
}

// Шаг прокрутки — свойство харнесса, а не расписания. Если результат от него
// зависит, B2 меряет гранулярность собственного цикла, и любое его изменение
// выглядит как изменение цены проб.
func TestProbeCostDoesNotDependOnStep(t *testing.T) {
	run := func(step time.Duration) ProbeCostResult {
		t.Helper()
		got, err := ProbeCost(ProbeCostConfig{
			Nodes:  200,
			Window: time.Hour,
			Step:   step,
			Sched:  health.DefaultScheduleConfig(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	coarse := run(time.Second)
	fine := run(250 * time.Millisecond)
	if coarse.Conns != fine.Conns {
		t.Fatalf("шагом 1с насчитано %d соединений, шагом 250мс — %d", coarse.Conns, fine.Conns)
	}

	// Равенство выше — не тавтология: за границей условия («шаг не крупнее
	// самого частого яруса») харнесс действительно недосчитывает. Без этой
	// проверки тест остался бы зелёным и при цикле, который вовсе перестал
	// зависеть от шага, — то есть при сломанном замере.
	sparse := run(45 * time.Second)
	if sparse.Conns >= fine.Conns {
		t.Fatalf("шаг 45с крупнее активного яруса, но насчитал %d соединений против %d: "+
			"замер перестал зависеть от прокрутки часов", sparse.Conns, fine.Conns)
	}
}

// Собственно B2: подписка §6.5 при штатном расписании укладывается в бюджет.
func TestProbeCostOfDefaultScheduleIsUnderBudget(t *testing.T) {
	got, err := ProbeCost(ProbeCostConfig{
		Nodes:  ProbeCostNodes,
		Window: time.Hour,
		Step:   time.Second,
		Sched:  health.DefaultScheduleConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if per := got.ConnsPerHour(); per > ProbeCostBudget {
		t.Fatalf("расписание просит %.0f исходящих соединений в час при бюджете %.0f (§6.5)",
			per, float64(ProbeCostBudget))
	}
}

// Бюджет обязан краснеть ровно на том, ради чего §6.5 назван: расписание,
// выродившееся в полный обход подписки раз в три минуты. Без этой проверки
// бюджет можно поставить любым числом, и B2 перестанет что-либо охранять.
func TestProbeCostCatchesFullSweep(t *testing.T) {
	sched := health.DefaultScheduleConfig()
	sched.Active = 3 * time.Minute
	sched.Pool = 3 * time.Minute
	sched.Rest = 3 * time.Minute
	sched.Jitter = 0
	sched.PoolSize = ProbeCostNodes // пул не ограничен — весь состав в горячем ярусе

	got, err := ProbeCost(ProbeCostConfig{
		Nodes:  ProbeCostNodes,
		Window: time.Hour,
		Step:   time.Second,
		Sched:  sched,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Цифра §6.5: 200 узлов раз в три минуты — 4000 хендшейков в час.
	if got.Conns != 4000 {
		t.Fatalf("полный обход насчитал %d соединений в час, §6.5 называет 4000", got.Conns)
	}
	if per := got.ConnsPerHour(); per <= ProbeCostBudget {
		t.Fatalf("полный обход подписки уложился в бюджет %.0f: он просит %.0f соединений в час",
			float64(ProbeCostBudget), per)
	}
}
