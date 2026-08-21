// B2 (§8.6) — стоимость проб: сколько исходящих соединений расписание §6.5
// просит за час при подписке в 200 узлов.
//
// Замер идёт по фейковым часам, а не по настоящему часу: мерится решение
// §6.5 — ярусы, их периоды и джиттер, — а не то, за сколько машина успевает
// открыть сокет. Настоящих сокетов поэтому тоже нет: исходящее выражено парой
// net.Pipe, и одна такая пара — ровно одно соединение, которое в проде открыл
// бы Engine.DialVia. Считается именно она, а не пакеты.
//
// Путь до счётчика настоящий: расписание, монитор, выбор и URLProber — те же,
// что в проде, с настоящим HTTP-обменом поверх трубы. Из-за этого в цену
// попадает и то, что даёт §5.4: мёртвый пробе-таргет заставляет пробу пойти в
// следующий, и одна проба стоит уже не одного соединения.
package bench

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/health"
)

// probeCostEpoch — начало отсчёта фейковых часов. Значение произвольно и на
// результат не влияет: расписание считает сроки от него же.
var probeCostEpoch = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// ProbeCostConfig — параметры замера B2.
type ProbeCostConfig struct {
	// Nodes — размер подписки. §6.5 называет 200.
	Nodes int
	// Window — окно наблюдения. §8.6 называет час.
	Window time.Duration
	// Step — шаг прокрутки часов: как часто расписание получает управление. На
	// результат не влияет, пока не крупнее самого частого яруса, — это
	// проверяет TestProbeCostDoesNotDependOnStep.
	Step time.Duration
	// Sched — расписание, чью цену меряем.
	Sched health.ScheduleConfig
}

// ProbeCostResult — одно измерение B2.
type ProbeCostResult struct {
	Nodes  int           `json:"nodes"`
	Window time.Duration `json:"window_ns"`
	Conns  int64         `json:"conns"`
	Probes int64         `json:"probes"`
}

// ConnsPerHour — цена в единицах §8.6.
func (r ProbeCostResult) ConnsPerHour() float64 {
	if r.Window <= 0 {
		return 0
	}
	return float64(r.Conns) / r.Window.Hours()
}

// ProbeCost крутит расписание по фейковым часам и считает исходящие соединения.
func ProbeCost(cfg ProbeCostConfig) (ProbeCostResult, error) {
	if cfg.Nodes < 1 {
		return ProbeCostResult{}, fmt.Errorf("bench: подписка из %d узлов", cfg.Nodes)
	}
	if cfg.Window <= 0 || cfg.Step <= 0 {
		return ProbeCostResult{}, fmt.Errorf("bench: окно %v, шаг %v", cfg.Window, cfg.Step)
	}

	ids := make([]string, cfg.Nodes)
	for i := range ids {
		ids[i] = fmt.Sprintf("n%03d", i)
	}
	active, pool, rest := splitTiers(ids, cfg.Sched.PoolSize)

	clk := clock.NewFake(probeCostEpoch)
	mon := health.NewMonitor(health.DefaultMonitorConfig(), clk)
	sel := health.NewSelector(mon, health.DefaultSelectorConfig(), clk)
	defer sel.Close()
	sel.SetCandidates(ids)

	var conns, probes atomic.Int64
	target := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), 80)
	prober := &countingProber{
		calls: &probes,
		inner: health.NewURLProber(pipeDial(&conns), []health.Target{{Addr: target, Path: "/generate_204"}}, clk),
	}

	sch := health.NewScheduler(prober, mon, sel, cfg.Sched, clk)
	sch.SetNodes(active, pool, rest)

	// Стартовый прогон — за окном: он бывает один раз за запуск агента, а
	// меряется установившаяся цена. Оставить его внутри значило бы приписать
	// часу лишнюю пробу каждого горячего узла.
	ctx := context.Background()
	sch.Sweep(ctx)
	conns.Store(0)
	probes.Store(0)

	for elapsed := time.Duration(0); elapsed < cfg.Window; elapsed += cfg.Step {
		clk.Advance(cfg.Step)
		sch.Sweep(ctx)
	}

	return ProbeCostResult{
		Nodes:  cfg.Nodes,
		Window: cfg.Window,
		Conns:  conns.Load(),
		Probes: probes.Load(),
	}, nil
}

// splitTiers раскладывает подписку по ярусам §6.5: первый узел активный, за ним
// пул кандидатов, остальное — редкий ярус.
func splitTiers(ids []string, poolSize int) (active string, pool, rest []string) {
	active = ids[0]
	tail := ids[1:]
	if poolSize < 0 {
		poolSize = 0
	}
	if poolSize > len(tail) {
		poolSize = len(tail)
	}
	return active, tail[:poolSize], tail[poolSize:]
}

// countingProber считает пробы. Соединения считаются отдельно и ниже: одна
// проба — не обязательно одно соединение (§5.4).
type countingProber struct {
	calls *atomic.Int64
	inner health.Prober
}

func (p *countingProber) Probe(ctx context.Context, nodeID string) health.Result {
	p.calls.Add(1)
	return p.inner.Probe(ctx, nodeID)
}

// pipeDial — исходящее поверх net.Pipe: пробе-таргет §8.1, отдающий 204. Каждый
// вызов — одно соединение, и это и есть измеряемая величина.
func pipeDial(conns *atomic.Int64) health.DialFunc {
	return func(_ context.Context, _ string, _ netip.AddrPort) (net.Conn, error) {
		conns.Add(1)
		cli, srv := net.Pipe()
		go func() {
			defer srv.Close()
			br := bufio.NewReader(srv)
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
			fmt.Fprint(srv, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
		}()
		return cli, nil
	}
}

// ProbeCostNodes — размер подписки, для которой назван бюджет: §6.5 считает
// нагрузку на провайдера именно на двухстах узлах.
const ProbeCostNodes = 200

// ProbeCostBudget — порог B2, исходящих соединений в час на ProbeCostNodes
// узлах.
//
// Откуда число. Штатное расписание DefaultScheduleConfig просит 808: активный
// узел раз в 30 с — 120, пять кандидатов раз в минуту — 300, остальные 194 раз
// в полчаса — 388. Верхняя граница названа §6.5 и равна 4000: полный обход
// подписки раз в три минуты. Порог поставлен между ними ближе к измеренному —
// запас в четверть покрывает подтверждающие пробы §6.3 и округление джиттера,
// но не покрывает ни одного вырождения ярусов: пул без ограничения PoolSize,
// редкий ярус с периодом пула и полный обход дают тысячи, а не сотни.
//
// Гейтится установившаяся цена на здоровой подписке — та самая, о которой
// говорит §6.5. Больная подписка стоит дороже (§5.4: мёртвый пробе-таргет
// уводит пробу в следующий URL), и это не деградация расписания, а погода.
const ProbeCostBudget = 1000
