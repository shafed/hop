package health

import (
	"context"
	"errors"
	"sync"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/policy"
)

// Target — один тестовый URL, опрошенный через outbound узла (§6.7).
// Реализация v1 появится на этапе 4 вместе с Xray; здесь важна только
// семантика сведения результатов.
type Target interface {
	Check(ctx context.Context, nodeID string) (time.Duration, error)
	Name() string
}

// ErrNoTargets — пробер без единого URL. Не «узел мёртв», а поломка конфигурации.
var ErrNoTargets = errors.New("health: у пробера нет ни одного тестового URL")

// MultiProber — проба по нескольким URL (§5.4).
//
// Р3: проба успешна, если успешен хотя бы один URL; rtt — минимальный из
// успешных; вердикт не зависит от порядка. URL опрашиваются параллельно,
// поэтому первый успевший и есть минимальный, и ждать остальных незачем: чем
// раньше кончится проба, тем короче раунд (A31, A32).
//
// Цель мульти-URL — пережить блокировку одного тестового домена. «Большинство»
// или «все» ровно этого не переживают, поэтому здесь именно «хотя бы один».
type MultiProber struct {
	Targets []Target
}

// Probe реализует Prober.
func (p *MultiProber) Probe(ctx context.Context, nodeID string) Result {
	targets := p.Targets
	// multi_url выключена — остаётся один URL, и блокировка тестового домена
	// хоронит всю подписку разом. Краснит T5, A31, A32.
	if !policy.MultiURL.On() && len(targets) > 1 {
		targets = targets[:1]
	}
	if len(targets) == 0 {
		return Result{Err: ErrNoTargets}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type outcome struct {
		rtt time.Duration
		err error
	}
	results := make(chan outcome, len(targets))
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			rtt, err := t.Check(ctx, nodeID)
			results <- outcome{rtt, err}
		}(t)
	}
	go func() { wg.Wait(); close(results) }()

	var lastErr error
	for o := range results {
		if o.err == nil {
			return Result{RTT: o.rtt} // первый успевший — он же самый быстрый
		}
		lastErr = o.err
	}
	if lastErr == nil {
		lastErr = errors.New("health: ни один URL не ответил")
	}
	return Result{Err: lastErr}
}
