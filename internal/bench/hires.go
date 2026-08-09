package bench

import "time"

// hiresResolution — наименьший наблюдаемый шаг часов. Замер латентности обязан
// его печатать: часы грубее измеряемого интервала дают не «немного шума», а
// молчаливые нули в половине выборки, и p50 выглядит как отсутствующий.
func hiresResolution() time.Duration {
	best := time.Duration(1<<63 - 1)
	for i := 0; i < 16; i++ {
		t0 := hiresNow()
		var d time.Duration
		for d == 0 {
			d = hiresNow() - t0
		}
		if d < best {
			best = d
		}
	}
	return best
}
