//go:build !linux

package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/shafed/hop/internal/bench"
)

func boundaryName() string { return bench.BoundaryName() }

// runTUN на не-Linux пока не реализован: macOS-утун приезжает вместе с
// сервисом (этап 2), Windows-адаптер Wintun — с этапом 8 (вопрос §7.2).
func runTUN(int, time.Duration) ([]bench.Result, error) {
	return nil, fmt.Errorf("режим tun не реализован на %s", runtime.GOOS)
}
