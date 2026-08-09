//go:build linux || darwin

package bench

import (
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

func osName() string { return runtime.GOOS }

// processCPU — процессорное время процесса, user+sys.
func processCPU() time.Duration {
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return tv(ru.Utime) + tv(ru.Stime)
}

func tv(t unix.Timeval) time.Duration {
	return time.Duration(t.Sec)*time.Second + time.Duration(t.Usec)*time.Microsecond
}
