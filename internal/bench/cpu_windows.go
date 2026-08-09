package bench

import (
	"runtime"
	"time"

	"golang.org/x/sys/windows"
)

func osName() string { return runtime.GOOS }

// processCPU — процессорное время процесса, user+kernel.
func processCPU() time.Duration {
	var creation, exit, kernel, user windows.Filetime
	h := windows.CurrentProcess()
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return 0
	}
	return filetime(kernel) + filetime(user)
}

// FILETIME считает интервалами по 100 нс.
func filetime(f windows.Filetime) time.Duration {
	return time.Duration(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) * 100 * time.Nanosecond
}
