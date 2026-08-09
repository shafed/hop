package bench

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Монотонные часы Go на Windows идут от системного таймера, и его шага
// (сотни микросекунд) не хватает на RTT границы в десятки микросекунд: больше
// половины замеров читались нулём. QueryPerformanceCounter даёт нужный
// порядок. В x/sys/windows он не обёрнут, поэтому берём из kernel32 напрямую.
var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	procQPC  = kernel32.NewProc("QueryPerformanceCounter")
	procQPF  = kernel32.NewProc("QueryPerformanceFrequency")

	qpcFreq  = qpcFrequency()
	qpcEpoch = qpcCounter()
)

func qpcCounter() int64 {
	var c int64
	procQPC.Call(uintptr(unsafe.Pointer(&c)))
	return c
}

func qpcFrequency() int64 {
	var f int64
	procQPF.Call(uintptr(unsafe.Pointer(&f)))
	if f == 0 {
		f = 1 // QPC недоступен: hiresNow выродится, resolution это покажет
	}
	return f
}

// hiresNow — монотонное время максимального доступного разрешения.
func hiresNow() time.Duration {
	return time.Duration((qpcCounter() - qpcEpoch) * int64(time.Second) / qpcFreq)
}
