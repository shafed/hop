package ipc

import (
	"runtime"
)

// DefaultPath — управляющая граница по умолчанию (§3.1).
var DefaultPath = defaultPath()

func defaultPath() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\hop`
	}
	return "/run/hop.sock"
}
