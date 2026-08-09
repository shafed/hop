package ipc

import (
	"runtime"
	"strconv"
	"strings"
)

// DefaultPath — управляющая граница по умолчанию (§3.1).
var DefaultPath = defaultPath()

func defaultPath() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\hop`
	}
	return "/run/hop.sock"
}

// peerUID возвращает UID из Peer() или -1, если владелец задан не UID-ом
// (Windows: там это SID).
func peerUID(peer string) int {
	rest, ok := strings.CutPrefix(peer, "uid:")
	if !ok {
		return -1
	}
	uid, err := strconv.Atoi(rest)
	if err != nil {
		return -1
	}
	return uid
}
