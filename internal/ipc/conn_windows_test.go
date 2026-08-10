//go:build windows

package ipc

import (
	"strings"
	"testing"
)

// Право открыть трубу даётся классу, а не SID слушателя. Раньше в дескриптор
// подставлялся currentSID() сервиса, то есть LocalSystem: агент обычного
// пользователя получал ERROR_ACCESS_DENIED и подключиться не мог вовсе.
//
// Этот тест краснеет при возврате любого SID процесса в дескриптор.
func TestPipeSDDLGrantsClassNotService(t *testing.T) {
	sid, err := currentSID()
	if err != nil {
		t.Fatalf("currentSID: %v", err)
	}
	if strings.Contains(sddl, sid) {
		t.Fatalf("SDDL несёт SID самого сервиса: %s", sddl)
	}
	if !strings.Contains(sddl, ";;;IU)") {
		t.Fatalf("SDDL не открыт интерактивным пользователям: %s", sddl)
	}
	// Everyone (WD) — то, что даёт умолчание named pipe и запрещает §6.1.
	if strings.Contains(sddl, ";;;WD)") {
		t.Fatalf("SDDL открыт Everyone: %s", sddl)
	}
}
