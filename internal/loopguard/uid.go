package loopguard

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// DefaultSysUIDMax — умолчание shadow-utils. Оно же ответ, когда /etc/login.defs
// не прочитался или ничего внятного не сказал: правило §6.8 обязано работать на
// машине без явной настройки, а ноль закрыл бы туннель на каждой такой.
const DefaultSysUIDMax = 999

// loginDefs — где машина держит границу между служебными учётками и людьми.
const loginDefs = "/etc/login.defs"

// SysUIDMax — SYS_UID_MAX этой машины, для Params.SystemUIDMax.
//
// Читается здесь, а не в plan: план — данные, и зависеть от файлов машины он не
// должен, иначе решение §6.8 перестанет проверяться где угодно (см. шапку
// пакета).
func SysUIDMax() int {
	f, err := os.Open(loginDefs)
	if err != nil {
		return DefaultSysUIDMax
	}
	defer f.Close()
	return parseSysUIDMax(f)
}

// parseSysUIDMax вынимает SYS_UID_MAX из формата login.defs: имя, пробелы,
// значение. Комментарии начинаются с `#` и значением не являются.
func parseSysUIDMax(r io.Reader) int {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Разделитель в login.defs — любой пробельный набор, чаще табы.
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "SYS_UID_MAX" {
			continue
		}
		n, err := strconv.Atoi(f[1])
		if err != nil || n <= 0 {
			continue
		}
		return n
	}
	return DefaultSysUIDMax
}
