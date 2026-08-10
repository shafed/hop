//go:build unix

package main

import (
	"fmt"
	"os/user"
	"strconv"
)

// lookupGID переводит имя группы в gid. Пустое имя — не менять группу: сокет
// остаётся доступен одному владельцу.
//
// Отсутствующая группа валит старт, а не понижается молча до 0600: сервис,
// поднявший сокет, к которому агент не может подключиться, выглядит рабочим и
// не работает. Установщик группу создаёт; в отладке и L3 передают -group "".
func lookupGID(name string) (int, error) {
	if name == "" {
		return -1, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("группа %q: %w (создать её или передать -group \"\")", name, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("группа %q: неразбираемый gid %q", name, g.Gid)
	}
	return gid, nil
}
