//go:build windows

package main

// lookupGID на Windows ничего не решает: доступ к трубе задаёт SDDL (§3.1),
// групп в понимании Unix здесь нет. Флаг -group принимается и игнорируется,
// чтобы одна и та же команда запуска годилась на всех трёх ОС.
func lookupGID(string) (int, error) { return -1, nil }
