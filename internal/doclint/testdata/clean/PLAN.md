# План (фикстура)

Этап закрывают T70–T71 и W71; T77 ещё не написан.

**Что должно сломаться при выключении.** `known_flag=off` → T70 краснеет.
Параметр `heartbeat_miss = 3` политикой не является и проверяться не должен;
`last_switch` в прозе — тоже не политика.

Подробности — `docs/verification-agent.md`, код — `internal/thing`,
символ — `internal/thing.Do`, чужой референс — `sing-tun/tun_linux.go:791`,
сеть — `0.0.0.0/0`, сокет — `/run/hop.sock`, шаблон — `docs/*.md`,
команда — `go build ./...`.
