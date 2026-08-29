# План (фикстура)

Этап закрывают T70 и T77.

**Что должно сломаться при выключении.** `known_flag=off` → T70 краснеет.
`nowhere_flag=off` → ничего не краснеет, потому что такой политики нет.

Подробности — `docs/gone.md` и `docs/verification-agent.md`.
Код живёт в `internal/thing`, срез сети — `0.0.0.0/0`, чужой референс —
`sing-tun/tun_linux.go:791`, символ — `internal/thing.Do`.
