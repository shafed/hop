package main

import (
	"io"

	"github.com/shafed/hop/internal/agent"
	"github.com/shafed/hop/internal/store"
)

// Настройки маршрутизации (§6.10) и апстримов (§5.7) с диска.
//
// Флаг `-routing` снят этапом 9: подкоманда `hop routing` надета поверх тех же
// вызовов без переписывания — вся работа здесь делается пакетом store, а не
// разбором аргументов. Формирование вывода уехало в output.go (§5.9).

// applySettings переносит настройки стора в конфигурацию связки.
//
// Отдельная функция, а не две строки в литерале agent.Config: это единственный
// шов между диском и продуктом, и он молчалив — оба поля необязательны, nil у
// каждого означает умолчания, поэтому забытый перенос не ломает ни сборку, ни
// модульные тесты. Функция существует затем, чтобы W52 и W53 могли на него
// смотреть, не поднимая ни туннеля, ни сервиса.
func applySettings(cfg *agent.Config, st *store.Store) {
	set := st.Settings()
	cfg.Routing = set.Routing
	cfg.DNSUpstreams = set.DNSUpstreams
}

// showSettings — человеческая половина `hop routing`.
//
// Тонкая обёртка над той же парой, что и у остальных читающих команд:
// значение собирает settingsView, подаёт его emit. Существует отдельной
// функцией потому, что на неё смотрят проверки вывода, а поднимать ради них
// разбор аргументов незачем.
func showSettings(st *store.Store, path string, out io.Writer) error {
	return emit(out, settingsView(st, path), false)
}
