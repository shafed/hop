package main

import (
	"io"

	"github.com/shafed/hop/internal/agent"
	"github.com/shafed/hop/internal/store"
)

// applySettings — заготовка: настройки стора пока не доезжают до связки.
func applySettings(cfg *agent.Config, st *store.Store) {}

// showSettings — заготовка: печатать пока нечего.
func showSettings(st *store.Store, path string, out io.Writer) error { return nil }
