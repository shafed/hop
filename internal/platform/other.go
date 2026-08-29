//go:build !linux

package platform

import (
	"errors"
	"log/slog"
	"runtime"

	"github.com/shafed/hop/internal/tunnel"
)

// Unsupported — платформенный слой, которого на этой ОС ещё нет.
//
// На macOS его содержание известно (utun через AF_SYSTEM, адрес через
// SIOCAIFADDR, маршруты через PF_ROUTE, `route change ... -reject` для
// orphaned — §5.10, §6.2), на Windows оно упирается в открытый вопрос §7.2:
// без подписанной wintun.dll рядом с бинарём адаптер не поднимается, и план
// держит этот вопрос блокером этапа 8.
//
// Отказ явный: молчаливая заглушка дала бы зелёный L3 там, где ничего не
// проверено.
type Unsupported struct{}

func New(*slog.Logger) *Unsupported { return &Unsupported{} }

var errUnsupported = errors.New("platform: привилегированный слой для " + runtime.GOOS + " появится вместе с этапом 8")

// Reclaim появится вместе с платформенным слоем: на macOS и Windows смерть
// сервиса переживают ещё и настройки DNS (§8.4, T29), и убирать за собой
// придётся больше, а не меньше.
func Reclaim() (int, error) { return 0, nil }

func (Unsupported) Up(tunnel.Params) (tunnel.Device, error) { return nil, errUnsupported }
func (Unsupported) Reject() error                           { return errUnsupported }
func (Unsupported) Restore() error                          { return errUnsupported }
func (Unsupported) Down() error                             { return nil }
