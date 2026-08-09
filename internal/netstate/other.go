//go:build !linux

package netstate

import (
	"errors"
	"runtime"
)

// System на macOS и Windows появится вместе с их платформенным слоем: там
// снапшот включает ещё и настройки DNS, которые переживают смерть процесса
// (§8.4, T29). Пока источника нет, вызов обязан отказать явно — молчаливо
// пустой снапшот совпал бы с любым и превратил бы T22 в вечно зелёный тест.
func System() Source { return unimplemented{} }

type unimplemented struct{}

func (unimplemented) Capture() (Snapshot, error) {
	return Snapshot{}, errors.New("netstate: источник состояния сети для " + runtime.GOOS + " ещё не написан")
}
