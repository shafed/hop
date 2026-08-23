//go:build windows

package main

import "errors"

// На Windows устройство приезжает не дескриптором, а именованной трубой
// (§3.2, ipc.Result.FD там всегда -1). Труба — работа этапа 8 вместе с
// wintun.dll; до неё агент на Windows поднимает туннель, но датаплейна не
// имеет.
//
// Отказ здесь громкий и named: молчаливая заглушка означала бы «hop up прошёл,
// трафика нет» — ровно тот дефект, ради которого этот этап и делается.
var errNoWindowsDevice = errors.New("датаплейн на Windows приезжает трубой и появится этапом 8")

func openDevice(fd int, name string, mtu int) (agentDevice, error) {
	return nil, errNoWindowsDevice
}

// closeInboundFD — на Windows закрывать нечего: устройство приезжает трубой, и
// ipc.Result.FD там всегда -1 (§3.2). Функция существует, чтобы транспорт мог
// откатывать неудавшийся подъём одинаково на всех ОС, не обрастая ветками.
func closeInboundFD(fd int) error { return nil }
