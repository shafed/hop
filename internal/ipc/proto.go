// Package ipc — управляющая граница «агент ↔ сервис» (§3.1).
//
// Транспорт: unix-сокет с правами владельца (Linux, macOS) и named pipe с
// явным SDDL (Windows). **Не TCP** — §6.1: hiddify слушает gRPC на
// 127.0.0.1:18020 вообще без проверки, и любой процесс любого пользователя
// машины может поднять чужой туннель.
//
// Кадр — uint32 big-endian длина плюс JSON. Длина, а не перевод строки: на
// Linux и macOS вместе с ответом на StartTunnel через SCM_RIGHTS едет
// дескриптор, и разбор обязан быть устойчив к тому, что ядро склеит или
// разрежет записи в потоке произвольно.
package ipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/shafed/hop/internal/tunnel"
)

// Op — операция §3.1.
type Op string

const (
	OpStart     Op = "StartTunnel"
	OpStop      Op = "StopTunnel"
	OpStatus    Op = "Status"
	OpHeartbeat Op = "Heartbeat"
	OpDetach    Op = "Detach"
	OpAttach    Op = "Attach"
)

// Request — запрос агента.
//
// Ни одного узла и ни одного ключа: сервис знает только параметры интерфейса и
// маршрутов (§3.1).
type Request struct {
	Op     Op             `json:"op"`
	Params *tunnel.Params `json:"params,omitempty"`
	Token  tunnel.Token   `json:"token,omitempty"`
	Reason tunnel.Reason  `json:"reason,omitempty"`
}

// Response — ответ сервиса.
type Response struct {
	Error string `json:"error,omitempty"`
	// Token заполняется только в ответ на StartTunnel и Attach. Агент держит
	// его в памяти и никуда не пишет (§6.14).
	Token tunnel.Token  `json:"token,omitempty"`
	State *tunnel.State `json:"state,omitempty"`
	// Device — Ref устройства. На Linux и macOS вместе с этим ответом едет
	// дескриптор; на Windows здесь имя трубы данных.
	Device string `json:"device,omitempty"`
	HasFD  bool   `json:"has_fd,omitempty"`
}

// maxFrame — предел кадра. Управляющие сообщения крошечные; предел стоит,
// чтобы недоверенная длина не превратилась в аллокацию на гигабайт.
const maxFrame = 1 << 16

func encode(v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(body) > maxFrame {
		return nil, fmt.Errorf("ipc: сообщение %d байт, предел %d", len(body), maxFrame)
	}
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], body)
	return out, nil
}

// frames нарезает поток на кадры. Живёт отдельно от транспорта: на unix байты
// приходят из ReadMsgUnix вместе с ancillary-данными, на Windows — обычным
// Read, а разбор один.
type frames struct {
	buf []byte
}

func (f *frames) feed(p []byte) { f.buf = append(f.buf, p...) }

// next возвращает следующий целый кадр или nil, если его ещё не набралось.
func (f *frames) next() ([]byte, error) {
	if len(f.buf) < 4 {
		return nil, nil
	}
	n := int(binary.BigEndian.Uint32(f.buf))
	if n > maxFrame {
		return nil, fmt.Errorf("ipc: кадр %d байт, предел %d", n, maxFrame)
	}
	if len(f.buf) < 4+n {
		return nil, nil
	}
	body := append([]byte(nil), f.buf[4:4+n]...)
	f.buf = f.buf[4+n:]
	return body, nil
}

var errClosed = errors.New("ipc: соединение закрыто")

func isClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, errClosed) || errors.Is(err, io.ErrClosedPipe)
}
