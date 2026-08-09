package ipc

// Conn — одно соединение управляющей границы.
//
// Дескриптор — часть интерфейса, а не отдельный канал: на Linux и macOS он
// едет вместе с ответом одним sendmsg через SCM_RIGHTS, и разнести их значит
// получить состояние «ответ пришёл, дескриптор нет».
type Conn interface {
	// Recv возвращает следующий кадр; fd = -1, если дескриптора не было.
	Recv() (body []byte, fd int, err error)
	// Send отправляет кадр. fd >= 0 едет вместе с ним.
	Send(body []byte, fd int) error
	// Peer — владелец процесса на том конце: "uid:1000" на Linux и macOS,
	// SID на Windows. То, что Attach сверяет с владельцем туннеля (§3.1).
	Peer() string
	Close() error
}

// Listener — слушающая сторона.
type Listener interface {
	Accept() (Conn, error)
	Close() error
}
