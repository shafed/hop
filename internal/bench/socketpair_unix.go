//go:build linux || darwin

package bench

import (
	"os"

	"golang.org/x/sys/unix"
)

// Boundary — две однонаправленные трубы, как на Windows: полудуплекс не должен
// душить встречный поток.
type Boundary struct {
	ServiceToAgent Pipe
	AgentToService Pipe
	closers        []interface{ Close() error }
}

func (b *Boundary) Close() {
	for _, c := range b.closers {
		_ = c.Close()
	}
}

// NewSocketPairBoundary — контрольный замер «чистая стоимость syscall»:
// AF_UNIX SOCK_STREAM вместо трубы, всё остальное то же.
func NewSocketPairBoundary() (*Boundary, error) {
	s2a, err := streamPair("b1-s2a")
	if err != nil {
		return nil, err
	}
	a2s, err := streamPair("b1-a2s")
	if err != nil {
		s2a.w.Close()
		s2a.r.Close()
		return nil, err
	}
	return &Boundary{
		ServiceToAgent: Pipe{W: s2a.w, R: s2a.r},
		AgentToService: Pipe{W: a2s.w, R: a2s.r},
		closers:        []interface{ Close() error }{s2a.w, s2a.r, a2s.w, a2s.r},
	}, nil
}

type pair struct{ w, r *os.File }

func streamPair(name string) (pair, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return pair{}, err
	}
	return pair{
		w: os.NewFile(uintptr(fds[0]), name+"-w"),
		r: os.NewFile(uintptr(fds[1]), name+"-r"),
	}, nil
}

// NewBoundary — граница этой ОС. На Unix горячего пути через границу нет
// (агент держит дескриптор), поэтому socketpair здесь — контрольный замер
// чистой стоимости syscall, а не модель продакшена.
func NewBoundary() (*Boundary, error) { return NewSocketPairBoundary() }

// BoundaryName — как называть границу в отчёте.
func BoundaryName() string { return "socketpair" }
