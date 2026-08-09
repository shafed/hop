package bench

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
)

// Boundary — пара named pipe, по одной на направление (§этап 1): полудуплекс
// на одной трубе душил бы встречный поток.
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

// pipeBufBytes — буфер трубы в ядре. Крупный буфер снижает число пробуждений.
const pipeBufBytes = 1 << 20

// NewPipeBoundary поднимает две named pipe в byte-режиме (MessageMode=false):
// границы пакетов несёт length-prefix, а не режим трубы.
func NewPipeBoundary() (*Boundary, error) {
	base := fmt.Sprintf(`\\.\pipe\xrayvpn-b1-%d`, os.Getpid())

	s2a, err := dialPair(base + "-s2a")
	if err != nil {
		return nil, err
	}
	a2s, err := dialPair(base + "-a2s")
	if err != nil {
		s2a.close()
		return nil, err
	}
	return &Boundary{
		ServiceToAgent: Pipe{W: s2a.server, R: s2a.client},
		AgentToService: Pipe{W: a2s.client, R: a2s.server},
		closers: []interface{ Close() error }{
			s2a.server, s2a.client, a2s.server, a2s.client,
		},
	}, nil
}

type pipePair struct {
	server, client net.Conn
	listener       net.Listener
}

func (p *pipePair) close() {
	if p.server != nil {
		p.server.Close()
	}
	if p.client != nil {
		p.client.Close()
	}
	if p.listener != nil {
		p.listener.Close()
	}
}

func dialPair(path string) (*pipePair, error) {
	l, err := winio.ListenPipe(path, &winio.PipeConfig{
		MessageMode:      false,
		InputBufferSize:  pipeBufBytes,
		OutputBufferSize: pipeBufBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("ListenPipe %s: %w", path, err)
	}

	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		c, err := l.Accept()
		ch <- acc{c, err}
	}()

	timeout := 5 * time.Second
	client, err := winio.DialPipe(path, &timeout)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("DialPipe %s: %w", path, err)
	}
	a := <-ch
	if a.err != nil {
		client.Close()
		l.Close()
		return nil, fmt.Errorf("Accept %s: %w", path, a.err)
	}
	return &pipePair{server: a.c, client: client, listener: l}, nil
}

// NewBoundary — граница этой ОС.
func NewBoundary() (*Boundary, error) { return NewPipeBoundary() }

// BoundaryName — как называть границу в отчёте.
func BoundaryName() string { return "named pipe" }
