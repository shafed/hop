//go:build !linux

package outbound

import (
	"fmt"
	"syscall"
)

// Selector is intentionally loud on platforms whose route monitor has not
// reached the implementation stage yet. An unbound fallback would be a loop.
type Selector struct{}

func New(string) (*Selector, error) {
	return nil, fmt.Errorf("%w: эта ОС ещё не реализована", ErrNoInterface)
}

func (*Selector) Interface() (string, error) { return "", ErrNoInterface }
func (*Selector) Close() error               { return nil }
func (*Selector) Control(string, string, syscall.RawConn) error {
	return ErrNoInterface
}
