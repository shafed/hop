package main

import (
	"fmt"
	"net"
	"time"

	"github.com/shafed/hop/internal/bench"
)

const (
	tunName  = "b1tun0"
	tunCIDR  = "10.99.0.1/24"
	tunMTU   = 1500
	peerAddr = "10.99.0.2"
	sinkPort = 19999
)

func boundaryName() string { return bench.BoundaryName() }

// runTUN снимает базовую линию реального TUN-fd и контрольный замер GSO.
// Требует собственного net namespace: запускать под `unshare -Urn`.
func runTUN(pkt int, dur time.Duration) ([]bench.Result, error) {
	var out []bench.Result

	plain, err := bench.OpenTUN(tunName, false)
	if err != nil {
		return nil, fmt.Errorf("%w (нужен свой netns: unshare -Urn)", err)
	}
	if err := plain.Up(tunCIDR, tunMTU); err != nil {
		plain.Close()
		return nil, err
	}

	cfg := bench.Config{PktSize: pkt, Batch: 1, Duration: dur}

	r, err := bench.TUNRead(plain, cfg, fmt.Sprintf("%s:9", peerAddr), 4)
	if err != nil {
		plain.Close()
		return nil, err
	}
	out = append(out, r)

	r, err = bench.TUNWrite(plain, cfg, net.ParseIP(peerAddr), net.ParseIP("10.99.0.1"), sinkPort)
	plain.Close()
	if err != nil {
		return nil, err
	}
	out = append(out, r)

	// Контрольный замер GSO. Не гейт: §4 вынес GSO за v1, число нужно, чтобы
	// знать цену возврата.
	gso, err := bench.OpenTUN(tunName, true)
	if err != nil {
		return nil, fmt.Errorf("vnet_hdr: %w", err)
	}
	defer gso.Close()
	if err := gso.Up(tunCIDR, tunMTU); err != nil {
		return nil, err
	}

	segSize := pkt - 28
	r, err = bench.TUNReadGSO(gso, cfg, fmt.Sprintf("%s:9", peerAddr), segSize, 45*segSize)
	if err != nil {
		return nil, err
	}
	return append(out, r), nil
}
