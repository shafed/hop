package bench

import (
	"bytes"
	"io"
	"net/netip"
	"testing"
)

// Сквозная проверка TCP-пути этапа 3: настоящая граница этой ОС, наш netstack
// на одной стороне, обычный gvisor на другой, фейковый диалер за ним.
//
// Оракул §8.3 этот путь не покрывает — T12 и T13 смотрят на fail-close, то есть
// на отказ. Здесь проверяется, что при живом узле поток проходит насквозь.
func TestNetstackTCPRoundTrip(t *testing.T) {
	r, err := newRig(NetstackConfig{}, false, true)
	if err != nil {
		t.Fatalf("стенд: %v", err)
	}
	defer r.close()

	conn, err := r.client.dial(netip.AddrPortFrom(benchServer, 80))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	want := []byte("интерактивный обмен мелким пакетом")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("вернулось %q, отправлено %q", got, want)
	}
}

// Вердикт получен до рукопожатия, и это видно снаружи: если исходящее
// соединение не установилось, приложение получает отказ на connect, а не
// установленное соединение, которое умрёт первым же байтом.
//
// Свойство держится на форвардере gvisor: SYN-ACK уходит только из
// CreateEndpoint, и до него можно передумать. Если бы стек отвечал на SYN сам,
// это пришлось бы чинить форком.
func TestRefusedUpstreamNeverCompletesHandshake(t *testing.T) {
	r, err := newRig(NetstackConfig{}, false, true)
	if err != nil {
		t.Fatalf("стенд: %v", err)
	}
	defer r.close()
	r.dialer.FailTCP(true)

	conn, err := r.client.dial(netip.AddrPortFrom(benchServer, 80))
	if err == nil {
		conn.Close()
		t.Fatal("соединение установлено, хотя исходящее не поднялось")
	}
	if len(r.dialer.TCPDialed()) != 0 {
		t.Fatal("диалер записал успешный звонок")
	}
}
