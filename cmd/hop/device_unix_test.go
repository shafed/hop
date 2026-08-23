//go:build unix

package main

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time" //hop:realtime

	"golang.org/x/sys/unix"

	"github.com/shafed/hop/internal/tunnel"
)

// TestW44CloseWakesTheReaderInsteadOfPullingTheFDAway — закрытие устройства
// заканчивает чтение обычным io.EOF, а не отказом.
//
// Дефект был в том, что close закрывал дескриптор, пока ReadPackets на нём
// спал: netstack получал «bad file descriptor», принимал его за отказ стека
// («стек остановился») и снимал датаплейн, хотя туннель всего лишь закрывали.
// Вторая половина того же — номер закрытого дескриптора ядро сразу отдаёт
// следующему open, и читатель дочитывает чужой файл.
//
// Окно между проверкой флага и системным вызовом узкое, поэтому проверка не
// ждёт удачи: труба кормится данными, чтобы каждый круг читателя был коротким,
// читателей несколько, и всё это повторяется — на прежнем коде так гонка
// воспроизводится, а не выпадает раз в сотню прогонов.
func TestW44CloseWakesTheReaderInsteadOfPullingTheFDAway(t *testing.T) {
	const (
		readers  = 4
		attempts = 20
	)
	for attempt := 0; attempt < attempts; attempt++ {
		var p [2]int
		if err := unix.Pipe(p[:]); err != nil {
			t.Fatalf("труба: %v", err)
		}
		// Пишущий конец неблокирующий: иначе писатель заснёт в полной трубе и
		// не заметит, что читателей больше нет.
		if err := unix.SetNonblock(p[1], true); err != nil {
			t.Fatalf("труба в неблокирующий режим: %v", err)
		}
		dev, err := openDevice(p[0], "hop0", 1400)
		if err != nil {
			unix.Close(p[0])
			unix.Close(p[1])
			t.Fatalf("openDevice: %v", err)
		}

		stop, written := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(written)
			pkt := []byte{0x45, 0x00, 0x00, 0x14}
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := unix.Write(p[1], pkt); err != nil && err != unix.EAGAIN {
					return // читающий конец закрыт — устройства больше нет
				}
			}
		}()

		var wg sync.WaitGroup
		errs := make(chan error, readers)
		for r := 0; r < readers; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				bufs := [][]byte{make([]byte, 1400)}
				for {
					if _, err := dev.ReadPackets(bufs); err != nil {
						errs <- err
						return
					}
				}
			}()
		}
		time.Sleep(2 * time.Millisecond) //hop:realtime — дать читателям дойти до Poll

		if err := dev.close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		wg.Wait()
		close(stop)
		<-written // писатель ушёл, и только теперь его конец можно закрывать
		unix.Close(p[1])

		close(errs)
		for err := range errs {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("ReadPackets вернул %v вместо io.EOF: закрытие выдернуло дескриптор "+
					"из-под спящего читателя, и netstack снимет датаплейн как при отказе стека, "+
					"хотя туннель просто закрывали", err)
			}
		}
	}
}

// TestW46AcquireClosesTheFDWhenTokenSaveFails — на отказе записи токена откат
// закрывает и присланный дескриптор, а не только туннель.
//
// Спутник W45: та сторожит туннель, который иначе остался бы поднятым, эта —
// дескриптор, который иначе дожил бы до конца процесса. Проверка unix-только:
// на Windows устройство приезжает трубой и ipc.Result.FD там всегда -1 (§3.2).
func TestW46AcquireClosesTheFDWhenTokenSaveFails(t *testing.T) {
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		t.Fatalf("труба: %v", err)
	}
	defer unix.Close(p[1])
	// p[0] отдаётся транспорту как «дескриптор, приехавший от сервиса»:
	// закрыть его — работа транспорта, и её тут и проверяют.

	tr := newTransport(&fakeControl{fd: p[0]}, unwritableTokenPath(t), time.Hour, quietLog()) //hop:realtime
	defer tr.close()

	if _, err := tr.Acquire(tunnel.Params{Name: "hop0", MTU: 1400}); err == nil {
		unix.Close(p[0])
		t.Fatal("Acquire прошёл молча, хотя токен записать не вышло")
	}
	if _, err := unix.FcntlInt(uintptr(p[0]), unix.F_GETFD, 0); err != unix.EBADF {
		unix.Close(p[0])
		t.Fatalf("дескриптор устройства остался открытым (F_GETFD вернул %v): агент утекает "+
			"дескриптором TUN на каждую неудачную попытку подъёма", err)
	}
}
