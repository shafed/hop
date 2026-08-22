package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/xraytest"
)

// Настоящее время в этом файле — это сетевые дедлайны стенда, а не логика
// продукта: живость и расписание живут в internal/health на фейковых часах.

func loopbackPhysical() (string, error) { return "lo", nil }

// echoServer — «интернет» стенда: отдаёт назад то, что получил.
func echoServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("эхо-сервер не поднялся: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

// nodeFor — узел, указывающий на инбаунд стенда.
func nodeFor(s *xraytest.Server, id string) Node {
	return Node{
		ID:        id,
		Protocol:  "vless",
		Server:    s.Host(),
		Port:      s.Port(),
		Transport: "raw",
		Security:  "none",
		Params:    map[string]string{"uuid": s.UUID()},
	}
}

// TestDialGoesThroughTheNode — базовый сквозной путь: клиент поднимает
// настоящее VLESS-соединение до настоящего инбаунда, и байты доходят до
// «интернета» и обратно. Моков между engine и узлом нет (§8.3).
func TestDialGoesThroughTheNode(t *testing.T) {
	echo := echoServer(t)
	srv, err := xraytest.NewServer(xraytest.Options{})
	if err != nil {
		t.Fatalf("инбаунд не поднялся: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	e, err := New([]Node{nodeFor(srv, "A")}, loopbackPhysical)
	if err != nil {
		t.Fatalf("движок не поднялся: %v", err)
	}
	t.Cleanup(func() { e.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) //hop:realtime
	defer cancel()
	conn, err := e.DialTCP(ctx, "A", echo)
	if err != nil {
		t.Fatalf("соединение через узел не установилось: %v", err)
	}
	defer conn.Close()

	want := []byte("привет через vless")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("запись: %v", err)
	}
	got := make([]byte, len(want))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second)) //hop:realtime
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("чтение: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("эхо вернуло %q, ожидалось %q", got, want)
	}
}

// TestDialPicksTheRequestedNode — A34 в его L1-половине: два узла, два
// инбаунда, и соединение видно ровно на том, чей id назвали (§6.7).
func TestDialPicksTheRequestedNode(t *testing.T) {
	echo := echoServer(t)
	srvA, err := xraytest.NewServer(xraytest.Options{})
	if err != nil {
		t.Fatalf("инбаунд A: %v", err)
	}
	t.Cleanup(func() { srvA.Close() })
	srvB, err := xraytest.NewServer(xraytest.Options{UUID: "0f8a6d31-4c9c-4a2f-9c1e-0d2b3a4c5d6e"})
	if err != nil {
		t.Fatalf("инбаунд B: %v", err)
	}
	t.Cleanup(func() { srvB.Close() })

	e, err := New([]Node{nodeFor(srvA, "A"), nodeFor(srvB, "B")}, loopbackPhysical)
	if err != nil {
		t.Fatalf("движок: %v", err)
	}
	t.Cleanup(func() { e.Close() })

	for _, id := range []string{"A", "B"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) //hop:realtime
		conn, err := e.DialTCP(ctx, id, echo)
		cancel()
		if err != nil {
			t.Fatalf("узел %s: соединение не установилось: %v", id, err)
		}
		conn.Close()
	}
}

// TestDialThroughUnknownNodeIsNotFatal — вызов с чужим id это ошибка
// вызывающего, а не смерть узла: иначе опечатка убивала бы живой узел.
func TestDialThroughUnknownNodeIsNotFatal(t *testing.T) {
	e, err := New(nil, nil)
	if err != nil {
		t.Fatalf("движок: %v", err)
	}
	t.Cleanup(func() { e.Close() })

	_, err = e.DialTCP(context.Background(), "нет-такого", "203.0.113.1:80")
	var de *DialError
	if !asDialError(err, &de) {
		t.Fatalf("ошибка %v не классифицирована", err)
	}
	if de.Fatal() {
		t.Errorf("вердикт %v, ожидался безвредный: неизвестный узел — ошибка вызывающего", de.Kind)
	}
}

// TestDeadNodeGivesFatalVerdict — узел, которого нет в сети, обязан дать
// смертельный вердикт §6.15, и приходит он через OnFailure, а не из потока:
// поток видит только «closed pipe» и различить узел с сайтом не может
// (dialer.go). На этом вердикте стоит вся смерть по трафику (A5, A29).
func TestDeadNodeGivesFatalVerdict(t *testing.T) {
	// Порт, на котором заведомо никто не слушает.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("порт: %v", err)
	}
	dead := l.Addr().(*net.TCPAddr)
	l.Close()

	verdicts := make(chan *DialError, 8)
	e, err := NewWithConfig(Config{
		Nodes: []Node{{
			ID: "мёртвый", Protocol: "vless", Server: "127.0.0.1", Port: dead.Port,
			Transport: "raw", Security: "none",
			Params: map[string]string{"uuid": xraytest.DefaultUUID},
		}},
		OnFailure: func(de *DialError) { verdicts <- de },
		Physical:  loopbackPhysical,
	})
	if err != nil {
		t.Fatalf("движок: %v", err)
	}
	t.Cleanup(func() { e.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) //hop:realtime
	defer cancel()
	conn, err := e.DialTCP(ctx, "мёртвый", "203.0.113.1:80")
	if err == nil {
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) //hop:realtime
		conn.Write([]byte("ping"))
		conn.SetReadDeadline(time.Now().Add(10 * time.Second)) //hop:realtime
		conn.Read(make([]byte, 4))
		conn.Close()
	}

	select {
	case de := <-verdicts:
		if !de.Fatal() {
			t.Errorf("вердикт %v, ожидался смертельный (§6.15). Ошибка: %v", de.Kind, de.Err)
		}
		if de.Kind != health.DialTimeout {
			t.Errorf("вердикт %v, ожидался dial-timeout: до узла не дозвонились", de.Kind)
		}
		if de.NodeID != "мёртвый" {
			t.Errorf("вердикт приписан узлу %q, ожидался «мёртвый»", de.NodeID)
		}
	case <-time.After(10 * time.Second): //hop:realtime
		t.Fatal("отказ мёртвого узла не доехал до OnFailure — смерть по трафику не работает")
	}
}

// TestStreamErrorIsNotFatal — отказ, увиденный потоком, узел не убивает.
//
// Причина в dialer.go: «closed pipe» приходит и когда мёртв узел, и когда
// целевой сайт отказал в соединении. Считать это смертью значит убивать живой
// узел за чужой отказ — ровно то, что §6.15 запрещает (T20).
func TestStreamErrorIsNotFatal(t *testing.T) {
	// Порт, на котором заведомо никто не слушает.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("порт: %v", err)
	}
	dead := l.Addr().(*net.TCPAddr)
	l.Close()

	e, err := NewWithConfig(Config{Nodes: []Node{{
		ID: "dead", Protocol: "vless", Server: "127.0.0.1", Port: dead.Port,
		Transport: "raw", Security: "none",
		Params: map[string]string{"uuid": xraytest.DefaultUUID},
	}}, Physical: loopbackPhysical})
	if err != nil {
		t.Fatalf("движок: %v", err)
	}
	t.Cleanup(func() { e.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) //hop:realtime
	defer cancel()

	// Соединение отдаётся лениво (conn.go), поэтому отказ ищем на вводе-выводе,
	// а не только в Dial.
	conn, err := e.DialTCP(ctx, "dead", "203.0.113.1:80")
	if err == nil {
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) //hop:realtime
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))  //hop:realtime
		if _, werr := conn.Write([]byte("ping")); werr != nil {
			err = werr
		} else {
			_, err = conn.Read(make([]byte, 4))
		}
	}
	if err == nil {
		t.Fatal("мёртвый узел не дал ошибки ни на dial, ни на вводе-выводе")
	}

	var de *DialError
	if !asDialError(err, &de) {
		t.Fatalf("ошибка %v не классифицирована", err)
	}
	if de.Fatal() {
		t.Errorf("вердикт по ошибке потока — %v, ожидался безвредный: узел и сайт тут неразличимы", de.Kind)
	}
}

func asDialError(err error, out **DialError) bool {
	for err != nil {
		if de, ok := err.(*DialError); ok {
			*out = de
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// TestProbeDialDoesNotReportTraffic — W37, решение Р38.
//
// Проба обязана идти через outbound проверяемого узла (§6.7), то есть тем же
// путём, что трафик. Без метки её провал засчитался бы и в окно проб, и в
// счётчик ошибок трафика, а §5.4 требует двух **разных** счётчиков: узел умирал
// бы вдвое быстрее порога §6.3.
//
// Проверка построена как близнец TestDeadNodeGivesFatalVerdict: тот же мёртвый
// узел, тот же дозвон, разница ровно в одной метке на контексте. Вердикт при
// этом обязан вернуться вызывающему — отменяется рассылка, а не классификация.
func TestProbeDialDoesNotReportTraffic(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("порт: %v", err)
	}
	dead := l.Addr().(*net.TCPAddr)
	l.Close()

	verdicts := make(chan *DialError, 8)
	e, err := NewWithConfig(Config{
		Nodes: []Node{{
			ID: "проба", Protocol: "vless", Server: "127.0.0.1", Port: dead.Port,
			Transport: "raw", Security: "none",
			Params: map[string]string{"uuid": xraytest.DefaultUUID},
		}},
		OnFailure: func(de *DialError) { verdicts <- de },
		Physical:  loopbackPhysical,
	})
	if err != nil {
		t.Fatalf("движок: %v", err)
	}
	t.Cleanup(func() { e.Close() })

	// Соединение отдаётся лениво (conn.go): отказ узла приезжает на первом
	// вводе-выводе, а не из Dial. Проба идёт тем же путём и видит то же.
	ctx, cancel := context.WithTimeout(WithProbe(context.Background()), 10*time.Second) //hop:realtime
	defer cancel()
	conn, err := e.DialTCP(ctx, "проба", "203.0.113.1:80")
	if err != nil {
		t.Fatalf("Dial отказал сразу: %v — стенд не тот, что в TestDeadNodeGivesFatalVerdict", err)
	}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) //hop:realtime
	conn.Write([]byte("ping"))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second)) //hop:realtime
	_, ioErr := conn.Read(make([]byte, 4))
	conn.Close()

	if ioErr == nil {
		t.Fatal("мёртвый узел ответил — стенд не тот, что в TestDeadNodeGivesFatalVerdict")
	}

	// Вердикт вызывающему — да: Р38 отменяет рассылку, а не классификацию.
	// Без этого проба не отличила бы смерть узла от отказа целевого хоста.
	var de *DialError
	if !errors.As(ioErr, &de) {
		t.Fatalf("ошибка %v не несёт вердикта: проба не смогла бы отличить смерть узла от чужого отказа", ioErr)
	}

	// Рассылка в счётчик трафика — нет.
	select {
	case got := <-verdicts:
		t.Fatalf("провал пробы доехал до OnFailure (%v): §5.4 требует двух разных счётчиков, а вышел один", got)
	case <-time.After(2 * time.Second): //hop:realtime
	}
}
