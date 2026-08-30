package agent

// Сквозной путь «отказ трафика → живость» (W30, W31).
//
// Отличие от остальных тестов связки — в том, чего здесь нет. В harness_test.go
// движок поддельный, и это записано там намеренно: шаги 3–6 регистра проверяют
// арифметику владения инстансами, а не Xray. Строки W30 и W31 требуют ровно
// обратного: путь от датаплейна до `health.Manager` целиком, без единого мока
// на нём. Поддельный движок здесь проверял бы только то, что тест сам же и
// написал: фейк, который зовёт `onFailure`, доказывает существование фейка.
//
// Поэтому стенд собирает настоящее: gvisor поверх поддельного устройства,
// настоящий инстанс Xray на настоящем VLESS-инбаунде (`internal/xraytest`) и
// настоящую живость. Поддельны здесь ровно две вещи, и обе — вне проверяемого
// пути: устройство (TUN требует прав, §8.1) и пробер (иначе живость убила бы
// узел раньше трафика по своему собственному счёту, и вердикт по трафику стал
// бы неразличим).

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/faultinject"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/packettest"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/tunnel"
	"github.com/shafed/hop/internal/xraytest"
)

// Адреса стенда те же, что в internal/netstack: клиент за туннелем,
// «интернет» — документационная сеть RFC 5737.
var e2eClient = netip.MustParseAddrPort("10.255.0.2:5000")

// e2eWait — потолок ожидания чужой горутины. Настоящие часы: ждём мы работу
// Xray и gvisor, а не время (тот же приём, что у packettest.WaitTimeout).
const e2eWait = 10 * time.Second //hop:realtime

// e2eNode — узел стенда: адрес, к которому связка будет дозваниваться.
type e2eNode struct {
	id   string
	addr string // host:port
	uuid string
}

// e2eRig — связка, собранная на настоящем движке.
type e2eRig struct {
	t    *testing.T
	a    *Agent
	hm   *health.Manager
	tr   *fakeTransport
	clk  *clock.Fake
	prob *scriptProber
}

// newE2ERig собирает связку с настоящим Xray.
//
// `NewXray` не подставляется: умолчание `New` строит `engine.NewWithConfig` и
// вешает на него единственный в продукте путь до `ReportFailure` — замыкание в
// wire.go. Подставить сюда фабрику значило бы вырезать проверяемый шов.
func newE2ERig(t *testing.T, nodes ...e2eNode) *e2eRig {
	t.Helper()

	clk := clock.NewFake(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	st, err := store.Open(t.TempDir(), clk)
	if err != nil {
		t.Fatalf("стор не открылся: %v", err)
	}

	sn := make([]store.Node, 0, len(nodes))
	order := make([]string, 0, len(nodes))
	for _, n := range nodes {
		host, port := splitHostPort(t, n.addr)
		sn = append(sn, store.Node{
			ID: n.id, GroupID: "g1", Protocol: "vless",
			Server: host, Port: port, Transport: "raw", Security: "none",
			Supported: true,
			Params:    map[string]string{"uuid": n.uuid},
		})
		order = append(order, n.id)
	}
	if err := st.Apply("g1", store.Merged{Added: order, Nodes: sn, Order: order}); err != nil {
		t.Fatalf("стор не принял узлы: %v", err)
	}

	r := &e2eRig{t: t, tr: newFakeTransport(), clk: clk, prob: newScriptProber()}
	// Пробер отвечает «жив» на всё: живость обязана узнать об отказе от
	// трафика, а не от собственной пробы. Иначе W30 зеленел бы и с оборванной
	// проводкой — узел умер бы по окну проб.
	r.hm = health.New(health.Config{Clock: clk, Prober: r.prob})

	a, err := New(Config{
		Store:    st,
		Health:   r.hm,
		Trans:    r.tr,
		Clock:    clk,
		Resolver: &servfailResolver{},
		Physical: func() (string, error) { return "lo", nil },
		Params:   tunnel.Params{Name: "hop0", MTU: 1400, Addr: "10.255.0.1/24", Table: 8420},
	})
	if err != nil {
		t.Fatalf("связка не собралась: %v", err)
	}
	r.a = a
	t.Cleanup(func() { _ = a.Close() })

	if err := a.ReloadNodes(); err != nil {
		t.Fatalf("узлы не доехали из стора в живость: %v", err)
	}
	return r
}

// start запускает живость, дожидается стартового обхода и поднимает туннель.
func (r *e2eRig) start() {
	r.t.Helper()

	r.a.Start()
	done := make(chan struct{})
	go func() { r.hm.WaitRound(1); close(done) }()
	select {
	case <-done:
	case <-time.After(e2eWait): //hop:realtime
		r.t.Fatal("стартовый обход не состоялся")
	}
	if s := r.a.Snapshot(); s.Active == "" {
		r.t.Fatalf("активного узла нет после обхода, фаза %q — стенд не дошёл до состояния, в котором трафик осмыслен", s.Traffic)
	}
	if err := r.a.Up(); err != nil {
		r.t.Fatalf("Up: %v", err)
	}
}

// dev — устройство, на которое смотрит стек.
func (r *e2eRig) dev() *packettest.FakeDevice {
	r.t.Helper()
	d := r.tr.device()
	if d == nil {
		r.t.Fatal("туннель не поднят: устройства нет")
	}
	return d
}

// traffic — попытка соединения из датаплейна: SYN в стек.
//
// Одного SYN достаточно, и это свойство продукта, а не упрощение стенда:
// форвардер gvisor отдаёт SYN-ACK только из CreateEndpoint, поэтому исходящее
// соединение устанавливается раньше рукопожатия с приложением
// (internal/netstack/tcp.go). Дозвон до узла случается, даже если клиент не
// пришлёт больше ни байта.
func (r *e2eRig) traffic(dst netip.AddrPort, port uint16, seq uint32) {
	src := netip.AddrPortFrom(e2eClient.Addr(), port)
	r.dev().Inject(packettest.TCPSyn(src, dst, seq))
}

// nodeHealth — живость узла на этот момент.
func (r *e2eRig) nodeHealth(id string) health.NodeHealth {
	r.t.Helper()
	h, ok := r.hm.Snapshot().Node(id)
	if !ok {
		r.t.Fatalf("узла %q нет в живости", id)
	}
	return h
}

// waitTrafficFailures ждёт, пока счётчик ошибок трафика узла не дойдёт до n.
func (r *e2eRig) waitTrafficFailures(id string, n int) health.NodeHealth {
	r.t.Helper()

	deadline := time.Now().Add(e2eWait) //hop:realtime
	var h health.NodeHealth
	for time.Now().Before(deadline) { //hop:realtime
		h = r.nodeHealth(id)
		if h.TrafficFailures >= n {
			return h
		}
		time.Sleep(5 * time.Millisecond) //hop:realtime
	}
	r.t.Fatalf("счётчик ошибок трафика узла %q остался %d, ожидалось %d: "+
		"отказ дозвона из датаплейна до живости не дошёл (§6.15, W30)", id, h.TrafficFailures, n)
	return h
}

// TestW30DialFailureFromDataplaneReachesHealth — W30: отказ дозвона до узла,
// начатый трафиком из датаплейна, доходит до живости и уменьшает её.
//
// Что делает проверку не тавтологией: живость здесь **уверена**, что узел жив.
// Пробер отвечает успехом, узел выбран активным, и единственный источник
// плохой новости — сам трафик. Путь, который при этом обязан сработать целиком:
// gvisor → agent/dialer.go → holder → engine.DialTCP → перехваченный системный
// диалер Xray (тег `node-*`) → classify.go → замыкание в wire.go →
// health.ReportFailure.
//
// Порог §6.3 — k=2, поэтому SYN'ов два: первый доказывает, что вердикт доехал,
// второй — что он именно «уменьшает живость», а не оседает в счётчике.
func TestW30DialFailureFromDataplaneReachesHealth(t *testing.T) {
	dead := closedAddr(t)
	r := newE2ERig(t, e2eNode{id: "мёртвый", addr: dead, uuid: xraytest.DefaultUUID})
	r.start()

	if h := r.nodeHealth("мёртвый"); h.TrafficFailures != 0 || h.State == health.Dead {
		t.Fatalf("до трафика узел уже %v с %d ошибками — стенд начал не с чистого состояния",
			h.State, h.TrafficFailures)
	}

	web := netip.MustParseAddrPort("203.0.113.7:80")
	r.traffic(web, 5001, 42)
	h := r.waitTrafficFailures("мёртвый", 1)
	if h.LastError == "" {
		t.Error("вердикт доехал без причины: в снимке пусто, а §6.15 требует названного вида отказа")
	}

	r.traffic(web, 5002, 43)
	h = r.waitTrafficFailures("мёртвый", 2)
	if h.State != health.Dead {
		t.Errorf("узел %v после %d ошибок трафика при k=%d — живость от отказов трафика не уменьшилась (§6.3)",
			h.State, h.TrafficFailures, health.DefaultK)
	}

	// Вторая половина строки: «уменьшает живость» наблюдаемо снаружи, а не
	// только в счётчике. Живых узлов больше нет, и связка обязана это сказать.
	if s := r.a.Snapshot(); s.Active != "" {
		t.Errorf("активен %q при мёртвом единственном узле: отказ трафика не дошёл до выбора", s.Active)
	}
}

// TestW31TargetFailureThroughLiveNodeKeepsHealth — W31: отказ целевого сайта
// через живой узел живость не трогает, и это проверено сквозь связку.
//
// T20 в `internal/l2` держит то же свойство на движке и живости, сшитых
// стендом. Здесь сшивает продукт: тот же путь идёт через `agent`, через
// настоящий стек и через единственный в продукте call-site `ReportFailure`.
// Разница не косметическая — атрибуция отказа по тегу outbound'а
// (`internal/engine/dialer.go`) есть ровно то, что отделяет «узел не отозвался»
// от «сайт не отозвался», и проверить её можно только там, где оба дозвона
// идут через один перехваченный диалер.
//
// Стенд обязан доказать, что трафик действительно дошёл до узла: без этого
// «живость не тронута» одинаково зелено и когда механизм работает, и когда до
// узла не дошло ни байта. Доказывает инжектор перед инбаундом — он считает
// принятые соединения.
//
// Замеренная граница стенда: адрес отказавшего сайта не может быть локальным.
// §6.10 выпускает 127.0.0.0/8 мимо туннеля, и `resolveRouting` подмешивает это
// правило к любой конфигурации, поэтому SYN на закрытый порт loopback уходит в
// bypass и до узла не доходит вовсе (замерено: инжектор видел одно соединение
// вместо трёх). Отсюда разделение: из датаплейна идёт запрос на
// документационный адрес RFC 5737 — он проксируется, — а отказ сайта, который
// обязан быть мгновенным и наблюдаемым, идёт через тот же диалер, который
// netstack получает в `Up`.
func TestW31TargetFailureThroughLiveNodeKeepsHealth(t *testing.T) {
	srv, err := xraytest.NewServer(xraytest.Options{})
	if err != nil {
		t.Fatalf("инбаунд: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	inj, err := faultinject.New(srv.Addr())
	if err != nil {
		t.Fatalf("инжектор: %v", err)
	}
	t.Cleanup(func() { inj.Close() })

	r := newE2ERig(t, e2eNode{id: "живой", addr: inj.Addr(), uuid: srv.UUID()})
	r.start()

	// Половина первая — из датаплейна. Узел обязан получить соединение: то,
	// что дальше сайт недостижим, — уже не его вина и не его вердикт.
	r.traffic(netip.MustParseAddrPort("203.0.113.7:80"), 5001, 42)
	if n := waitConns(t, inj, 1); n < 1 {
		t.Fatalf("узел не принял ни одного соединения из датаплейна: проверять нечего")
	}

	// Половина вторая — отказ сайта, мгновенный и наблюдаемый. Диалер тот же
	// самый, что netstack получает в Up (wire.go), и живость в нём настоящая.
	d := newDialer(r.hm, r.a.engine)
	deadSite := mustAddrPort(t, closedAddr(t))
	streamErr := talkTo(t, d, deadSite, "GET / HTTP/1.0\r\n\r\n")
	if streamErr == nil {
		t.Fatal("отказ целевого хоста не дал ошибки вовсе — стенд собран не так")
	}
	var de *engine.DialError
	if errors.As(streamErr, &de) && de.Fatal() {
		t.Errorf("вердикт по отказу целевого хоста — %v, узел от этого умирать не должен (§6.15)", de.Kind)
	}

	// Половина третья — буквальный 502 из §8.2: сайт ответил, и ответ плохой.
	// Ошибки здесь нет вовсе, и это тоже утверждение: связка не выдумывает
	// отказ узла из содержимого чужого ответа.
	site := badGatewayServer(t)
	conn, err := d.DialTCP(mustAddrPort(t, site))
	if err != nil {
		// Живость в диагностике обязательна: самый вероятный способ сюда
		// попасть — узел, убитый чужим отказом, и тогда «не дозвонились» само
		// по себе назвало бы следствие вместо причины.
		t.Fatalf("через живой узел не дозвонились до сайта: %v (живость узла: %+v)",
			err, r.nodeHealth("живой"))
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(e2eWait)) //hop:realtime
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", site); err != nil {
		t.Fatalf("запрос к сайту не ушёл: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ответ сайта не прочитан: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("сайт ответил %d, ожидалось 502 — стенд собран не так", resp.StatusCode)
	}

	// Трафик действительно ходил через узел: иначе «живость не тронута»
	// доказывало бы только то, что стенд простоял без дела.
	if n := waitConns(t, inj, 3); n < 3 {
		t.Fatalf("узел принял %d соединений, ожидалось не меньше 3: трафик до узла не дошёл", n)
	}

	// А теперь собственно утверждение строки.
	h := r.nodeHealth("живой")
	if h.TrafficFailures != 0 {
		t.Errorf("счётчик ошибок трафика узла = %d (%q), ожидался 0: живой узел умирает за чужой отказ (§6.15)",
			h.TrafficFailures, h.LastError)
	}
	if h.State == health.Dead {
		t.Errorf("узел мёртв после отказа целевого сайта: %+v", h)
	}
	if s := r.a.Snapshot(); s.Active != "живой" {
		t.Errorf("активен %q, ожидался «живой»: переключаться не с чего", s.Active)
	}
}

// talkTo дозванивается через связку и пробует поговорить.
//
// Отказ ищется и на дозвоне, и на вводе-выводе: соединение Xray отдаётся
// лениво (internal/engine/conn.go), и отказ сайта приезжает первой записью или
// первым чтением, а не из Dial.
func talkTo(t *testing.T, d *dialer, dst netip.AddrPort, req string) error {
	t.Helper()

	conn, err := d.DialTCP(dst)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(e2eWait)) //hop:realtime
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	_, err = conn.Read(make([]byte, 64))
	return err
}

// closedAddr — адрес, на котором заведомо никто не слушает.
func closedAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("порт: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// badGatewayServer — «целевой сайт», отвечающий 502 и ничем больше.
func badGatewayServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("сайт не поднялся: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(e2eWait)) //hop:realtime
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimSpace(line) == "" {
						break
					}
				}
				_, _ = c.Write([]byte("HTTP/1.0 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			}()
		}
	}()
	return l.Addr().String()
}

// waitConns ждёт, пока инжектор не примет n соединений.
func waitConns(t *testing.T, inj *faultinject.Injector, n int) int {
	t.Helper()

	deadline := time.Now().Add(e2eWait) //hop:realtime
	got := inj.Conns()
	for got < n && time.Now().Before(deadline) { //hop:realtime
		time.Sleep(5 * time.Millisecond) //hop:realtime
		got = inj.Conns()
	}
	return got
}

func mustAddrPort(t *testing.T, addr string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		t.Fatalf("адрес %q: %v", addr, err)
	}
	return ap
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	ap := mustAddrPort(t, addr)
	return ap.Addr().String(), int(ap.Port())
}
