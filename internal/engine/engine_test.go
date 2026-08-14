package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time" //hop:realtime

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	// Инбаунд VLESS нужен только стенду §8.1: в продукте инбаундов нет
	// вообще (§5.3), поэтому регистрация живёт в тесте, а не в registry.go.
	_ "github.com/xtls/xray-core/proxy/vless/inbound"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/faultinject"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/node"
)

const testUUID = "6c8f2f2c-3e34-4b2a-9a2f-9d3f7a1b5c11"

// TestStartBringsUpInstance — самое дешёвое, что обязано работать: конфиг,
// собранный buildConfig на фиктивном узле, поднимается настоящим core.New.
// Узел никуда не ведёт, соединений не открывается: проверяется сборка.
func TestStartBringsUpInstance(t *testing.T) {
	e := newEngine(t, fakeNode("n1", netip.MustParseAddrPort("127.0.0.1:1")))
	if err := e.Start(); err != nil {
		t.Fatalf("старт: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("останов: %v", err)
	}
}

// До Start любой Dial обязан отказать, а не пойти напрямую: молчаливый обход
// туннеля — fail-open, запрещённый §5.6.
func TestDialBeforeStartFails(t *testing.T) {
	e := newEngine(t, fakeNode("n1", netip.MustParseAddrPort("127.0.0.1:1")))
	e.SetActive("n1")

	if _, err := e.DialTCP(netip.MustParseAddrPort("93.184.216.34:80")); err == nil {
		t.Fatal("DialTCP до Start прошёл")
	}
	if _, err := e.DialUDP(netip.MustParseAddrPort("127.0.0.1:5353")); err == nil {
		t.Fatal("DialUDP до Start прошёл")
	}
	if _, err := e.DialDirect(context.Background(), netip.MustParseAddrPort("127.0.0.1:80")); err == nil {
		t.Fatal("DialDirect до Start прошёл")
	}
}

// Без активного узла трафик тоже обязан отказать: §5.6 не знает состояния
// «некуда, значит напрямую».
func TestDialWithoutActiveNodeFails(t *testing.T) {
	e := newEngine(t, fakeNode("n1", netip.MustParseAddrPort("127.0.0.1:1")))
	if err := e.Start(); err != nil {
		t.Fatalf("старт: %v", err)
	}
	t.Cleanup(func() { e.Close() })

	if _, err := e.DialTCP(netip.MustParseAddrPort("127.0.0.1:80")); err == nil {
		t.Fatal("DialTCP без активного узла прошёл")
	}
}

// Сквозной путь: агент реально устанавливает VLESS-соединение с настоящим
// инбаундом Xray в том же процессе (§8.1, «тестовые узлы»).
func TestDialThroughRealVLESSNode(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(site.Close)

	rec := &recorder{}
	e, _ := nodeEngine(t, rec)
	e.SetActive("n1")

	status := httpThrough(t, e, siteAddr(t, site))
	if status != "204" {
		t.Fatalf("сайт ответил %q, ожидалось 204", status)
	}
	if got := rec.successes(); got == 0 {
		t.Fatal("успешное проксирование не дошло до health")
	}
	if got := rec.failures(); len(got) != 0 {
		t.Fatalf("живой узел получил отказы: %v", got)
	}
}

// T20 (§8.2). Отказ целевого хоста узел не убивает: ни 502, ни RST от сайта
// после успешного проксирования, ни отказ сайта принять соединение. Всё это
// проходит через живой узел, и узел остаётся жив.
//
// Развилка — classify; при HOP_DISABLE=error_classify смертью становится любой
// отказ, и тест обязан покраснеть.
func TestT20SiteErrorDoesNotKillNode(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	t.Cleanup(site.Close)

	rec := &recorder{}
	e, _ := nodeEngine(t, rec)
	e.SetActive("n1")

	if status := httpThrough(t, e, siteAddr(t, site)); status != "502" {
		t.Fatalf("сайт ответил %q, ожидалось 502", status)
	}
	if got := rec.failures(); len(got) != 0 {
		t.Fatalf("502 от сайта убил узел: %v", got)
	}

	// Сайт оборвал соединение RST-ом посреди тела ответа. Проксирование к
	// этому моменту уже состоялось — отказ принадлежит сайту, не узлу.
	c, err := e.DialTCP(rstSite(t))
	if err != nil {
		t.Fatalf("соединение через узел: %v", err)
	}
	c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	io.ReadAll(c)
	c.Close()
	if got := rec.failures(); len(got) != 0 {
		t.Fatalf("RST от сайта убил узел: %v", got)
	}

	// Сайт вовсе не принял соединение — connection refused из §6.15, который
	// назван там отказом целевого хоста.
	c, err = e.DialTCP(closedPort(t))
	if err != nil {
		t.Fatalf("соединение через узел: %v", err)
	}
	c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	io.ReadAll(c)
	c.Close()
	if got := rec.failures(); len(got) != 0 {
		t.Fatalf("отказ сайта убил узел: %v", got)
	}

	if rec.successes() == 0 {
		t.Fatal("узел не подал признаков жизни, тест ничего не доказывает")
	}
}

// Обратная сторона T20: отказ самого узла обязан быть смертью, иначе
// классификация тривиально проходит, ничего не различая. Узел ведёт в
// закрытый порт — до него не доходят вовсе (§6.15, DialTimeout).
func TestDeadNodeIsClassifiedAsDeath(t *testing.T) {
	rec := &recorder{}
	e := newEngineWith(t, rec, fakeNode("n1", closedPort(t)))
	if err := e.Start(); err != nil {
		t.Fatalf("старт: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	e.SetActive("n1")

	c, err := e.DialTCP(netip.MustParseAddrPort("93.184.216.34:80"))
	if err == nil {
		c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		io.ReadAll(c)
		c.Close()
	}

	got := rec.failures()
	if len(got) == 0 {
		t.Fatal("мёртвый узел не дал ни одного отказа")
	}
	if got[0] != health.DialTimeout {
		t.Fatalf("вид отказа %v, ожидался %v", got[0], health.DialTimeout)
	}
}

// Узел за инжектором отказов (§8.1): сервер снят, соединение принято и
// немедленно оборвано. Это другая ветка §6.15, чем закрытый порт, и другой
// путь в коде — здесь стенд и движок встречаются по-настоящему.
func TestNodeTornByInjectorIsDeath(t *testing.T) {
	fi, err := faultinject.New(vlessNode(t), faultinject.Config{}, clock.System{})
	if err != nil {
		t.Fatalf("стенд: %v", err)
	}
	t.Cleanup(func() { fi.Close() })
	fi.SetMode(faultinject.RST)

	rec := &recorder{}
	e := newEngineWith(t, rec, vlessNodeSpec("n1", fi.Addr()))
	if err := e.Start(); err != nil {
		t.Fatalf("старт: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	e.SetActive("n1")

	c, err := e.DialTCP(netip.MustParseAddrPort("93.184.216.34:80"))
	if err == nil {
		c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		io.ReadAll(c)
		c.Close()
	}

	got := rec.failures()
	if len(got) == 0 {
		t.Fatal("снятый узел не дал ни одного отказа")
	}
	if got[0] != health.HandshakeFailed {
		t.Fatalf("вид отказа %v, ожидался %v", got[0], health.HandshakeFailed)
	}
}

// direct обязан ходить мимо узлов: на нём стоит bootstrap §5.7а, и если он
// пойдёт через узел, на старте получится петля.
func TestDialDirectBypassesNodes(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(site.Close)

	rec := &recorder{}
	// Узел ведёт в закрытый порт: если direct пойдёт через него, ответа не
	// будет вовсе.
	e := newEngineWith(t, rec, fakeNode("n1", closedPort(t)))
	if err := e.Start(); err != nil {
		t.Fatalf("старт: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	e.SetActive("n1")

	c, err := e.DialDirect(context.Background(), siteAddr(t, site))
	if err != nil {
		t.Fatalf("direct: %v", err)
	}
	defer c.Close()
	if status := request(t, c); status != "204" {
		t.Fatalf("direct получил %q, ожидалось 204", status)
	}
	if got := rec.failures(); len(got) != 0 {
		t.Fatalf("direct отчитался в health за узел: %v", got)
	}
	if rec.successes() != 0 {
		t.Fatal("direct отчитался успехом за узел")
	}
}

// SetActive меняет тег, а не конфиг: два узла живут в одном экземпляре Xray
// одновременно, и переключение не пересобирает движок (§5.5).
func TestSetActivePicksNodeWithoutRebuild(t *testing.T) {
	first := vlessNode(t)
	second := vlessNode(t)

	rec := &recorder{}
	e := newEngineWith(t, rec,
		vlessNodeSpec("n1", first),
		vlessNodeSpec("n2", second))
	if err := e.Start(); err != nil {
		t.Fatalf("старт: %v", err)
	}
	t.Cleanup(func() { e.Close() })

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(site.Close)

	e.SetActive("n1")
	if status := httpThrough(t, e, siteAddr(t, site)); status != "204" {
		t.Fatalf("через n1 получено %q", status)
	}
	e.SetActive("n2")
	if e.Active() != "n2" {
		t.Fatalf("активный узел %q", e.Active())
	}
	if status := httpThrough(t, e, siteAddr(t, site)); status != "204" {
		t.Fatalf("через n2 получено %q", status)
	}
}

// UDP идёт через тот же узел одним PacketConn на исходный порт клиента: из
// этого получается full-cone (§5.3), и ответы приходят со всех адресов, куда
// клиент писал, а не только с первого.
func TestDialUDPServesEveryDestination(t *testing.T) {
	first, second := udpEcho(t), udpEcho(t)

	rec := &recorder{}
	e, _ := nodeEngine(t, rec)
	e.SetActive("n1")

	pc, err := e.DialUDP(netip.MustParseAddrPort("10.0.0.5:44444"))
	if err != nil {
		t.Fatalf("UDP через узел: %v", err)
	}
	defer pc.Close()

	seen := map[netip.AddrPort]bool{}
	for _, dst := range []netip.AddrPort{first, second} {
		if _, err := pc.WriteTo([]byte("ping"), net.UDPAddrFromAddrPort(dst)); err != nil {
			t.Fatalf("запись на %v: %v", dst, err)
		}
		pc.SetReadDeadline(time.Now().Add(5 * time.Second)) //hop:realtime
		buf := make([]byte, 64)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ответ от %v: %v", dst, err)
		}
		if string(buf[:n]) != "ping" {
			t.Fatalf("от %v пришло %q", from, buf[:n])
		}
		addr, _ := netip.ParseAddrPort(from.String())
		seen[addr] = true
	}
	if !seen[first] || !seen[second] {
		t.Fatalf("ответы пришли не со всех адресов: %v", seen)
	}
	if got := rec.failures(); len(got) != 0 {
		t.Fatalf("живой узел получил отказы на UDP: %v", got)
	}
}

// Проба ходит через указанный узел, а не через активный (§6.7).
func TestDialViaIgnoresActive(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(site.Close)

	rec := &recorder{}
	e, _ := nodeEngine(t, rec)
	// Активного узла нет вовсе: проба обязана дойти и без него.
	c, err := e.DialVia(context.Background(), "n1", siteAddr(t, site))
	if err != nil {
		t.Fatalf("проба: %v", err)
	}
	defer c.Close()
	if status := request(t, c); status != "204" {
		t.Fatalf("проба получила %q", status)
	}

	if _, err := e.DialVia(context.Background(), "нет-такого", siteAddr(t, site)); err == nil {
		t.Fatal("проба через неизвестный узел прошла")
	}
}

// --- обвязка ---

func newEngine(t *testing.T, nodes ...node.Node) *Engine {
	t.Helper()
	return newEngineWith(t, health.NopReporter{}, nodes...)
}

func newEngineWith(t *testing.T, rep health.Reporter, nodes ...node.Node) *Engine {
	t.Helper()
	e, err := New(nodes, Options{}, rep, clock.System{})
	if err != nil {
		t.Fatalf("сборка движка: %v", err)
	}
	return e
}

// nodeEngine — запущенный движок против настоящего VLESS-инбаунда.
func nodeEngine(t *testing.T, rep health.Reporter) (*Engine, netip.AddrPort) {
	t.Helper()
	addr := vlessNode(t)
	e := newEngineWith(t, rep, vlessNodeSpec("n1", addr))
	if err := e.Start(); err != nil {
		t.Fatalf("старт: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e, addr
}

func vlessNodeSpec(id string, addr netip.AddrPort) node.Node {
	return node.Node{
		ID:        id,
		Protocol:  node.VLESS,
		Server:    addr.Addr().String(),
		Port:      addr.Port(),
		Transport: node.Raw,
		Security:  node.SecNone,
		UserID:    testUUID,
		Supported: true,
	}
}

func fakeNode(id string, addr netip.AddrPort) node.Node { return vlessNodeSpec(id, addr) }

// vlessNode поднимает настоящий VLESS-инбаунд Xray в этом же процессе:
// свободный выход наружу через freedom. Это «узел» стенда §8.1.
func vlessNode(t *testing.T) netip.AddrPort {
	t.Helper()
	port := freePort(t)
	cfg := fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "inbounds": [{
	    "tag": "in",
	    "listen": "127.0.0.1",
	    "port": %d,
	    "protocol": "vless",
	    "settings": {"clients": [{"id": %q}], "decryption": "none"}
	  }],
	  "outbounds": [{"tag": "out", "protocol": "freedom"}]
	}`, port, testUUID)

	pb, err := serial.LoadJSONConfig(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("конфиг узла: %v", err)
	}
	inst, err := core.New(pb)
	if err != nil {
		t.Fatalf("сборка узла: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("старт узла: %v", err)
	}
	t.Cleanup(func() { inst.Close() })
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("порт: %v", err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// rstSite — сайт, который отвечает и обрывает соединение RST-ом, не дописав
// обещанное тело. Проксирование к этому моменту состоялось, отказ — сайта.
func rstSite(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("сайт: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c.Read(make([]byte, 512))
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nначало"))
				c.(*net.TCPConn).SetLinger(0)
				c.Close()
			}()
		}
	}()
	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("адрес сайта: %v", err)
	}
	return addr
}

// udpEcho — датаграммный собеседник за узлом.
func udpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("эхо UDP: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("адрес эха UDP: %v", err)
	}
	return addr
}

// closedPort — адрес, на котором заведомо никто не слушает.
func closedPort(t *testing.T) netip.AddrPort {
	t.Helper()
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), freePort(t))
}

func siteAddr(t *testing.T, s *httptest.Server) netip.AddrPort {
	t.Helper()
	addr, err := netip.ParseAddrPort(strings.TrimPrefix(s.URL, "http://"))
	if err != nil {
		t.Fatalf("адрес сайта: %v", err)
	}
	return addr
}

// httpThrough ходит на сайт через активный узел и отдаёт код ответа.
func httpThrough(t *testing.T, e *Engine, dst netip.AddrPort) string {
	t.Helper()
	c, err := e.DialTCP(dst)
	if err != nil {
		t.Fatalf("соединение через узел: %v", err)
	}
	defer c.Close()
	return request(t, c)
}

func request(t *testing.T, c net.Conn) string {
	t.Helper()
	req := "GET / HTTP/1.1\r\nHost: site\r\nConnection: close\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatalf("запрос: %v", err)
	}
	body, err := io.ReadAll(c)
	if err != nil && !strings.Contains(err.Error(), "closed") {
		t.Fatalf("ответ: %v", err)
	}
	line, _, _ := bytes.Cut(body, []byte("\r\n"))
	fields := strings.Fields(string(line))
	if len(fields) < 2 {
		t.Fatalf("ответ не похож на HTTP: %q", body)
	}
	return fields[1]
}

// recorder — тестовый health.Reporter. Свои ReportFailure/ReportSuccess он
// объявляет, но не зовёт: линт cmd/reportlint следит именно за вызовами.
type recorder struct {
	mu   sync.Mutex
	fail []health.FailureKind
	ok   int
	rtts []time.Duration
}

func (r *recorder) ReportFailure(_ string, kind health.FailureKind) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fail = append(r.fail, kind)
}

func (r *recorder) ReportSuccess(_ string, rtt time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ok++
	r.rtts = append(r.rtts, rtt)
}

func (r *recorder) failures() []health.FailureKind {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]health.FailureKind(nil), r.fail...)
}

func (r *recorder) successes() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ok
}
