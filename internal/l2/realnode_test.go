package l2

import (
	"context"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time" //hop:realtime

	xlog "github.com/xtls/xray-core/common/log"

	"github.com/shafed/hop/internal/engine"
	"github.com/shafed/hop/internal/health"
)

// xrayLog ловит сообщения Xray. Без него смоук бесполезен как диагностика:
// поток отдаёт «closed pipe», а настоящая причина — рукопожатие REALITY,
// отказ узла, отсутствие маршрута — живёт только в логе (engine/dialer.go).
type xrayLog struct {
	t  *testing.T
	mu sync.Mutex
	ms []string
}

func (l *xrayLog) Handle(m xlog.Message) {
	s := m.String()
	l.mu.Lock()
	l.ms = append(l.ms, s)
	l.mu.Unlock()
}

func (l *xrayLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.ms, "\n")
}

// Смоук против настоящего узла. Не входит ни в один прогон CI и включается
// только переменной окружения:
//
//	HOP_TEST_NODE='vless://...' go test -run TestRealNode ./internal/l2
//
// **Почему это не тест, а смоук.** Настоящий узел нельзя перевести в
// blackhole по команде, он живёт в чужой сети и падает не тогда, когда нужно
// тесту. Всё, что проверяется таблицей §8.3, проверяется на локальных
// инбаундах за инжектором — там отказ управляем, а прогон воспроизводим.
//
// **Что тогда он даёт.** Ровно то, чего локальный инбаунд дать не может: он
// настроен нами же, а значит согласован с нашим конфигом по построению.
// Настоящий узел проверяет разбор ссылки, генерацию streamSettings для REALITY
// (включая молодой `pqv`) и совместимость нашей сборки Xray с сервером, который
// мы не настраивали.
//
// **Ссылка не хранится в репозитории** (§6.14): в ней `uuid` и ключи.

// TestRealNodeSmoke ходит в интернет через узел из HOP_TEST_NODE.
func TestRealNodeSmoke(t *testing.T) {
	link := os.Getenv("HOP_TEST_NODE")
	if link == "" {
		t.Skip("HOP_TEST_NODE не задан — смоук против настоящего узла пропущен")
	}

	node, err := parseVLESS(link)
	if err != nil {
		t.Fatalf("ссылка не разобралась: %v", err)
	}
	t.Logf("узел: %s:%d, транспорт %s, security %s", node.Server, node.Port, node.Transport, node.Security)

	verdicts := make(chan *engine.DialError, 8)
	eng, err := engine.NewWithConfig(engine.Config{
		Nodes:     []engine.Node{node},
		OnFailure: func(de *engine.DialError) { verdicts <- de },
	})
	if err != nil {
		t.Fatalf("движок не собрался: %v", err)
	}
	defer eng.Close()

	// Перехват лога ставится ПОСЛЕ старта инстанса: app/log регистрирует свой
	// обработчик при старте и затирает чужой, поставленный раньше.
	logs := &xrayLog{t: t}
	xlog.RegisterHandler(logs)

	// Проба идёт тем же путём, что и трафик (§6.7) — через outbound узла.
	target := &health.HTTPTarget{
		URL: "http://cp.cloudflare.com/generate_204",
		Dial: func(ctx context.Context, nodeID, network, addr string) (net.Conn, error) {
			return eng.DialTCP(ctx, nodeID, addr)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second) //hop:realtime
	defer cancel()

	rtt, err := target.Check(ctx, node.ID)
	if err != nil {
		diag := logs.text()

		// Среда с перехватом TLS. REALITY именно для этого и сделан: он видит
		// не тот сертификат и отказывается продолжать. Красить смоук нечем —
		// узел тут ни при чём, и никакая правка конфига это не изменит.
		if strings.Contains(diag, "received real certificate") {
			t.Skipf("среда перехватывает TLS на пути к узлу — REALITY отказался, и правильно сделал.\n"+
				"Проверить можно так: openssl s_client -connect %s:%d -servername %s\n"+
				"Если issuer сертификата — не удостоверяющий центр настоящего сайта, смоук здесь не прогнать.",
				node.Server, node.Port, node.Param("sni"))
		}

		select {
		case de := <-verdicts:
			t.Fatalf("через настоящий узел не прошло: %v (вердикт §6.15: %v)\nЛог Xray:\n%s", err, de.Kind, diag)
		default:
			t.Fatalf("через настоящий узел не прошло: %v\nЛог Xray:\n%s", err, diag)
		}
	}
	t.Logf("сквозной путь через настоящий узел: %v", rtt)

	select {
	case de := <-verdicts:
		t.Errorf("успешная проба, но пришёл вердикт отказа: %v", de)
	default:
	}
}

// parseVLESS — минимальный разбор ссылки, только для смоука.
//
// Настоящий каскад §6.12 — этап 7; здесь нужно ровно столько, чтобы собрать
// один outbound, и жить этому коду до появления настоящего парсера.
func parseVLESS(link string) (engine.Node, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return engine.Node{}, err
	}
	if u.Scheme != "vless" {
		return engine.Node{}, errUnsupportedScheme
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return engine.Node{}, err
	}

	q := u.Query()
	params := map[string]string{"uuid": u.User.Username()}
	for _, k := range []string{"flow", "sni", "pbk", "sid", "spx", "fp", "pqv", "host", "path", "serviceName", "alpn"} {
		if v := q.Get(k); v != "" {
			params[k] = v
		}
	}

	transport := q.Get("type")
	if transport == "" {
		transport = "tcp"
	}
	security := q.Get("security")
	if security == "" || security == "0" || security == "false" {
		security = "none"
	}

	return engine.Node{
		ID:        "real",
		Protocol:  "vless",
		Server:    u.Hostname(),
		Port:      port,
		Transport: transport,
		Security:  security,
		Params:    params,
	}, nil
}

type smokeError string

func (e smokeError) Error() string { return string(e) }

const errUnsupportedScheme = smokeError("l2: ссылка не vless://")
