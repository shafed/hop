// Package xraytest — настоящие инбаунды Xray в том же процессе теста (§8.1).
//
// Пакет намеренно **не импортирует testing**: им пользуются и L2-тесты, и
// бенчмарк B2, а тестовые флаги в бинаре бенчмарка не нужны — по той же
// причине, по которой FakePacketDevice живёт отдельно от internal/packet.
//
// Стенд даёт узел, к которому агент подключается по-настоящему: VLESS-инбаунд
// плюс freedom-outbound, то есть полный путь «клиент → узел → интернет» без
// единого мока между netstack и узлом (§8.3).
package xraytest

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// Server — запущенный VLESS-инбаунд.
type Server struct {
	inst *core.Instance
	addr string
	uuid string
}

// Options — как поднять инбаунд.
type Options struct {
	// UUID пользователя. Пусто — возьмётся DefaultUUID.
	UUID string
	// Listen — адрес инбаунда. Пусто — 127.0.0.1 со свободным портом.
	Listen string
}

// DefaultUUID — пользователь стенда. Не секрет: стенд локальный и живёт
// внутри одного теста (§6.14 про настоящие ключи, здесь их нет).
const DefaultUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// NewServer поднимает VLESS-инбаунд с freedom-выходом наружу.
func NewServer(opt Options) (*Server, error) {
	uuid := opt.UUID
	if uuid == "" {
		uuid = DefaultUUID
	}
	host, port := "127.0.0.1", 0
	if opt.Listen != "" {
		h, p, err := net.SplitHostPort(opt.Listen)
		if err != nil {
			return nil, fmt.Errorf("xraytest: негодный listen %q: %w", opt.Listen, err)
		}
		host = h
		if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
			return nil, fmt.Errorf("xraytest: негодный порт в %q: %w", opt.Listen, err)
		}
	}
	if port == 0 {
		p, err := freePort(host)
		if err != nil {
			return nil, err
		}
		port = p
	}

	cfg := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []map[string]any{{
			"tag":      "in",
			"listen":   host,
			"port":     port,
			"protocol": "vless",
			"settings": map[string]any{
				"clients":    []map[string]any{{"id": uuid}},
				"decryption": "none",
			},
			"streamSettings": map[string]any{"network": "raw", "security": "none"},
		}},
		"outbounds": []map[string]any{{"protocol": "freedom", "tag": "direct"}},
	}

	inst, err := start(cfg)
	if err != nil {
		return nil, err
	}
	return &Server{inst: inst, addr: net.JoinHostPort(host, fmt.Sprint(port)), uuid: uuid}, nil
}

// Addr — адрес инбаунда, он же адрес узла для клиента.
func (s *Server) Addr() string { return s.addr }

// Host и Port — то же самое по частям: клиентскому конфигу нужны они.
func (s *Server) Host() string {
	h, _, _ := net.SplitHostPort(s.addr)
	return h
}

func (s *Server) Port() int {
	_, p, _ := net.SplitHostPort(s.addr)
	var n int
	fmt.Sscanf(p, "%d", &n)
	return n
}

// UUID пользователя инбаунда.
func (s *Server) UUID() string { return s.uuid }

// Close останавливает инбаунд.
func (s *Server) Close() error {
	if s.inst == nil {
		return nil
	}
	err := s.inst.Close()
	s.inst = nil
	return err
}

func start(cfg map[string]any) (*core.Instance, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("xraytest: конфиг не сериализуется: %w", err)
	}
	c, err := serial.LoadJSONConfig(strings.NewReader(string(b)))
	if err != nil {
		return nil, fmt.Errorf("xraytest: Xray не принял конфиг: %w", err)
	}
	inst, err := core.New(c)
	if err != nil {
		return nil, fmt.Errorf("xraytest: инстанс не собрался: %w", err)
	}
	if err := inst.Start(); err != nil {
		return nil, fmt.Errorf("xraytest: инстанс не запустился: %w", err)
	}
	return inst, nil
}

// freePort занимает и тут же отпускает порт. Гонка здесь возможна в теории:
// между Close и стартом инбаунда порт может занять кто-то ещё. На практике
// это единственный способ — конфиг Xray требует порт числом, а не слушателем.
func freePort(host string) (int, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, fmt.Errorf("xraytest: не нашёлся свободный порт: %w", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
