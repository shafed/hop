package subscription

import (
	"encoding/base64"
	"testing"

	"github.com/shafed/hop/internal/store"
)

// Формы ссылок, которых нет в регистре отдельной строкой, но которые разбор
// обязан понимать: без них узел провайдера просто не появится, и причина
// будет выглядеть как «битая ссылка».

// vmess в форме v2rayN: base64 от JSON. Проверяется заодно, что "net" стал
// транспортом, а "scy" — методом шифрования vmess, который движок читает из
// params под именем security.
func TestVMessJSONFormIsParsed(t *testing.T) {
	js := `{"v":"2","ps":"json-uzel","add":"a.example.com","port":"8443","id":"11111111-1111-1111-1111-111111111111","aid":"0","scy":"auto","net":"h2","type":"none","host":"h2.example.org","path":"/p","tls":"tls","sni":"a.example.com"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))

	p, err := Parse([]byte(link))
	if err != nil {
		t.Fatalf("не разобралось: %v", err)
	}
	if len(p.Nodes) != 1 {
		t.Fatalf("узлов %d, ожидался 1", len(p.Nodes))
	}
	n := p.Nodes[0]
	if n.Name != "json-uzel" || n.Server != "a.example.com" || n.Port != 8443 {
		t.Errorf("имя/адрес/порт разобраны как %q %s:%d", n.Name, n.Server, n.Port)
	}
	if n.Param("uuid") != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("uuid = %q", n.Param("uuid"))
	}
	if n.Transport != "http" {
		t.Errorf("транспорт %q, ожидался http: net=h2 нормализуется, type=none — это headerType", n.Transport)
	}
	if n.Security != "tls" {
		t.Errorf("security %q, ожидалось tls", n.Security)
	}
	if n.Param("security") != "auto" {
		t.Errorf("метод шифрования vmess = %q, ожидался auto из scy", n.Param("security"))
	}
}

// vmess в стандартной форме — обычная ссылка со схемой.
func TestVMessURLFormIsParsed(t *testing.T) {
	link := "vmess://11111111-1111-1111-1111-111111111111@a.example.com:443?type=ws&security=tls&encryption=auto&path=%2Fws#url-uzel"
	p, err := Parse([]byte(link))
	if err != nil {
		t.Fatalf("не разобралось: %v", err)
	}
	n := p.Nodes[0]
	if n.Protocol != "vmess" || n.Param("uuid") == "" || n.Transport != "ws" || !n.Supported {
		t.Errorf("узел разобран как %+v", n)
	}
	if n.Param("security") != "auto" {
		t.Errorf("метод шифрования vmess = %q, ожидался auto из encryption", n.Param("security"))
	}
}

// shadowsocks в трёх формах: base64 всего тела, base64 пользовательской части
// и открытый method:password (2022).
func TestShadowsocksFormsAreParsed(t *testing.T) {
	whole := "ss://" + base64.StdEncoding.EncodeToString(
		[]byte("aes-256-gcm:parol@a.example.com:8388")) + "#vsjo-v-base64"
	userinfo := "ss://" + base64.StdEncoding.EncodeToString(
		[]byte("aes-256-gcm:parol")) + "@b.example.com:8388#userinfo-v-base64"
	plain := "ss://2022-blake3-aes-256-gcm:parol@c.example.com:8388#otkrytym-tekstom"

	for _, link := range []string{whole, userinfo, plain} {
		p, err := Parse([]byte(link))
		if err != nil {
			t.Fatalf("ссылка %q не разобралась: %v", link, err)
		}
		if len(p.Nodes) != 1 {
			t.Fatalf("ссылка %q дала %d узлов", link, len(p.Nodes))
		}
		n := p.Nodes[0]
		if n.Protocol != "shadowsocks" || n.Port != 8388 {
			t.Errorf("ссылка %q: протокол %q, порт %d", link, n.Protocol, n.Port)
		}
		if n.Param("password") != "parol" || n.Param("method") == "" {
			t.Errorf("ссылка %q: метод %q, пароль %q", link, n.Param("method"), n.Param("password"))
		}
		if !n.Supported {
			t.Errorf("ссылка %q: узел не поддержан, причина %v", link, n.UnsupReason)
		}
	}
}

// reality без публичного ключа собрать нельзя — §6.11 называет этот случай
// прямо, и причина у него security, а не parse.
func TestRealityWithoutKeyIsUnsupportedBySecurity(t *testing.T) {
	link := "vless://11111111-1111-1111-1111-111111111111@a.example.com:443?type=raw&security=reality&sni=www.example.org#bez-pbk"
	p, err := Parse([]byte(link))
	if err != nil {
		t.Fatalf("не разобралось: %v", err)
	}
	n := p.Nodes[0]
	if n.Supported || n.UnsupReason != store.UnsupSecurity {
		t.Errorf("узел: supported=%v, причина %v; ожидалось false и security", n.Supported, n.UnsupReason)
	}
}

// Ссылка известного протокола без обязательного поля — это битая ссылка у
// провайдера, причина parse, а не «наша сборка не умеет».
func TestMissingRequiredFieldIsReportedAsParse(t *testing.T) {
	link := "vless://@a.example.com:443?type=ws&security=tls#bez-uuid"
	p, err := Parse([]byte(link))
	if err != nil {
		t.Fatalf("не разобралось: %v", err)
	}
	if len(p.Nodes) != 1 {
		t.Fatalf("узлов %d, ожидался 1", len(p.Nodes))
	}
	if n := p.Nodes[0]; n.Supported || n.UnsupReason != store.UnsupParse {
		t.Errorf("узел: supported=%v, причина %v; ожидалось false и parse", n.Supported, n.UnsupReason)
	}
}

// Тело, которого не взяла ни одна ступень каскада: «не распозналось» — это
// отдельный отказ, а не пустой результат (У3).
func TestUnrecognizedBodyIsAnError(t *testing.T) {
	if _, err := Parse([]byte("совершенно посторонний текст")); err == nil {
		t.Error("нераспознанное тело разобралось без ошибки")
	}
	if _, err := Parse(nil); err == nil {
		t.Error("пустое тело разобралось без ошибки")
	}
}
