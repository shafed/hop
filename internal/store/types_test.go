package store

import "testing"

// TestProjectionsDoNotShareParams — единственная проверка шага: проекции
// собираются и не отдают наружу ту же карту params. Общая карта означала бы,
// что граница §3.4 держится на договорённости движка не писать в чужое.
func TestProjectionsDoNotShareParams(t *testing.T) {
	n := Node{
		ID:        "n1",
		GroupID:   ManualGroupID,
		Protocol:  "vless",
		Server:    "example.org",
		Port:      443,
		Transport: "ws",
		Security:  "tls",
		Params:    map[string]string{"uuid": "секрет"},
		Supported: true,
	}

	e := n.ToEngine()
	if e.ID != n.ID || e.Server != n.Server || e.Port != n.Port {
		t.Fatalf("проекция для движка потеряла адрес: %+v", e)
	}
	e.Params["uuid"] = "чужое"
	if n.Params["uuid"] != "секрет" {
		t.Fatal("движок пишет в params узла: карта отдана, а не скопирована")
	}

	h := n.ToHealth()
	if h.ID != n.ID || !h.Supported {
		t.Fatalf("проекция для живости: %+v", h)
	}
}
