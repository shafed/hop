// Путь скачивания подписки — docs/verification-store.md §5.2 (S14, S15) и §4.
// Уровень L1: настоящей сети здесь нет вовсе, HTTP-клиент подставной, часы
// фейковые, диск — t.TempDir().
package subscription

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time" //hop:realtime — длительности и точка отсчёта фейковых часов, обращений к настоящему времени нет

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/store"
)

// subEpoch — откуда стартуют фейковые часы. Значение произвольно.
var subEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const subURL = "https://example.invalid/sub"

// doerFunc — подставной HTTP-клиент. Интерфейс Doer ради этого и введён:
// проверки S14 и S15 обязаны гоняться без сети.
type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

// respond — ответ, отданный целиком.
func respond(data []byte) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Body:          io.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
		Header:        http.Header{},
	}
}

// cut — ответ, пообещавший заголовком всё тело и отдавший только начало: так
// выглядит передача, оборванная на середине.
func cut(full []byte, sent int) *http.Response {
	r := respond(full[:sent])
	r.ContentLength = int64(len(full))
	return r
}

// brokenReader отдаёт начало тела и обрывается ошибкой — вторая форма того же
// обрыва, при которой заголовку верить не приходится вовсе.
type brokenReader struct {
	data []byte
	sent bool
}

func (b *brokenReader) Read(p []byte) (int, error) {
	if b.sent {
		return 0, io.ErrUnexpectedEOF
	}
	b.sent = true
	return copy(p, b.data), nil
}

func (b *brokenReader) Close() error { return nil }

// serve — загрузчик, отдающий один заранее собранный ответ.
func serve(t *testing.T, resp *http.Response) *Downloader {
	t.Helper()
	return NewDownloader(doerFunc(func(*http.Request) (*http.Response, error) {
		return resp, nil
	}), clock.NewFake(subEpoch))
}

// testStore — стор в собственном временном каталоге.
func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir(), clock.NewFake(subEpoch))
	if err != nil {
		t.Fatalf("стор не открылся: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// links — эталонная подписка из двух ссылок.
func links() []string {
	return []string{
		"vless://" + uuidA + "@a.example.com:443?type=ws&security=tls#a",
		"vless://" + uuidB + "@b.example.com:443?type=grpc&security=reality&pbk=xxx#b",
	}
}

func base64Body(links ...string) []byte {
	return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
}

// snapshot — состав группы в виде, по которому видно и порядок, и содержимое:
// «группа цела» — это не только те же id.
func snapshot(nodes []store.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID+" "+n.Server+" "+n.Name+" "+n.Param("uuid"))
	}
	return out
}

// filled — группа, наполненная удачным обновлением. То состояние, целость
// которого проверяют S14 и S15.
func filled(t *testing.T, groupID string) (*store.Store, []string) {
	t.Helper()
	st := testStore(t)
	u := &Updater{Store: st, Downloader: serve(t, respond(base64Body(links()...))), NewID: seqIDs("n")}

	res, err := u.Update(context.Background(), groupID, subURL)
	if err != nil {
		t.Fatalf("первое обновление не прошло: %v", err)
	}
	if len(res.Merged.Added) != 2 {
		t.Fatalf("добавлено %d узлов, ожидалось 2: проверка стояла бы на пустой группе", len(res.Merged.Added))
	}
	return st, snapshot(st.Nodes(groupID))
}

// TestS14EmptyParseIsRejected — S14: подписка разобралась в ноль узлов.
// Слияние не применено, группа цела, возвращена ошибка (Р7).
func TestS14EmptyParseIsRejected(t *testing.T) {
	st, before := filled(t, "sub")

	// Две строки, ни одна из которых не стала узлом: формат распознан
	// построчно, узлов ноль. Именно так выглядит подписка, которую провайдер
	// опустошил по ошибке.
	body := []byte("это не ссылка\nи это не ссылка")
	p, err := Parse(body)
	if err != nil || len(p.Nodes) != 0 {
		t.Fatalf("тело для проверки подобрано неверно: узлов %d, ошибка %v", len(p.Nodes), err)
	}

	u := &Updater{Store: st, Downloader: serve(t, respond(body)), NewID: seqIDs("m")}
	res, err := u.Update(context.Background(), "sub", subURL)
	if !errors.Is(err, ErrEmptySubscription) {
		t.Fatalf("пустая подписка применилась: ошибка %v, результат %+v", err, res)
	}

	if got := snapshot(st.Nodes("sub")); !slices.Equal(got, before) {
		t.Errorf("группа изменилась пустым обновлением:\nбыло  %v\nстало %v", before, got)
	}
}

// TestS15TruncatedBodyIsRejected — S15: тело оборвано на середине. То же:
// группа цела, ошибка (Р7).
//
// Ловится это не разбором, а транспортом: обрезанное тело разбирается в
// осмысленный, но неполный список узлов — то есть выглядит ровно как подписка,
// из которой провайдер убрал половину. Проверка того и требует, чтобы отказ
// случился раньше слияния.
func TestS15TruncatedBodyIsRejected(t *testing.T) {
	full := base64Body(links()...)
	half := full[:len(full)/4*2] // кратно четырём: обрезок остаётся годным base64

	// Половина тела разбирается и даёт узлы — значит проверка «ноль узлов» тут
	// не сработала бы, и группа лишилась бы второго узла вместе с историей.
	if p, err := Parse(half); err != nil || len(p.Nodes) == 0 {
		t.Fatalf("обрезок подобран неудачно: узлов %d, ошибка %v — проверка стала бы дубликатом S14", len(p.Nodes), err)
	}

	for _, tc := range []struct {
		name string
		resp func() *http.Response
	}{
		{
			name: "тела меньше обещанного",
			resp: func() *http.Response { return cut(full, len(half)) },
		},
		{
			name: "чтение оборвалось",
			resp: func() *http.Response {
				r := respond(nil)
				r.ContentLength = -1
				r.Body = &brokenReader{data: half}
				return r
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, before := filled(t, "sub")

			u := &Updater{Store: st, Downloader: serve(t, tc.resp()), NewID: seqIDs("m")}
			if _, err := u.Update(context.Background(), "sub", subURL); !errors.Is(err, ErrTruncated) {
				t.Fatalf("оборванное тело применилось: %v", err)
			}
			if got := snapshot(st.Nodes("sub")); !slices.Equal(got, before) {
				t.Errorf("группа изменилась оборванным обновлением:\nбыло  %v\nстало %v", before, got)
			}
		})
	}
}

// TestUpdateKeepsIDsAndTakesQuota — удачный путь целиком: id переживают
// обновление (§5.8), состав и порядок берутся у провайдера (Р8), заголовок
// квоты доезжает до вызывающего.
func TestUpdateKeepsIDsAndTakesQuota(t *testing.T) {
	st, before := filled(t, "sub")

	// Провайдер поменял местами узлы и правил косметику первого.
	changed := []string{
		"vless://" + uuidB + "@b.example.com:443?type=grpc&security=reality&pbk=xxx#b",
		"vless://" + uuidA + "@a.example.com:443?type=ws&security=tls&sni=new.example#переименован",
	}
	resp := respond(base64Body(changed...))
	resp.Header.Set("Subscription-Userinfo", "upload=1; download=2; total=3")

	u := &Updater{Store: st, Downloader: serve(t, resp), NewID: seqIDs("m")}
	res, err := u.Update(context.Background(), "sub", subURL)
	if err != nil {
		t.Fatalf("обновление не прошло: %v", err)
	}

	if len(res.Merged.Added) != 0 || len(res.Merged.Removed) != 0 {
		t.Errorf("Added %v, Removed %v: сменились только имя и SNI", res.Merged.Added, res.Merged.Removed)
	}
	if res.QuotaInfo != "upload=1; download=2; total=3" {
		t.Errorf("quota_info не доехал: %q", res.QuotaInfo)
	}
	if res.Format != FormatBase64 {
		t.Errorf("формат %s, а тело было base64", res.Format)
	}

	// id те же, порядок — провайдерский, то есть обратный прежнему.
	nodes := st.Nodes("sub")
	want := []string{beforeID(before, 1), beforeID(before, 0)}
	if got := nodeIDs(nodes); !slices.Equal(got, want) {
		t.Errorf("порядок узлов %v, а провайдер прислал %v", got, want)
	}
	if n, ok := nodeByID(nodes, want[1]); !ok || n.Param("sni") != "new.example" || n.Name != "переименован" {
		t.Errorf("правка провайдера не доехала до стора: %+v", n)
	}
}

// beforeID — id из снимка состава.
func beforeID(snap []string, i int) string { return strings.Fields(snap[i])[0] }

func nodeIDs(nodes []store.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	return out
}

// TestDownloadRejectsOversizedBody — потолок §4: 8 МиБ. Тело читается целиком в
// память, поэтому потолок обязателен — без него объём памяти назначает
// провайдер.
func TestDownloadRejectsOversizedBody(t *testing.T) {
	big := bytes.Repeat([]byte("a"), MaxBodySize+1)
	if _, err := serve(t, respond(big)).Get(context.Background(), subURL); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("тело больше потолка принято: %v", err)
	}

	// Ровно потолок — ещё не много: граница проверяется с обеих сторон.
	exact := bytes.Repeat([]byte("a"), MaxBodySize)
	if _, err := serve(t, respond(exact)).Get(context.Background(), subURL); err != nil {
		t.Fatalf("тело ровно в потолок отвергнуто: %v", err)
	}
}

// TestDownloadTimeoutRunsOnStoreClock — таймаут §4 идёт по инъектируемым часам,
// а не по настоящим: иначе проверка стоила бы тридцати секунд реального
// времени (§8.1).
func TestDownloadTimeoutRunsOnStoreClock(t *testing.T) {
	fake := clock.NewFake(subEpoch)
	reached := make(chan struct{})
	d := NewDownloader(doerFunc(func(r *http.Request) (*http.Response, error) {
		close(reached)
		<-r.Context().Done()
		return nil, r.Context().Err()
	}), fake)

	go func() {
		<-reached
		fake.Advance(DownloadTimeout + time.Second)
	}()

	start := time.Now() //hop:realtime — измеряется настоящая длительность теста, а не логика продукта
	_, err := d.Get(context.Background(), subURL)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("ожидался таймаут по часам: %v", err)
	}
	if elapsed := time.Since(start); elapsed > DownloadTimeout { //hop:realtime — там же
		t.Errorf("проверка шла %s: таймаут отсчитывается настоящим временем, а не часами", elapsed)
	}
}

// TestDownloadRejectsErrorStatus — 404 от провайдера не подписка. Тело такого
// ответа в слияние не идёт: страница с ошибкой разобралась бы в ноль узлов, и
// причина утонула бы в S14.
func TestDownloadRejectsErrorStatus(t *testing.T) {
	resp := respond([]byte("<html>нет такой подписки</html>"))
	resp.StatusCode, resp.Status = http.StatusNotFound, "404 Not Found"

	_, err := serve(t, resp).Get(context.Background(), subURL)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("ответ 404 принят за подписку: %v", err)
	}
}

// TestUpdateRefusesManualGroup — Р10: manual не подписка, обновлять нечего.
func TestUpdateRefusesManualGroup(t *testing.T) {
	st := testStore(t)
	u := &Updater{Store: st, Downloader: serve(t, respond(base64Body(links()...))), NewID: seqIDs("n")}
	if _, err := u.Update(context.Background(), store.ManualGroupID, subURL); err == nil {
		t.Fatal("группа manual обновилась из подписки")
	}
	if got := st.Nodes(store.ManualGroupID); len(got) != 0 {
		t.Errorf("в manual появились узлы из подписки: %v", nodeIDs(got))
	}
}

// TestNewIDIsUnique — генератор по умолчанию не выдаёт одинаковых id: id,
// выданный дважды, склеил бы историю проб двух разных узлов.
func TestNewIDIsUnique(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for range 1000 {
		id := NewID()
		if id == "" || seen[id] {
			t.Fatalf("генератор id выдал %q дважды или пусто", id)
		}
		seen[id] = true
	}
}
