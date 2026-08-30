package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/subscription"
)

// Замеры проходов «`hop nodes` через сокет §3.3» (W65) и «уборка при Open не
// ждёт замок» (S47), сохранённые исполнимыми.
//
// Не охрана, а замер: утверждений о продукте эти функции почти не проверяют и
// падать им не от чего — они печатают числа, на которых стоят решения проходов
// (форма ответа, опровержение довода про flock, цена уборки под замком).
// Записанные в implementation-notes.md числа обязаны воспроизводиться этой
// командой, иначе раздел заметок становится вторым экземпляром правды.
//
//	go test ./cmd/hop -run 'TestW65Measure|TestS47Measure' -v -count=1
//
// Охраняют те же механизмы W65, W66 и S47 — они обычные тесты и идут в общем
// гейте.

// measureStore заводит настоящий стор с n узлами, разобранными из настоящих
// ссылок: сокращать до store.Node руками значило бы мерить не то, что кладёт
// `hop sub add`.
func measureStore(t *testing.T, n int) *store.Store {
	t.Helper()

	root := withTestStore(t)
	st, err := store.Open(root, clock.System{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cc := []string{"nl", "de", "sg", "jp", "us"}
	city := []string{"Amsterdam", "Frankfurt", "Singapore", "Tokyo", "New-York"}
	flags := []string{"🇳🇱", "🇩🇪", "🇸🇬", "🇯🇵", "🇺🇸"}

	var links strings.Builder
	for i := 0; i < n; i++ {
		k := i % 5
		host := fmt.Sprintf("%s-%s-%02d.nodes.example-provider.net", cc[k], city[k], i/5)
		fmt.Fprintf(&links, "vless://11111111-2222-3333-4444-%012d@%s:443"+
			"?type=ws&security=tls&sni=%s&path=%%2Fws#%s %s-%s-%02d %%7C 1.5x\n",
			i, host, host, flags[k], cc[k], city[k], i/5)
	}
	p, err := subscription.Parse([]byte(links.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != n {
		t.Fatalf("разобрано %d узлов из %d", len(p.Nodes), n)
	}
	const gid = "sub-0123456789ab"
	if err := st.Apply(gid, subscription.Diff(gid, nil, p, subscription.NewID)); err != nil {
		t.Fatal(err)
	}

	// Отметка времени фиксированная, но с наносекундами: у настоящей пробы они
	// есть почти всегда, а RFC3339 без них короче на десять байт на узел — две
	// тысячи байт на подписке §6.5, то есть разница, меняющая сам вывод замера.
	// Настоящее «сейчас» дало бы то же число, но с прыжком в ±12 байт от
	// прогона к прогону, и записанное в заметки число перестало бы сходиться.
	probedAt := time.Date(2026, 8, 30, 6, 23, 36, 212948594, time.UTC)
	hs := make([]health.NodeHealth, 0, n)
	for _, nd := range st.Nodes(gid) {
		hs = append(hs, health.NodeHealth{
			NodeID: nd.ID, State: health.Alive,
			RTT: 123 * time.Millisecond, LastProbeAt: probedAt,
		})
	}
	st.PutHealth(hs)
	return st
}

// TestW65MeasureNodesAgainstTheFrameLimit — сколько весит ответ `hop nodes` на
// подписке §6.5 и на каком узле он перестаёт влезать в кадр §3.1.
//
// Числа этого прогона — довод, по которому ответ нарезан на кадры, а не отдан
// одним. json.Marshal здесь мимо emit законен: AST-проверка W58 разбирает
// только не-тестовые файлы, а мерить надо сам байтовый размер, а не печать.
func TestW65MeasureNodesAgainstTheFrameLimit(t *testing.T) {
	const frame = 1 << 16 // maxFrame, internal/ipc/proto.go

	st := measureStore(t, 200)
	v := nodesView(st)
	compact, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	one, err := json.Marshal(v.Groups[0].Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("узлов 200; JSON компактный %d байт; с отступами %d; предел кадра §3.1 %d",
		len(compact), len(indented), frame)
	t.Logf("один NodeView: %d байт", len(one))

	// На каком узле кадр переполняется. Список удлиняется повторением уже
	// измеренных узлов: форма та же, растёт только количество.
	base := v.Groups[0]
	for n := len(base.Nodes); n <= 3*len(base.Nodes); n++ {
		g := base
		g.Nodes = make([]store.NodeView, 0, n)
		for i := 0; i < n; i++ {
			g.Nodes = append(g.Nodes, base.Nodes[i%len(base.Nodes)])
		}
		b, err := json.Marshal(nodesOut{Groups: []store.GroupNodesView{g}})
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > frame {
			t.Logf("кадр переполняется на %d узлах этой формы (%d байт)", n, len(b))
			break
		}
	}

	// Чувствительность к длине имени: настоящие провайдеры называют узлы длиннее.
	for _, extra := range []int{0, 10, 20, 40} {
		g := base
		g.Nodes = make([]store.NodeView, 0, len(base.Nodes))
		for _, n := range base.Nodes {
			n.Name += strings.Repeat("x", extra)
			g.Nodes = append(g.Nodes, n)
		}
		b, err := json.Marshal(nodesOut{Groups: []store.GroupNodesView{g}})
		if err != nil {
			t.Fatal(err)
		}
		verdict := "влезает"
		if len(b) > frame {
			verdict = "НЕ влезает"
		}
		t.Logf("200 узлов, имя длиннее на %2d символов: %d байт — %s", extra, len(b), verdict)
	}
}

// TestW65MeasureAgentDoesNotHoldTheLock — держит ли агент замок стора всю свою
// жизнь.
//
// Довод, ради которого этот замер сохранён исполнимым: прошлый HANDOFF
// утверждал, что держит, и на этом стояла постановка задачи. Замер утверждение
// опроверг.
//
// Модель агента честная в том, что здесь мерится: второй *store.Store на том же
// каталоге со своим файловым замком (flock у разных описаний открытого файла
// конфликтует и внутри одного процесса — потому и мерится в процессе), который
// пишет транзакцию за транзакцией, как persistHealth. Параллельно идёт
// настоящий разбор аргументов и настоящий путь `hop nodes` со своим store.Open
// и store.Close.
func TestW65MeasureAgentDoesNotHoldTheLock(t *testing.T) {
	agentStore := measureStore(t, 200)
	// Каталог берётся у стора, который завела measureStore: withTestStore
	// назначает HOP_STORE, и второй вызов увёл бы замер в пустой каталог.
	root := os.Getenv("HOP_STORE")
	nodes := agentStore.Nodes("sub-0123456789ab")

	var stop atomic.Bool
	var rounds, total, worst atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; !stop.Load(); i++ {
			hs := make([]health.NodeHealth, 0, len(nodes))
			for j, nd := range nodes {
				hs = append(hs, health.NodeHealth{
					NodeID: nd.ID, State: health.Alive,
					RTT:         time.Duration(i+j) * time.Millisecond,
					LastProbeAt: time.Now(), //hop:realtime
				})
			}
			agentStore.PutHealth(hs)
			start := time.Now() //hop:realtime
			if err := agentStore.Flush(); err != nil {
				t.Errorf("модель агента: запись отказала: %v", err)
				return
			}
			d := int64(time.Since(start)) //hop:realtime
			rounds.Add(1)
			total.Add(d)
			if d > worst.Load() {
				worst.Store(d)
			}
			// Пауза, иначе модель не оставляет читателю процессорного времени
			// и мерилась бы уже конкуренция за планировщик, а не замок. Даже с
			// ней модель на три порядка злее продукта: persistHealth пишет раз
			// в тридцать секунд (healthPersistEvery), а не пятьсот раз в
			// секунду.
			time.Sleep(2 * time.Millisecond) //hop:realtime
		}
	}()

	const runs = 40
	ok, fail := 0, 0
	var slowest time.Duration
	sock := t.TempDir() + "/связки-нет.sock"
	for i := 0; i < runs; i++ {
		c, _, errs := testCLI(t)
		start := time.Now() //hop:realtime
		code := c.dispatch([]string{"nodes", "-client-socket", sock})
		if d := time.Since(start); d > slowest { //hop:realtime
			slowest = d
		}
		if code == 0 {
			ok++
			continue
		}
		fail++
		t.Errorf("`hop nodes` при пишущем агенте дал %d: %s", code, errs.String())
	}
	stop.Store(true)
	<-done

	t.Logf("стор %s, узлов %d", root, len(nodes))
	// «Flush занял», а не «замок держался»: измеряется от вызова, то есть
	// вместе с ожиданием замка. Разница не косметическая — S47 нашёлся ровно
	// в ней (см. TestS47MeasureSweepLockUnderALiveWriter).
	t.Logf("модель агента: транзакций %d, Flush занимал в среднем %s, дольше всего %s",
		rounds.Load(),
		time.Duration(total.Load()/max(rounds.Load(), 1)).Round(time.Microsecond),
		time.Duration(worst.Load()).Round(time.Microsecond))
	t.Logf("hop nodes при живом «агенте»: успехов %d, отказов %d, дольше всего %s",
		ok, fail, slowest.Round(time.Millisecond))

	// Второе полустишие замера: отказ ВОСПРОИЗВОДИТСЯ, но только когда замок
	// держат дольше lockTimeout, — то есть не агентом. Держится он тем же
	// flock, каким его берёт стор; путь к файлу проверяется, а не угадывается.
	lock := root + "/.lock"
	if _, err := os.Stat(lock); err != nil {
		t.Fatalf("файла замка нет по ожидаемому пути %s: %v", lock, err)
	}
	t.Logf("для второй половины замера — держать замок дольше lockTimeout (5 с) чужим процессом:\n"+
		"    flock -x %s sleep 8 & HOP_STORE=%s hop nodes", lock, root)
}

// TestS47MeasureSweepLockUnderALiveWriter — во что обходится читателю уборка
// мусора при Open, когда чужая запись идёт прямо сейчас.
//
// Модель та же, что у W65, с одной разницей: писатель без паузы. Пауза там
// стоит нарочно, чтобы мерить замок, а не планировщик; здесь она мешает — окно
// временного файла узкое, и попасть в него надо много раз, чтобы увидеть
// выброс.
//
// Числа, ради которых замер сохранён. До починки худший `hop nodes` из сорока —
// от 457 мс до 2.063 с в пяти прогонах при медиане 4 мс: выброс, а не общее
// замедление, и попадает в него тот Open, что пришёлся на окно временного
// файла. Писатель платил столько же по-своему: его худший Flush — 51 мс во всех
// пяти прогонах, ровно круг опроса lockRetry (50 мс), потерянный в пользу
// читателя, ушедшего подметать. Контроль, по которому видно, что дело не в
// планировщике, — тот же прогон без временных файлов вовсе:
//
//	HOP_DISABLE=atomic_write go test ./cmd/hop -run TestS47Measure -v -count=1
//
// он давал 7 мс худшего и до починки, и 1.2 мс худшего Flush. Сам механизм
// охраняется S47 — TestS47OpenDoesNotWaitForTheSweepLock, internal/store.
func TestS47MeasureSweepLockUnderALiveWriter(t *testing.T) {
	agentStore := measureStore(t, 200)
	root := os.Getenv("HOP_STORE")
	nodes := agentStore.Nodes("sub-0123456789ab")

	var stop atomic.Bool
	var rounds, worst atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; !stop.Load(); i++ {
			hs := make([]health.NodeHealth, 0, len(nodes))
			for j, nd := range nodes {
				hs = append(hs, health.NodeHealth{
					NodeID: nd.ID, State: health.Alive,
					RTT:         time.Duration(i+j) * time.Millisecond,
					LastProbeAt: time.Now(), //hop:realtime
				})
			}
			agentStore.PutHealth(hs)
			start := time.Now() //hop:realtime
			if err := agentStore.Flush(); err != nil {
				t.Errorf("модель агента: запись отказала: %v", err)
				return
			}
			// Вместе с ожиданием замка: писатель до починки стоял за читателем,
			// ушедшим подметать, и это вторая половина той же цены.
			if d := int64(time.Since(start)); d > worst.Load() { //hop:realtime
				worst.Store(d)
			}
			rounds.Add(1)
		}
	}()

	const runs = 40
	sock := t.TempDir() + "/связки-нет.sock"
	took := make([]time.Duration, 0, runs)
	for i := 0; i < runs; i++ {
		c, _, errs := testCLI(t)
		start := time.Now() //hop:realtime
		code := c.dispatch([]string{"nodes", "-client-socket", sock})
		took = append(took, time.Since(start)) //hop:realtime
		if code != 0 {
			t.Errorf("`hop nodes` при пишущем без пауз агенте дал %d: %s", code, errs.String())
		}
	}
	stop.Store(true)
	<-done

	slices.Sort(took)
	t.Logf("стор %s, узлов %d", root, len(nodes))
	t.Logf("писатель без пауз: транзакций %d, дольше всего Flush занял %s",
		rounds.Load(), time.Duration(worst.Load()).Round(time.Microsecond))
	t.Logf("hop nodes: медиана %s, девятый дециль %s, худший %s",
		took[len(took)/2].Round(time.Millisecond),
		took[len(took)*9/10].Round(time.Millisecond),
		took[len(took)-1].Round(time.Millisecond))
}
