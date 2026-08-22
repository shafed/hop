package resolver

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/dnsmsg"
	"github.com/shafed/hop/internal/policy"
)

// Кэш ответов: TTL и его границы (Р17), отрицательный кэш (Р18), ключ и
// регистр имени (Р23), потолок с вытеснением LRU и склейка одинаковых
// вопросов в полёте (Р24).
//
// Кэш хранит ответ апстрима целиком, байтами, а не разобранные записи: У6
// велит отдавать клиенту то, что пришло, включая TTL (C4), и разбор ради
// хранения означал бы пересборку ради отдачи — то есть ровно ту
// самодеятельность, которую запрещает D47.

// errInFlightFull — летящих запросов уже MaxInFlight (Р24, D39). Спина
// превращает это в SERVFAIL немедленно: ждать освобождения места значит
// копить горутины ровно там, где потолок и заводился.
var errInFlightFull = errors.New("resolver: потолок одновременных запросов наверх исчерпан")

// entry — одна запись кэша.
//
// Момент смерти хранится временем, а не длительностью: пересчитывать остаток
// пришлось бы на каждом чтении, а сравнить с часами — одно сравнение.
type entry struct {
	key      string
	msg      dnsmsg.Msg
	expires  time.Time
	negative bool
}

// cache — общий на процесс кэш ответов (Р23): все клиенты локальны и ходят в
// одну сеть через один узел, поэтому делить кэш по клиентам не за чем.
//
// Карта плюс список: карта даёт поиск по ключу, список — порядок вытеснения.
// Цена — два указателя на запись и ручная синхронность двух структур; выигрыш
// — вытеснение за constant time, без обхода 4096 записей в тот момент, когда
// кэш и так переполнен.
type cache struct {
	clk clock.Clock

	mu    sync.Mutex
	byKey map[string]*list.Element // ключ Р23 → элемент lru
	lru   *list.List               // front — свежайший, back — кандидат на вылет
}

func newCache(clk clock.Clock) *cache {
	return &cache{
		clk:   clk,
		byKey: make(map[string]*list.Element),
		lru:   list.New(),
	}
}

// get — живая запись по ключу.
//
// Протухшая запись здесь же и выбрасывается: иначе имя, к которому больше не
// обращаются, держит память до тех пор, пока его не вытеснит LRU, а вытеснить
// его может только приток 4096 новых имён.
//
// Граница срока — строгая: запись с TTL 600 жива на шестисотой секунде и
// мертва на шестьсот первой (D24). Выбор из двух одинаково защитимых, и он
// назван здесь, чтобы проверка не гадала.
func (c *cache) get(key string) (dnsmsg.Msg, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.byKey[key]
	if !ok {
		return dnsmsg.Msg{}, false
	}
	e := el.Value.(*entry)
	if c.clk.Now().After(e.expires) {
		c.removeLocked(el)
		return dnsmsg.Msg{}, false
	}
	c.lru.MoveToFront(el)
	return e.msg, true
}

// put кладёт ответ апстрима, если он вообще подлежит кэшированию.
//
// Решение «класть или нет» и срок жизни считает cacheTTL: политика Р17/Р18
// живёт в одном месте, а не размазана по вызывающим.
func (c *cache) put(key string, m dnsmsg.Msg) {
	ttl, negative, ok := cacheTTL(m)
	if !ok {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Повторный ответ на тот же вопрос замещает прежний целиком, а не
	// продлевает его: апстрим мог сменить и записи, и TTL.
	if el, exists := c.byKey[key]; exists {
		c.removeLocked(el)
	}

	e := &entry{key: key, msg: m, expires: c.clk.Now().Add(ttl), negative: negative}
	c.byKey[key] = c.lru.PushFront(e)

	// Вытеснение с хвоста — самый давно не спрошенный (D32). Цикл, а не одно
	// удаление: потолок мог быть понижен, и один вылет за вставку оставил бы
	// кэш выше границы неопределённо долго.
	for c.lru.Len() > CacheEntries {
		c.removeLocked(c.lru.Back())
	}
}

// removeLocked снимает запись из обеих структур сразу. Вызывается под c.mu.
func (c *cache) removeLocked(el *list.Element) {
	e := el.Value.(*entry)
	c.lru.Remove(el)
	delete(c.byKey, e.key)
}

// size — записей всего и из них отрицательных.
//
// Считаются только живые: протухшая запись клиенту не достанется, и показывать
// её в Stats.Entries значит показывать не то, что кэш умеет отдать. Цена —
// обход списка на каждый Snapshot, до 4096 сравнений времени; альтернатива
// (чистить протухшее прямо здесь) сделала бы чтение статистики записью в кэш,
// а Snapshot зовёт и `hop status`, и любой тест.
//
// Пары счётчиков вместо обхода здесь нет намеренно: запись умирает не в
// момент вызова, а по часам, и счётчик, который никто не декрементирует в
// секунду смерти, показывал бы протухшее живым — то есть ровно ту величину,
// которой D19 («Entries = 0 после сброса») и D32 («Entries ≤ 4096») верить бы
// не смогли.
func (c *cache) size() (entries, negative int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.clk.Now()
	for el := c.lru.Front(); el != nil; el = el.Next() {
		e := el.Value.(*entry)
		if now.After(e.expires) {
			continue
		}
		entries++
		if e.negative {
			negative++
		}
	}
	return entries, negative
}

// reset выкидывает всё. Зовётся только из flush (Р25, §5.7в).
//
// Летящие наверх запросы reset не трогает: их ответы лягут в уже новый кэш.
// Это осознанная щель — запрос, ушедший через прежний узел, вернётся и
// закэшируется после сброса, — и закрывает её Р20: запрос, застигнутый
// переключением, повторяется через нового активного (З7, D16).
func (c *cache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.byKey = make(map[string]*list.Element)
	c.lru.Init()
}

// cacheTTL — сколько жить ответу и отрицательный ли он. ok=false означает «в
// кэш не класть вовсе».
//
// Здесь и только здесь применяются границы Р17 и Р18: internal/dnsmsg отдаёт
// факты сообщения, а политика кэша — наша.
func cacheTTL(m dnsmsg.Msg) (ttl time.Duration, negative bool, ok bool) {
	// Усечённый ответ — заведомо неполный RRset: апстрим велит прийти по TCP.
	// Кэшировать его значит раздавать обрезок всем следующим спросившим, и
	// хуже того — молча, потому что повтор по TCP (D33) делает поход наверх, а
	// попадание в кэш его не делает.
	if m.Header.Truncated() {
		return 0, false, false
	}

	f, err := m.Facts()
	if err != nil {
		// Сообщение, у которого не сходится хвост, — мусор из сети (D15).
		// Отдать его клиенту мог решить кто-то выше; осадить его в кэше и
		// раздавать дальше — точно нет.
		return 0, false, false
	}

	if m.Negative() {
		if !policy.DNSNegativeCache.On() {
			return 0, true, false
		}
		// Р18: min(SOA.MINIMUM, TTL записи SOA, 300 с), а без SOA — 30 с.
		// Оба поля SOA, а не одно: авторитет вправе назвать запись SOA
		// короткоживущей, не трогая MINIMUM, и уважить надо меньшее.
		secs := seconds(NegativeDefault)
		if f.HasSOA {
			secs = min(f.SOAMinimum, f.SOATTL, seconds(NegativeCap))
		}
		if secs == 0 {
			return 0, true, false
		}
		return time.Duration(secs) * time.Second, true, true
	}

	// Всё, что не NOERROR с непустой ANSWER и не отрицательный ответ, — это
	// REFUSED, FORMERR и прочие отказы апстрима. Кэшировать их спека не
	// просит, а цена ошибки та же, что у Р18 наоборот: чужой сбой на минуту
	// становится нашим. Наверх пойдёт каждый такой вопрос — так и задумано.
	if m.Header.Rcode() != dnsmsg.RcodeNoError || !f.HasAnswer {
		return 0, false, false
	}

	// Р17: минимум TTL по ANSWER, потолок 600 с, пола нет — 0 значит 0 и в
	// кэш не кладётся вовсе (RFC 1035 прямо запрещает).
	secs := min(f.MinTTL, seconds(TTLCap))
	if secs == 0 {
		return 0, false, false
	}
	return time.Duration(secs) * time.Second, false, true
}

// seconds — граница из §4 в тех же единицах, в которых TTL приходит по
// проводу. Все границы кратны секунде по построению.
func seconds(d time.Duration) uint32 { return uint32(d / time.Second) }

// answerFor — кэшированный ответ, годный именно этому клиенту.
//
// Написание имени берётся из его запроса, а не из кэша (Р23, D30): стаб,
// применяющий 0x20-рандомизацию, сверяет секцию вопроса побайтно и ответ с
// чужим написанием молча отбросит — снаружи это выглядит как «DNS не
// работает» при полностью рабочем резолвере.
//
// Совпало написание — отдаётся тот же срез без копии: ответ клиенту всё равно
// собирает dnsmsg.Reply, и вторая копия на общем пути стоила бы аллокации на
// каждое попадание. Длины имён равны по построению: ключ кэша — то же имя в
// нижнем регистре, значит разного размера у них быть не может.
func answerFor(cached, q dnsmsg.Msg) dnsmsg.Msg {
	if bytes.Equal(cached.Question.Name, q.Question.Name) {
		return cached
	}

	out := make([]byte, len(cached.Raw))
	copy(out, cached.Raw)
	copy(out[dnsmsg.HeaderLen:], q.Question.Name)

	m := cached
	m.Raw = out
	m.Question.Name = dnsmsg.Name(out[dnsmsg.HeaderLen : dnsmsg.HeaderLen+len(q.Question.Name)])
	return m
}

// flight — один летящий наверх вопрос и общий ответ на всех, кто его ждёт.
type flight struct {
	done chan struct{}
	msg  dnsmsg.Msg
	err  error // отказ тоже общий: спросили одно и то же, отказ один
}

// flightGroup — склейка одинаковых вопросов в полёте (Р24).
//
// Ключ тот же, что у кэша: вопросы, неразличимые для кэша, неразличимы и для
// апстрима, и заводить второй способ считать вопросы одинаковыми значило бы
// завести второе место, где регистр имени учитывается по-своему.
type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flight
}

func newFlightGroup() *flightGroup { return &flightGroup{m: make(map[string]*flight)} }

// join — либо слот лидера (leader=true), либо уже летящий за этим вопросом.
func (g *flightGroup) join(key string) (f *flight, leader bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if f, ok := g.m[key]; ok {
		return f, false
	}
	f = &flight{done: make(chan struct{})}
	g.m[key] = f
	return f, true
}

// finish отдаёт результат ждущим и снимает вопрос с полёта. Зовёт только
// лидер, ровно один раз.
func (g *flightGroup) finish(key string, f *flight, m dnsmsg.Msg, err error) {
	f.msg, f.err = m, err

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	close(f.done)
}

// lookup — попадание в кэш либо поход наверх. Промах кэша и есть поход
// наверх, поэтому шаг один: иначе между проверкой и запросом появляется окно,
// в котором склейка не работает.
func (r *Resolver) lookup(ctx context.Context, q dnsmsg.Msg, rt route) (dnsmsg.Msg, error) {
	key := q.Question.Key()

	if m, ok := r.cache.get(key); ok {
		r.cnt.hits.Add(1)
		return answerFor(m, q), nil
	}

	if !policy.DNSSingleFlight.On() {
		r.cnt.misses.Add(1)
		m, err := r.fetch(ctx, key, q, rt)
		if err != nil {
			return dnsmsg.Msg{}, err
		}
		return answerFor(m, q), nil
	}

	f, leader := r.flight.join(key)
	if !leader {
		// Склеенный запрос — не промах и не попадание: наверх он не пошёл, но
		// и готового ответа в кэше для него не было. Свой счётчик, Coalesced
		// (D38).
		r.cnt.coalesced.Add(1)
		select {
		case <-f.done:
			if f.err != nil {
				return dnsmsg.Msg{}, f.err
			}
			return answerFor(f.msg, q), nil
		case <-ctx.Done():
			// Бюджет клиента вышел раньше, чем ответ лидера. Лидер при этом
			// продолжает и дойдёт до кэша: бросать чужой полёт из-за своего
			// таймаута значит наказывать всех остальных ждущих.
			return dnsmsg.Msg{}, ctx.Err()
		}
	}

	// Лидер перепроверяет кэш. Между промахом выше и захватом слота предыдущий
	// полёт за тем же вопросом мог завершиться: он кладёт ответ в кэш до того,
	// как снимет себя с карты, — значит мимо обеих проверок сразу проскочить
	// нельзя, и второго запроса наверх за уже полученным ответом не будет.
	if m, ok := r.cache.get(key); ok {
		r.flight.finish(key, f, m, nil)
		r.cnt.hits.Add(1)
		return answerFor(m, q), nil
	}

	r.cnt.misses.Add(1)
	m, err := r.fetch(ctx, key, q, rt)
	r.flight.finish(key, f, m, err)
	if err != nil {
		return dnsmsg.Msg{}, err
	}
	return answerFor(m, q), nil
}

// fetch — поход наверх, занимающий место в потолке летящих (Р24, D39).
//
// Кэш заполняется здесь, а не в lookup: тогда «положил в кэш» и «освободил
// место» — соседние строки одной функции, и ветки, где ответ получен, а в кэш
// не попал, взяться неоткуда.
func (r *Resolver) fetch(ctx context.Context, key string, q dnsmsg.Msg, rt route) (dnsmsg.Msg, error) {
	if !r.reserveInFlight() {
		return dnsmsg.Msg{}, errInFlightFull
	}
	defer r.cnt.inFlight.Add(-1)

	m, err := r.ask(ctx, q, rt)
	if err != nil {
		return dnsmsg.Msg{}, err
	}
	r.cache.put(key, m)
	return m, nil
}

// reserveInFlight занимает место под потолком MaxInFlight.
//
// Цикл сравнения с обменом, а не Add с откатом при перелёте: откат на мгновение
// оставляет счётчик выше потолка, и Snapshot в этот момент показал бы InFlight
// = 257 — то самое число, которое D39 объявляет невозможным.
func (r *Resolver) reserveInFlight() bool {
	for {
		n := r.cnt.inFlight.Load()
		if n >= MaxInFlight {
			return false
		}
		if r.cnt.inFlight.CompareAndSwap(n, n+1) {
			return true
		}
	}
}
