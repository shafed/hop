package resolver

import (
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/shafed/hop/internal/policy"
)

// cacheKey — имя, тип, класс. Регистр снят (RFC 4343): апстрим вправе вернуть
// имя в любом, а для клиента это одно и то же имя.
type cacheKey struct {
	name  string
	typ   dnsmessage.Type
	class dnsmessage.Class
}

// entry — запись кэша.
//
// Поле node — это и есть «сброс кэша при смене узла» из §5.7в. Хранить метку
// в записи, а не звать Flush по событию переключения, потому что событие
// приходит асинхронно: между переключением и обработкой события успевает
// пролезть запрос, и он получил бы адрес, выданный CDN прежнего региона —
// ровно то, что §5.7в запрещает.
type entry struct {
	msg     *dnsmessage.Message
	stored  time.Time
	expires time.Time
	node    string
}

// lookup — ответ из кэша с пересчитанным TTL.
func (r *Resolver) lookup(key cacheKey, node string) (*dnsmessage.Message, bool) {
	now := r.clk.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.cache[key]
	if !ok {
		return nil, false
	}
	if !now.Before(e.expires) {
		delete(r.cache, key)
		return nil, false
	}
	// Политика §8: при dns_cache_flush_on_switch=off метка узла не смотрится,
	// и после переключения клиент получает адрес, добытый через прежний узел.
	// Ровно это краснит T14.
	if policy.DNSCacheFlush.On() && e.node != node {
		delete(r.cache, key)
		r.stats.NodeStale++
		return nil, false
	}
	return aged(e.msg, now.Sub(e.stored)), true
}

// store кладёт ответ в кэш, если его есть смысл хранить.
func (r *Resolver) store(key cacheKey, msg *dnsmessage.Message, node string) {
	ttl := r.ttlOf(msg)
	if ttl <= 0 {
		return
	}
	now := r.clk.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(now)
	r.cache[key] = &entry{msg: msg, stored: now, expires: now.Add(ttl), node: node}
	r.evictLocked()
}

// ttlOf — сколько держать ответ. Минимум по записям ответа, зажатый в
// [MinTTL, MaxTTL]; пустой ответ (NXDOMAIN или NODATA) держится
// NegativeTTL.
func (r *Resolver) ttlOf(msg *dnsmessage.Message) time.Duration {
	if len(msg.Answers) == 0 {
		return r.cfg.NegativeTTL
	}
	min := ^uint32(0)
	for _, a := range msg.Answers {
		if a.Header.TTL < min {
			min = a.Header.TTL
		}
	}
	ttl := time.Duration(min) * time.Second
	if ttl < r.cfg.MinTTL {
		ttl = r.cfg.MinTTL
	}
	if ttl > r.cfg.MaxTTL {
		ttl = r.cfg.MaxTTL
	}
	return ttl
}

// sweepLocked выбрасывает просроченное.
func (r *Resolver) sweepLocked(now time.Time) {
	for k, e := range r.cache {
		if !now.Before(e.expires) {
			delete(r.cache, k)
		}
	}
}

// evictLocked держит потолок. Кэш — это кэш: при переполнении выбрасывается
// запись, а не отказывается резолв. Порядок выброса произвольный: LRU здесь
// стоил бы списка на каждый запрос, а выигрыш на потолке в тысячи имён
// незаметен.
func (r *Resolver) evictLocked() {
	for k := range r.cache {
		if len(r.cache) <= r.cfg.MaxEntries {
			return
		}
		delete(r.cache, k)
	}
}

// aged — копия ответа с TTL, уменьшенным на прожитое. Копируются заголовки
// записей, а не тела: тела неизменяемы, а TTL правится у каждой.
func aged(msg *dnsmessage.Message, elapsed time.Duration) *dnsmessage.Message {
	out := *msg
	out.Answers = ageAll(msg.Answers, elapsed)
	out.Authorities = ageAll(msg.Authorities, elapsed)
	out.Additionals = ageAll(msg.Additionals, elapsed)
	return &out
}

func ageAll(rs []dnsmessage.Resource, elapsed time.Duration) []dnsmessage.Resource {
	if len(rs) == 0 {
		return nil
	}
	sec := uint32(elapsed / time.Second)
	out := make([]dnsmessage.Resource, len(rs))
	copy(out, rs)
	for i := range out {
		if out[i].Header.TTL > sec {
			out[i].Header.TTL -= sec
		} else {
			out[i].Header.TTL = 0
		}
	}
	return out
}
