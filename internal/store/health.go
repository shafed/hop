package store

import (
	"slices"
	"time" //hop:realtime — только длительность дебаунса; «сейчас» берётся из clock

	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/policy"
)

// healthDebounce — как часто живость доходит до диска (§2 SPEC, §4 регистра).
// Отсчитывается по часам стора, а не по настоящему времени: иначе S38 стоял бы
// тридцать секунд (требование 4, docs/verification-store.md §2).
const healthDebounce = 30 * time.Second

// PutHealth принимает срез живости от health и кладёт его на диск не чаще раза
// в healthDebounce (§2, шаг 6 регистра).
//
// На диск идут только state, rtt_ms и last_probe_at. Окно, traffic_failures и
// last_error описывают «прямо сейчас» и после паузы врут: окно, пролежавшее
// выключенным час, воскресило бы узел по §6.3 из записей, которым час. Отсюда
// же берётся вторая половина обещания §2 — восстановленный state не даёт узлу
// считаться проверенным: пустое окно означает probed = false, и стартовый
// бюджет §5.6 отсчитывается заново.
//
// Обрезка идёт здесь, а не при записи: в памяти стора нет смысла держать вторую
// копию окна — источник истины у health, и отданная наружу копия часовой
// давности была бы ровно той полуправдой, от которой §2 избавляется.
//
// Живость узлов, которых в сторе нет, отбрасывается. Это не новое решение, а
// та же причина, по которой Apply удаляет живость ушедших: id выдаются заново,
// и переживший рестарт мусор однажды приклеился бы к чужому узлу.
//
// Ошибки не возвращает — подпись из §2 регистра. Отказ записи при этом ничего
// не теряет: секция остаётся грязной, и следующий вызов или Close повторят
// запись, а Close отдаст ошибку наружу.
func (s *Store) PutHealth(hs []health.NodeHealth) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	for _, h := range hs {
		if h.NodeID == "" {
			continue
		}
		if _, known := s.nodes[h.NodeID]; !known {
			continue
		}
		slice := healthSlice(h)
		if old, ok := s.healthByNode[h.NodeID]; ok && sameHealth(old, slice) {
			continue
		}
		s.healthByNode[h.NodeID] = slice
		s.dirty |= sectionHealth
	}

	now := s.clk.Now()
	// Дебаунс — по переднему фронту: первый срез уходит на диск сразу, дальше не
	// чаще раза в тридцать секунд. Так рестарт сразу после старта агента застаёт
	// на диске уже что-то, а не пустой файл, и при этом частота записи ограничена
	// ровно так, как требует §2.
	due := s.dirty&sectionHealth != 0 && !now.Before(s.lastHealthAt.Add(healthDebounce))
	s.mu.Unlock()

	if !due {
		return
	}
	_ = s.transact(func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.dirty&sectionHealth == 0 {
			// Пока ждали замок, живость записал кто-то другой — писать нечего.
			return nil
		}
		if err := s.writeDirtyLocked(); err != nil {
			return err
		}
		// Отсчёт дебаунса ведётся от удавшейся записи: после отказа следующий
		// вызов обязан попробовать снова, а не ждать тридцать секунд.
		s.lastHealthAt = now
		return nil
	})
}

// Health отдаёт живость узла, известную стору: срез с диска либо последнее, что
// принёс PutHealth.
func (s *Store) Health(nodeID string) (health.NodeHealth, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	h, ok := s.healthByNode[nodeID]
	if !ok {
		return health.NodeHealth{}, false
	}
	return cloneHealth(h), true
}

// healthSlice оставляет от живости то, чему можно верить после паузы (§2).
//
// Единственное место, где спрашивается политика health_slice: выключенная
// отдаёт NodeHealth целиком, вместе с окном, — и тогда запись, чтение и оба
// охраняемых свойства ломаются разом (S36, S37).
func healthSlice(h health.NodeHealth) health.NodeHealth {
	if !policy.HealthSlice.On() {
		return cloneHealth(h)
	}
	return health.NodeHealth{
		NodeID:      h.NodeID,
		State:       h.State,
		RTT:         h.RTT,
		LastProbeAt: h.LastProbeAt,
	}
}

// cloneHealth копирует окно: без него отданная наружу живость делила бы срез с
// тем, кто её принёс.
func cloneHealth(h health.NodeHealth) health.NodeHealth {
	h.Window = slices.Clone(h.Window)
	return h
}

// sameHealth — совпадает ли живость во всём. Своя функция, а не ==: у
// NodeHealth есть срез Window, и структура со срезом несравнима.
//
// Нужна затем, чтобы повторный срез без изменений не пачкал секцию: файл, ничем
// не отличающийся от лежащего на диске, переписывать незачем — та же бережность,
// которой требует S8.
func sameHealth(a, b health.NodeHealth) bool {
	return a.NodeID == b.NodeID &&
		a.State == b.State &&
		a.RTT == b.RTT &&
		a.LastProbeAt.Equal(b.LastProbeAt) &&
		a.TrafficFailures == b.TrafficFailures &&
		a.LastError == b.LastError &&
		slices.Equal(a.Window, b.Window)
}
