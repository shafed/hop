package store

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

// Apply записывает состав группы, решённый слиянием (§5.8, шаг 5 регистра
// docs/verification-store.md §8).
//
// Стор про слияние не знает ничего: ему приносят готовый состав. Здесь он
// только кладётся на диск — под замком Р14 и целиком: «прочитать — изменить —
// записать» кончается записью, а не пометкой «грязно», иначе процесс команды,
// применивший подписку и вышедший, унёс бы её с собой.
//
// Отметку времени группы ставит стор, а не слияние: Diff намеренно оставлен
// чистой функцией и часов не знает (см. internal/subscription/merge.go), а
// время в продукте берётся только из clock.Clock (§8.1).
//
// Узлы, ушедшие из состава, удаляются вместе со своей живостью. §1/С8 обещает,
// что «исчезнувшие удаляются», а живость мёртвого id — мусор, который переживёт
// рестарт и однажды приклеится к чужому узлу: id выдаются заново, и совпадение
// стоило бы чужой истории проб. Живость выживших не трогается вовсе — это
// вторая половина T18.
func (s *Store) Apply(groupID string, m Merged) error {
	if groupID == "" {
		return errors.New("store: состав применён к группе без id")
	}
	if err := checkComposition(groupID, m); err != nil {
		return err
	}
	// Закрытый стор отсекается до замка: замок закрыт вместе с ним, и попытка
	// его взять дала бы отказ про дескриптор вместо внятного «стор закрыт».
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return errors.New("store: стор закрыт")
	}

	return s.transact(func() error {
		s.mu.Lock()
		defer s.mu.Unlock()

		if err := s.applyLocked(groupID, m); err != nil {
			return err
		}
		return s.writeDirtyLocked()
	})
}

// checkComposition отбраковывает состав, который нельзя записать, до того как
// изменена хоть одна запись: применение состава не бывает наполовину.
func checkComposition(groupID string, m Merged) error {
	seen := make(map[string]bool, len(m.Nodes))
	for _, n := range m.Nodes {
		switch {
		case n.ID == "":
			return fmt.Errorf("store: в составе группы %q есть узел без id", groupID)
		case n.GroupID != groupID:
			// Слияние не пересекает границу группы (Р9). Здесь это последнее
			// место, где чужой узел ещё можно заметить: дальше он лёг бы в
			// nodes.json с чужим group_id и достался бы чужой подписке.
			return fmt.Errorf("store: узел %q помечен группой %q, а состав применяется к %q", n.ID, n.GroupID, groupID)
		case seen[n.ID]:
			return fmt.Errorf("store: узел %q встречается в составе группы %q дважды", n.ID, groupID)
		}
		seen[n.ID] = true
	}
	return nil
}

// applyLocked меняет состояние. Требует s.mu и вызывается под файловым замком.
func (s *Store) applyLocked(groupID string, m Merged) error {
	for _, n := range m.Nodes {
		if old, ok := s.nodes[n.ID]; ok && old.GroupID != groupID {
			return fmt.Errorf("store: узел %q уже принадлежит группе %q — состав группы %q его не получит (Р9)", n.ID, old.GroupID, groupID)
		}
	}

	keep := make(map[string]bool, len(m.Nodes))
	for _, n := range m.Nodes {
		keep[n.ID] = true
	}

	// Ушедшие считаются по составу, а не по Merged.Removed: состав — это то,
	// чем группа стала, и узел, которого в нём нет, остался бы в сторе
	// навсегда, если бы слияние забыло назвать его в Removed. Для состава,
	// собранного Diff, оба списка совпадают.
	var gone []string
	for id, n := range s.nodes {
		if n.GroupID == groupID && !keep[id] {
			gone = append(gone, id)
		}
	}
	slices.Sort(gone) // порядок удаления не значим, но повторяемость вывода — да

	healthDropped := false
	for _, id := range gone {
		delete(s.nodes, id)
		if _, ok := s.healthByNode[id]; ok {
			delete(s.healthByNode, id)
			healthDropped = true
		}
	}

	nodesChanged := len(gone) > 0
	for _, n := range m.Nodes {
		old, ok := s.nodes[n.ID]
		if !ok || !sameNode(old, n) {
			nodesChanged = true
		}
		// Клон: иначе состав группы держал бы те же карты params, что и
		// вызывающий, и правка одного меняла бы другое.
		s.nodes[n.ID] = cloneNode(n)
	}

	order := m.Order
	if len(order) == 0 && len(m.Nodes) > 0 {
		// Состав без порядка — след вызывающего, собравшего Merged руками.
		// Порядок восстанавливается из состава: узел, выпавший из node_order,
		// уходит в хвост Nodes() и теряет своё место при равных rtt (§6.4).
		order = make([]string, 0, len(m.Nodes))
		for _, n := range m.Nodes {
			order = append(order, n.ID)
		}
	}

	g, known := s.groups[groupID]
	if !known {
		// Группы нет — заводится с одним лишь id. Метаданные подписки (имя,
		// source_url, quota_info) Merged не несёт, и этой дорогой их не
		// записать: они принадлежат `hop sub add`. Отказ здесь был бы хуже —
		// он сделал бы первый импорт невозможным вовсе.
		g = Group{ID: groupID}
		s.groupOrder = append(s.groupOrder, groupID)
	}
	orderChanged := !slices.Equal(g.NodeOrder, order)
	g.NodeOrder = slices.Clone(order)
	// Р8: порядок принадлежит провайдеру и переписывается на каждом слиянии.
	g.LastUpdatedAt = s.clk.Now()
	s.groups[groupID] = g

	// Грязным помечается только изменившееся. Файл, который не изменился, не
	// переписывается: S8 требует этого от health.json, и та же бережность
	// уместна для nodes.json — он секретный и переписывается атомарно, то есть
	// не бесплатно.
	s.dirty |= sectionGroups
	if nodesChanged || orderChanged {
		// Порядок узлов в nodes.json берётся из node_order (см. encodeNodes),
		// поэтому смена порядка — тоже изменение файла.
		s.dirty |= sectionNodes
	}
	if healthDropped {
		s.dirty |= sectionHealth
	}
	return nil
}

// sameNode — совпадают ли узлы во всём. Своя функция, а не ==: у Node есть
// карта Params, и структура с картой несравнима.
func sameNode(a, b Node) bool {
	return a.ID == b.ID &&
		a.GroupID == b.GroupID &&
		a.MergeKey == b.MergeKey &&
		a.Name == b.Name &&
		a.Protocol == b.Protocol &&
		a.Server == b.Server &&
		a.Port == b.Port &&
		a.Transport == b.Transport &&
		a.Security == b.Security &&
		a.Supported == b.Supported &&
		a.UnsupReason == b.UnsupReason &&
		a.RawLink == b.RawLink &&
		maps.Equal(a.Params, b.Params)
}
