// Package store — персистентность агента: группы, узлы, здоровье (§3.4).
//
// Каталог `0700`, файлы `0600` (§6.14): в узлах лежат ключи доступа, и права
// здесь — не гигиена, а единственное, что отделяет их от любого процесса
// пользователя.
//
// Обновление подписки — diff, а не замена (§5.8). Полная замена стирала бы
// историю проб и текущий выбор каждые несколько часов, и автопереключение
// начинало бы с нуля, переопрашивая всю подписку.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time" //hop:realtime

	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/node"
)

// Права §6.14. Каталог — только владельцу, файлы с ключами — тоже.
const (
	dirMode  = 0o700
	fileMode = 0o600
)

// ManualGroup — группа для узлов, добавленных ссылкой (`hop node add`, §С2).
// Источника у неё нет, обновлению подписки она не подлежит.
const ManualGroup = "manual"

// Group — §2. Одна подписка либо manual.
type Group struct {
	ID            string
	Name          string
	SourceURL     string // пусто для manual
	LastUpdatedAt time.Time
	// QuotaInfo — сырой заголовок Subscription-UserInfo, если пришёл. Хранится
	// как есть: что с ним делать, §7 ещё не решил.
	QuotaInfo string
	// NodeOrder — порядок узлов как в подписке.
	NodeOrder []string

	AutoUpdate     bool
	UpdateInterval time.Duration
}

// Diff — результат обновления подписки (§5.8). Kept — узлы, сохранившие id и
// историю: именно это утверждает T18.
type Diff struct {
	Added   []string
	Kept    []string
	Removed []string
}

// Store — стор агента.
type Store struct {
	dir string

	mu     sync.RWMutex
	groups map[string]Group
	nodes  map[string]node.Node
	health map[string]health.NodeHealth
}

// Open открывает каталог стора, создавая его с правами 0700, и читает
// состояние.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("store: пустой путь к каталогу")
	}
	s := &Store{
		dir:    dir,
		groups: map[string]Group{},
		nodes:  map[string]node.Node{},
		health: map[string]health.NodeHealth{},
	}
	if err := s.mkdir(); err != nil {
		return nil, err
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close закрывает стор. Сбрасывать нечего: каждая правка доезжает до диска в
// том же вызове, что её сделал, — иначе убийство агента (§6.2 это штатный
// сценарий, а не авария) теряло бы последнюю подписку.
func (s *Store) Close() error { return nil }

// Groups — все группы.
func (s *Store) Groups() []Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Group, 0, len(s.groups))
	for _, g := range s.groups {
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b Group) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Group — группа по id.
func (s *Store) Group(id string) (Group, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[id]
	return g, ok
}

// PutGroup создаёт или обновляет группу.
func (s *Store) PutGroup(g Group) error {
	if g.ID == "" {
		return errors.New("store: у группы пустой id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Порядок узлов принадлежит ApplySubscription. Правка имени или квоты не
	// должна его обнулять: иначе обновление названия группы стирало бы
	// подписку целиком.
	if old, ok := s.groups[g.ID]; ok && g.NodeOrder == nil {
		g.NodeOrder = old.NodeOrder
	}
	s.groups[g.ID] = g
	return s.saveState()
}

// DeleteGroup удаляет группу вместе с её узлами и их историей.
func (s *Store) DeleteGroup(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[id]; !ok {
		return fmt.Errorf("store: группа %q не найдена", id)
	}
	delete(s.groups, id)
	for nodeID, n := range s.nodes {
		if n.GroupID == id {
			delete(s.nodes, nodeID)
			delete(s.health, nodeID)
		}
	}
	if err := s.saveState(); err != nil {
		return err
	}
	return s.saveHealth()
}

// Nodes — узлы группы в порядке подписки.
func (s *Store) Nodes(groupID string) []node.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodesOf(groupID)
}

// AllNodes — узлы всех групп.
func (s *Store) AllNodes() []node.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.groups))
	for id := range s.groups {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var out []node.Node
	for _, id := range ids {
		out = append(out, s.nodesOf(id)...)
	}
	return out
}

// Node — узел по id.
func (s *Store) Node(id string) (node.Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.nodes[id]
	return n, ok
}

// PutNode кладёт одиночный узел (`hop node add`, §С2), выдавая ему id, если
// его ещё нет.
func (s *Store) PutNode(n node.Node) (node.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n.GroupID == "" {
		n.GroupID = ManualGroup
	}
	if n.ID == "" {
		n.ID = newID()
	}
	if err := n.Validate(); err != nil {
		return node.Node{}, err
	}
	s.nodes[n.ID] = n

	g, ok := s.groups[n.GroupID]
	if !ok {
		g = Group{ID: n.GroupID, Name: n.GroupID}
	}
	if !slices.Contains(g.NodeOrder, n.ID) {
		g.NodeOrder = append(g.NodeOrder, n.ID)
	}
	s.groups[n.GroupID] = g
	return n, s.saveState()
}

// ApplySubscription сливает разобранную подписку в группу (§5.8).
//
// Ключ слияния — поле MergeKey, проставленное разбором (§6.16). Узел с
// совпавшим ключом сохраняет id и историю проб, даже если у него сменились
// транспорт, SNI или имя; исчезнувший из подписки удаляется вместе с историей.
//
// Стор не считает ключ сам: он не знает ни про ссылки, ни про их нормализацию
// (§3.4). Развилка политики merge_key живёт в sub.MergeKey.
func (s *Store) ApplySubscription(groupID string, parsed []node.Node) (Diff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	g, ok := s.groups[groupID]
	if !ok {
		return Diff{}, fmt.Errorf("store: группа %q не найдена", groupID)
	}
	// Старый состав по ключу. Совпадение с ним и есть «тот же узел».
	old := map[string]node.Node{}
	for _, n := range s.nodesOf(groupID) {
		if _, dup := old[n.MergeKey]; !dup {
			old[n.MergeKey] = n
		}
	}

	// Сначала слияние целиком в локальных переменных, и только потом правка
	// стора: отказ на пятом узле не должен оставлять группу с четырьмя
	// применёнными и остальными старыми.
	var (
		diff   Diff
		staged = make([]node.Node, 0, len(parsed))
	)
	for i, p := range parsed {
		// Пустой ключ склеил бы всю подписку в один узел, поэтому это отказ,
		// а не повод посчитать ключ здесь: считать его стору нечем (§3.4).
		if p.MergeKey == "" {
			return Diff{}, fmt.Errorf("store: узел #%d без ключа слияния", i)
		}
		p.GroupID = groupID
		if prev, ok := old[p.MergeKey]; ok {
			// Тот же узел: id переживает обновление (§2), а с ним и запись
			// NodeHealth — её никто не трогает.
			p.ID = prev.ID
			delete(old, p.MergeKey)
			diff.Kept = append(diff.Kept, p.ID)
		} else {
			p.ID = newID()
			diff.Added = append(diff.Added, p.ID)
		}
		if err := p.Validate(); err != nil {
			return Diff{}, err
		}
		staged = append(staged, p)
	}

	order := make([]string, 0, len(staged))
	for _, p := range staged {
		s.nodes[p.ID] = p
		order = append(order, p.ID)
	}

	// Остатки — то, что исчезло из подписки. История уходит вместе с узлом:
	// держать её значило бы копить окна проб мёртвых ссылок навсегда.
	for _, n := range old {
		delete(s.nodes, n.ID)
		delete(s.health, n.ID)
		diff.Removed = append(diff.Removed, n.ID)
	}
	slices.Sort(diff.Removed)

	g.NodeOrder = order
	s.groups[groupID] = g

	if err := s.saveState(); err != nil {
		return Diff{}, err
	}
	if err := s.saveHealth(); err != nil {
		return Diff{}, err
	}
	return diff, nil
}

// Health — сохранённая история узла.
func (s *Store) Health(nodeID string) (health.NodeHealth, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.health[nodeID]
	return h, ok
}

// PutHealth сохраняет историю узла. Пишется редко: §2 разделил Node и
// NodeHealth именно потому, что второе меняется на порядки чаще, и складывать
// их в один файл значило бы переписывать ключи на каждой пробе.
func (s *Store) PutHealth(h health.NodeHealth) error {
	if h.NodeID == "" {
		return errors.New("store: история без node_id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.health[h.NodeID] = h
	return s.saveHealth()
}

// nodesOf — узлы группы в порядке node_order. Зовётся под уже взятым замком.
func (s *Store) nodesOf(groupID string) []node.Node {
	g, ok := s.groups[groupID]
	if !ok {
		return nil
	}
	out := make([]node.Node, 0, len(g.NodeOrder))
	for _, id := range g.NodeOrder {
		if n, ok := s.nodes[id]; ok {
			out = append(out, n)
		}
	}
	return out
}

// newID — 64 бита из crypto/rand. Времени в id нет намеренно: часы здесь
// инъектируются и в тестах стоят на месте (§8.1), а id обязан быть уникален и
// там.
func newID() string {
	var b [8]byte
	rand.Read(b[:]) // crypto/rand.Read ошибок не возвращает
	return hex.EncodeToString(b[:])
}
