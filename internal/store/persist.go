package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/node"
)

// Три файла, а не один: §2 развёл Node и NodeHealth именно потому, что второе
// меняется на порядки чаще, — в одном файле каждая проба переписывала бы ключи
// доступа.
const (
	groupsFile = "groups.json"
	nodesFile  = "nodes.json"
	healthFile = "health.json"
)

// mkdir создаёт каталог стора и доводит права до 0700.
//
// MkdirAll уважает umask, а §6.14 — нет: каталог обязан быть 0700 и тогда,
// когда umask мягче, и тогда, когда каталог остался от прошлой установки.
func (s *Store) mkdir() error {
	if err := os.MkdirAll(s.dir, dirMode); err != nil {
		return fmt.Errorf("store: каталог: %w", err)
	}
	if err := os.Chmod(s.dir, dirMode); err != nil {
		return fmt.Errorf("store: права каталога: %w", err)
	}
	return nil
}

func (s *Store) load() error {
	var groups []Group
	if err := readJSON(filepath.Join(s.dir, groupsFile), &groups); err != nil {
		return err
	}
	var nodes []node.Node
	if err := readJSON(filepath.Join(s.dir, nodesFile), &nodes); err != nil {
		return err
	}
	var hs []health.NodeHealth
	if err := readJSON(filepath.Join(s.dir, healthFile), &hs); err != nil {
		return err
	}
	for _, g := range groups {
		s.groups[g.ID] = g
	}
	for _, n := range nodes {
		s.nodes[n.ID] = n
	}
	for _, h := range hs {
		s.health[h.NodeID] = h
	}
	return nil
}

// saveState пишет группы и узлы. Зовётся под уже взятым замком.
func (s *Store) saveState() error {
	groups := make([]Group, 0, len(s.groups))
	for _, g := range s.groups {
		groups = append(groups, g)
	}
	slices.SortFunc(groups, func(a, b Group) int { return strings.Compare(a.ID, b.ID) })

	nodes := make([]node.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		nodes = append(nodes, n)
	}
	slices.SortFunc(nodes, func(a, b node.Node) int { return strings.Compare(a.ID, b.ID) })

	if err := writeJSON(filepath.Join(s.dir, groupsFile), groups); err != nil {
		return err
	}
	return writeJSON(filepath.Join(s.dir, nodesFile), nodes)
}

// saveHealth пишет историю. Зовётся под уже взятым замком.
func (s *Store) saveHealth() error {
	hs := make([]health.NodeHealth, 0, len(s.health))
	for _, h := range s.health {
		hs = append(hs, h)
	}
	slices.SortFunc(hs, func(a, b health.NodeHealth) int { return strings.Compare(a.NodeID, b.NodeID) })
	return writeJSON(filepath.Join(s.dir, healthFile), hs)
}

// readJSON читает файл, если он есть. Отсутствие файла — не ошибка: первый
// запуск начинается с пустого стора.
func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: чтение %s: %w", filepath.Base(path), err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("store: разбор %s: %w", filepath.Base(path), err)
	}
	return nil
}

// writeJSON пишет через временный файл и переименование: обрыв на середине
// записи не должен оставлять стор с половиной подписки.
//
// Права 0600 ставятся дважды — при создании и явным chmod, — потому что
// первое зависит от umask, а §6.14 от него зависеть не может.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: сборка %s: %w", filepath.Base(path), err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return fmt.Errorf("store: запись %s: %w", filepath.Base(path), err)
	}
	if err := os.Chmod(tmp, fileMode); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("store: права %s: %w", filepath.Base(path), err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("store: запись %s: %w", filepath.Base(path), err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("store: закрытие %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("store: замена %s: %w", filepath.Base(path), err)
	}
	return nil
}
