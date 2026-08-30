package store

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/policy"
)

// Права из §2 и §6.14. Секрет — весь nodes.json целиком, а не перечисленные
// поля (Р12): params несёт uuid, пароли и pbk, а список полей устаревает на
// каждом новом протоколе.
const (
	dirPerm    fs.FileMode = 0o700
	secretPerm fs.FileMode = 0o600
	publicPerm fs.FileMode = 0o644
)

// section — часть состояния, живущая в своём файле. Грязные секции пишутся по
// отдельности: живость обновляется каждые секунды, и переписывать вместе с ней
// узлы значило бы возвращать тот самый общий файл, который §2 разделил.
type section uint8

const (
	sectionGroups section = 1 << iota
	sectionNodes
	sectionHealth
	sectionSettings
)

// Store — персистентность узлов, групп и живости (§3.4).
//
// Конкретный тип, а не интерфейс: второй реализации не предвидится, а
// интерфейс ради тестов спрятал бы как раз то, что тесты проверяют, — диск
// (docs/verification-store.md §2).
//
// Нулевое значение неработоспособно, создавать через Open.
type Store struct {
	root string
	clk  clock.Clock
	w    *writer
	lock *fileLock

	// lockOn — политика store_lock, снятая один раз при Open. Выключенная
	// означает «второй писатель не отсекается» и ломает S28.
	lockOn bool

	// txMu упорядочивает транзакции внутри процесса. Файловый замок этого не
	// делает: он рекомендательный и берётся на дескриптор, то есть две
	// горутины одного процесса возьмут его обе.
	txMu sync.Mutex

	mu         sync.Mutex
	groupOrder []string
	groups     map[string]Group
	nodes      map[string]Node
	// healthByNode — срез живости: то, чему можно верить после паузы (§2).
	// Пополняется PutHealth, отдаётся Health, переживает рестарт.
	healthByNode map[string]health.NodeHealth
	// settings — настройки §6.10 и §5.7, прочитанные при Open. Только
	// чтение: файл принадлежит человеку, стор его не правит и заводит лишь
	// пустым, если файла нет.
	settings Settings
	// lastHealthAt — когда живость последний раз дошла до диска. По часам
	// стора: дебаунс §2 не имеет права тратить настоящее время (см. health.go).
	lastHealthAt time.Time
	dirty        section
	closed       bool
}

// Open открывает стор в каталоге root. Каталог создаётся с правами 0700, если
// его нет.
//
// Корень задаётся снаружи, а не берётся из os.UserConfigDir внутри: иначе
// проверки работали бы в настоящем сторе разработчика и не могли бы идти
// параллельно (требование 3, docs/verification-store.md §2).
//
// Битые файлы обрабатываются несимметрично (Р13): нечитаемый health.json — не
// ошибка, живость считается пустой и восстановится первым же раундом проб;
// нечитаемые nodes.json или groups.json — отказ старта, потому что пустой
// список узлов при живом файле выглядит как «подписка исчезла» и провоцирует
// пользователя добавить её заново, потеряв всё окончательно.
func Open(root string, clk clock.Clock) (*Store, error) {
	if root == "" {
		return nil, errors.New("store: пустой путь к каталогу стора")
	}
	if clk == nil {
		return nil, errors.New("store: стор открыт без часов")
	}
	if err := os.MkdirAll(root, dirPerm); err != nil {
		return nil, fmt.Errorf("store: не создать каталог %s: %w", root, err)
	}
	// MkdirAll накладывает umask, а §6.14 требует ровно 0700: каталог с
	// секретами не бывает «в основном закрытым».
	if err := os.Chmod(root, dirPerm); err != nil {
		return nil, fmt.Errorf("store: не выставить права %04o на каталог %s: %w", dirPerm, root, err)
	}

	s := &Store{
		root:         root,
		clk:          clk,
		w:            newWriter(root, policy.AtomicWrite.On()),
		lockOn:       policy.StoreLock.On(),
		groups:       make(map[string]Group),
		nodes:        make(map[string]Node),
		healthByNode: make(map[string]health.NodeHealth),
	}
	lk, err := openLock(lockPath(root))
	if err != nil {
		return nil, err
	}
	s.lock = lk

	if err := s.load(); err != nil {
		_ = s.lock.close()
		return nil, err
	}
	return s, nil
}

// load читает все три файла и приводит каталог в порядок.
//
// Чтение идёт без замка: rename атомарен, и читатель всегда видит либо прежний
// файл целиком, либо новый целиком (У4). Замок берётся только тогда, когда
// Open обязан что-то изменить — создать недостающие файлы или убрать мусор от
// убитого процесса; иначе `hop nodes` при работающем агенте ждал бы замок ради
// одного чтения.
//
// И даже тогда ЖДЁТ его только запись. Уборка замок пробует и, если занят,
// уходит ни с чем: временный файл живёт ровно столько, сколько идёт чужая
// запись, и занятый замок — это и есть доказательство, что владелец файла жив,
// а файл не мусор. Ждать здесь значило бы принимать чужую запись за мусор от
// убитого процесса и стоять из-за неё. Замерено на живом писателе без пауз
// (cmd/hop/measure_test.go, TestS47MeasureSweepLockUnderALiveWriter): худший
// `hop nodes` из сорока — от 457 мс до 2.063 с в пяти прогонах при медиане
// 4 мс, то есть выброс, а не общее замедление; после — 6 мс. Платил и сам
// писатель: его худший Flush — 51 мс, ровно круг опроса lockRetry, потерянный
// в пользу подметающего читателя; после — 1.1 мс.
//
// Пропущенная уборка ничего не теряет: мусор доживёт до следующего Open, у
// которого замок свободен (S26, S47).
func (s *Store) load() error {
	if err := s.readGroups(); err != nil {
		return err
	}
	if err := s.readNodes(); err != nil {
		return err
	}
	s.readHealth()
	if err := s.readSettings(); err != nil {
		return err
	}

	if err := s.fixPerms(); err != nil {
		return err
	}
	missing, err := s.missingSections()
	if err != nil {
		return err
	}
	if missing != 0 {
		// Ради недостающих файлов замок ждут: это запись, а не уборка. Стор
		// без файлов невозможно проверить на права (§6.14), и случается это
		// один раз за жизнь каталога, а не на каждом чтении.
		return s.transact(func() error {
			if err := s.w.sweep(); err != nil {
				return err
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			s.dirty |= missing
			return s.writeDirtyLocked()
		})
	}

	garbage, err := s.hasTempGarbage()
	if err != nil {
		return err
	}
	if !garbage {
		return nil
	}
	// Не состоялась — и хорошо: занятый замок означает живого писателя, чей
	// временный файл трогать нельзя (см. комментарий к load).
	_, err = s.tryTransact(s.w.sweep)
	return err
}

func (s *Store) readGroups() error {
	raw, ok, err := readFile(filepath.Join(s.root, groupsFile))
	if err != nil || !ok {
		return err
	}
	order, groups, err := decodeGroups(raw)
	if err != nil {
		return fmt.Errorf("store: %s нечитаем (%w); файл не тронут — почините или удалите его вручную, пустой список групп молча заменил бы ваши подписки", groupsFile, err)
	}
	s.groupOrder, s.groups = order, groups
	return nil
}

func (s *Store) readNodes() error {
	raw, ok, err := readFile(filepath.Join(s.root, nodesFile))
	if err != nil || !ok {
		return err
	}
	nodes, err := decodeNodes(raw)
	if err != nil {
		return fmt.Errorf("store: %s нечитаем (%w); файл не тронут — почините или удалите его вручную, пустой список узлов выглядел бы как исчезнувшая подписка", nodesFile, err)
	}
	s.nodes = nodes
	return nil
}

// readHealth читает живость и молчит о любой её порче (Р13): потерянная
// живость стоит одного раунда проб, и отказывать из-за неё в старте дороже,
// чем начать с пустого среза.
func (s *Store) readHealth() {
	raw, ok, err := readFile(filepath.Join(s.root, healthFile))
	if err != nil || !ok {
		return
	}
	hs, err := decodeHealth(raw)
	if err != nil {
		return
	}
	s.healthByNode = hs
}

// readFile отдаёт содержимое файла; ok == false означает «файла нет».
func readFile(path string) ([]byte, bool, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		return raw, true, nil
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("store: не прочитать %s: %w", filepath.Base(path), err)
	}
}

// files — раскладка §2: имя, права и секция состояния.
func files() []struct {
	name string
	perm fs.FileMode
	sec  section
} {
	return []struct {
		name string
		perm fs.FileMode
		sec  section
	}{
		{groupsFile, publicPerm, sectionGroups},
		{nodesFile, secretPerm, sectionNodes},
		{healthFile, publicPerm, sectionHealth},
		{settingsFile, publicPerm, sectionSettings},
	}
}

// missingSections — секции, файлов которых ещё нет. Они будут созданы пустыми:
// стор, у которого файлы появляются только после первой записи, невозможно
// проверить на права, а §6.14 — не про будущее состояние каталога.
func (s *Store) missingSections() (section, error) {
	var missing section
	for _, f := range files() {
		_, err := os.Stat(filepath.Join(s.root, f.name))
		switch {
		case err == nil:
		case errors.Is(err, fs.ErrNotExist):
			missing |= f.sec
		default:
			return 0, fmt.Errorf("store: не проверить %s: %w", f.name, err)
		}
	}
	return missing, nil
}

// fixPerms приводит права уже существующих файлов к §2. Стор, доставшийся от
// прежней версии или скопированный с правами по умолчанию, иначе оставил бы
// nodes.json читаемым для всех.
func (s *Store) fixPerms() error {
	for _, f := range files() {
		path := filepath.Join(s.root, f.name)
		if _, err := os.Stat(path); err != nil {
			continue // отсутствующий файл получит права при создании
		}
		if err := os.Chmod(path, f.perm); err != nil {
			return fmt.Errorf("store: не выставить права %04o на %s: %w", f.perm, f.name, err)
		}
	}
	return nil
}

func (s *Store) hasTempGarbage() (bool, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return false, fmt.Errorf("store: не прочитать каталог %s: %w", s.root, err)
	}
	for _, e := range entries {
		if !e.IsDir() && isTempName(e.Name()) {
			return true, nil
		}
	}
	return false, nil
}

// transact выполняет «прочитать — изменить — записать» под замком (Р14).
// Отсюда же им воспользуется Apply (шаг 5 регистра).
func (s *Store) transact(fn func() error) error {
	s.txMu.Lock()
	defer s.txMu.Unlock()

	if s.lockOn {
		if err := s.lock.acquire(s.clk); err != nil {
			return err
		}
		defer s.lock.release()
	}
	return fn()
}

// tryTransact — та же транзакция, но без ожидания: замок пробуется один раз,
// и занятый означает «не состоялась», а не ошибку. Отданный false — это
// «сейчас работает кто-то другой», и звать fn в этом случае нельзя.
//
// Существует ради уборки в load: ей нужен замок не для того, чтобы дождаться
// своей очереди, а для того, чтобы отличить брошенный временный файл от чужого
// живого.
func (s *Store) tryTransact(fn func() error) (bool, error) {
	s.txMu.Lock()
	defer s.txMu.Unlock()

	if s.lockOn {
		ok, err := s.lock.try()
		if err != nil {
			return false, fmt.Errorf("store: не взять замок %s: %w", s.lock.path, err)
		}
		if !ok {
			return false, nil
		}
		defer s.lock.release()
	}
	return true, fn()
}

// Groups отдаёт группы в том порядке, в котором они лежат в сторе.
func (s *Store) Groups() []Group {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Group, 0, len(s.groupOrder))
	for _, id := range s.groupOrder {
		g, ok := s.groups[id]
		if !ok {
			continue
		}
		g.NodeOrder = slices.Clone(g.NodeOrder)
		out = append(out, g)
	}
	return out
}

// Nodes отдаёт узлы группы в порядке node_order (Р8): при равных rtt выигрывает
// первый по порядку (§6.4), поэтому порядок — часть наблюдаемого, а не деталь
// хранения.
//
// Узлы группы, которых в node_order почему-то нет, идут хвостом в порядке id:
// потерять узел из-за расхождения двух файлов хуже, чем показать его не на
// своём месте.
func (s *Store) Nodes(groupID string) []Node {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Node, 0, len(s.groups[groupID].NodeOrder))
	taken := make(map[string]bool)
	for _, id := range s.groups[groupID].NodeOrder {
		n, ok := s.nodes[id]
		if !ok || n.GroupID != groupID || taken[id] {
			continue
		}
		taken[id] = true
		out = append(out, cloneNode(n))
	}

	var rest []string
	for id, n := range s.nodes {
		if n.GroupID == groupID && !taken[id] {
			rest = append(rest, id)
		}
	}
	slices.Sort(rest)
	for _, id := range rest {
		out = append(out, cloneNode(s.nodes[id]))
	}
	return out
}

// Node отдаёт узел по id.
func (s *Store) Node(id string) (Node, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.nodes[id]
	if !ok {
		return Node{}, false
	}
	return cloneNode(n), true
}

// cloneNode отдаёт узел так, чтобы правка отданной копии не меняла стор:
// Params — карта, и без клона граница держалась бы на договорённости не писать
// в чужое.
func cloneNode(n Node) Node {
	n.Params = maps.Clone(n.Params)
	return n
}

// Flush синхронен: вернулся без ошибки — данные на диске (требование 5,
// docs/verification-store.md §2). Тесту и выходу не нужно ни спать, ни
// опрашивать файл в цикле.
func (s *Store) Flush() error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return errors.New("store: стор закрыт")
	}
	return s.transact(func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.writeDirtyLocked()
	})
}

// Close дописывает несохранённое и отпускает замок. Повторный вызов безвреден.
//
// Пишет всегда, если есть что: дебаунс живости (§2) — это про частоту, а не
// про право потерять последнее состояние (§4 регистра).
//
// Если писать НЕЧЕГО — замок не берётся вовсе. Это не оптимизация, а починка
// замеренного дефекта: чтение стора идёт без замка (см. load), но Close брал
// его безусловно, и читающая команда при занятом сторе печатала весь ответ, а
// потом ждала пять секунд и отдавала код 1. Замер на живом бинаре (записан в
// implementation-notes.md, «Замер: держит ли агент flock всю жизнь»): 201
// строка вывода в stdout и код 1 следом. Отказ после напечатанного ответа —
// это ложь про собственный успех, и мониторингу вокруг кодов возврата (§5.9)
// она обходится дороже всего.
func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	dirty := s.dirty
	s.mu.Unlock()

	var err error
	if dirty != 0 {
		err = s.transact(func() error {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.writeDirtyLocked()
		})
	}

	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	if cerr := s.lock.close(); err == nil {
		err = cerr
	}
	return err
}

// writeDirtyLocked пишет грязные секции. Требует s.mu и вызывается под замком.
//
// Каждый файл атомарен сам по себе; общей транзакции на три файла нет и по §2
// быть не может — файлы разделены как раз потому, что пишутся с разной
// частотой.
func (s *Store) writeDirtyLocked() error {
	for _, f := range files() {
		if s.dirty&f.sec == 0 {
			continue
		}
		data, err := s.encodeLocked(f.sec)
		if err != nil {
			return fmt.Errorf("store: не сериализовать %s: %w", f.name, err)
		}
		if err := s.w.write(f.name, f.perm, data); err != nil {
			return err
		}
		// Секция снимается с грязных только после успешной записи: иначе
		// отказ записи молча превратился бы в потерю правки.
		s.dirty &^= f.sec
	}
	return nil
}

func (s *Store) encodeLocked(sec section) ([]byte, error) {
	switch sec {
	case sectionGroups:
		return encodeGroups(s.groupOrder, s.groups)
	case sectionNodes:
		return encodeNodes(s.groupOrder, s.groups, s.nodes)
	case sectionHealth:
		return encodeHealth(s.healthByNode)
	case sectionSettings:
		return encodeSettings(s.settings)
	}
	return nil, fmt.Errorf("неизвестная секция %d", sec)
}
