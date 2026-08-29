// Package doclint — проверка документов на утверждения о состоянии, за
// которыми нет исполнимой проверки (§8, третий линтер семьи negcheck и
// realtimelint).
//
// Проверяется четыре вида утверждений:
//
//   - номер T*/W*, названный в таблицах §8 SPEC.md, в PLAN.md или в
//     docs/verification-agent.md, обязан существовать Go-тестом — номер стоит
//     в имени теста или в его doc-комментарии;
//   - имя политики, названное в PLAN.md или docs/verification-agent.md,
//     обязано быть зарегистрировано в internal/policy;
//   - путь, названный в HANDOFF.json, PLAN.md, SPEC.md или
//     implementation-notes.md, обязан существовать;
//   - имя ветки или хеш коммита, названные в HANDOFF.json, обязаны
//     разрешаться в этом репозитории;
//   - номер, объявленный ненаписанным в прозе (участок, открытый пометкой
//     doclint:unwritten), обязан стоять строкой в docs/not-yet-written.md —
//     иначе прозаический список утверждает отсутствие того, что уже есть.
//
// Единственное исключение — одна строка в docs/not-yet-written.md; линтер
// читает этот список сам и краснеет на строке, которая больше не нужна.
// Отдельная мёртвая ссылка помечается словом doclint:ignore в той же строке
// (в JSON — в том же строковом значении).
//
// Граница распознавания намеренно узкая: пропустить сомнительное дешевле, чем
// шуметь. Подробности — implementation-notes.md, раздел про doclint.
package doclint

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Kind — класс находки.
type Kind string

const (
	KindTest   Kind = "тест"
	KindPolicy Kind = "политика"
	KindPath   Kind = "путь"
	KindRef    Kind = "ссылка git"
	KindStale  Kind = "лишняя строка"
	// KindProse — проза объявила ненаписанным то, за чем стоит тест. Единственный
	// вид, который смотрит в обратную сторону: остальные четыре требуют
	// исполнимого за утверждением «сделано».
	KindProse Kind = "проза"
)

// AllowList — единственный список исключений, который линтер читает сам.
const AllowList = "docs/not-yet-written.md"

// Marker — пометка «здесь мёртвая ссылка названа намеренно».
const Marker = "doclint:ignore"

// MarkerUnwritten — пометка «ниже идёт прозаический список ненаписанного».
// Она открывает участок, на котором жирная голова каждого пункта читается как
// объявление номера ненаписанным и сверяется с AllowList.
//
// Пометка нужна потому, что распознать такое объявление по самой прозе нельзя:
// жирным номером начинаются пункты и в PLAN.md, и в SPEC.md, где они значат
// совсем другое. Пометка — то же решение, что и doclint:ignore: границу
// проводит документ, а не догадка линтера.
const MarkerUnwritten = "doclint:unwritten"

// Finding — одно утверждение документа, за которым ничего не стоит.
type Finding struct {
	File  string
	Line  int
	Kind  Kind
	Token string
	Msg   string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s %s — %s", f.File, f.Line, f.Kind, f.Token, f.Msg)
}

// Config — что и чем проверять.
type Config struct {
	// Root — корень дерева документов (для продукта — корень модуля).
	Root string
	// Policies — имена зарегистрированных политик (policy.All()).
	Policies []string
	// ResolveRef отвечает, разрешается ли имя ветки или хеш в этом
	// репозитории. nil выключает проверку целиком: у CI-чекаута нет ни
	// локальных веток проходов, ни полной истории.
	ResolveRef func(name string) bool
}

// Файлы, за которыми линтер следит. Разные проверки читают разные наборы:
// номера живут в плане и регистрах, пути — везде, ветки — только в HANDOFF.
const (
	filePlan    = "PLAN.md"
	fileSpec    = "SPEC.md"
	fileNotes   = "implementation-notes.md"
	fileHandoff = "HANDOFF.json"
	fileAgent   = "docs/verification-agent.md"
)

// Check возвращает находки, отсортированные по файлу и строке.
func Check(cfg Config) ([]Finding, error) {
	r := &pass{cfg: cfg, seen: map[string]bool{}}
	var err error
	if r.tests, err = collectTestNumbers(cfg.Root); err != nil {
		return nil, err
	}
	if r.allow, err = readAllowList(cfg.Root); err != nil {
		return nil, err
	}
	if r.top, err = topLevel(cfg.Root); err != nil {
		return nil, err
	}
	if r.base, err = basenames(cfg.Root); err != nil {
		return nil, err
	}
	r.policies = map[string]bool{}
	for _, p := range cfg.Policies {
		r.policies[p] = true
	}

	for _, name := range []string{filePlan, fileAgent} {
		doc, err := readMarkdown(cfg.Root, name)
		if err != nil {
			return nil, err
		}
		r.numbers(doc, false)
		r.policyNames(doc)
		r.paths(doc)
		r.unwritten(doc)
	}
	spec, err := readMarkdown(cfg.Root, fileSpec)
	if err != nil {
		return nil, err
	}
	r.numbers(spec, true)
	r.paths(spec)

	// Список исключений — тоже документ: причина, ссылающаяся на
	// несуществующий файл, — ровно та гниль, против которой всё это.
	for _, name := range []string{fileNotes, AllowList} {
		doc, err := readMarkdown(cfg.Root, name)
		if os.IsNotExist(err) && name == AllowList {
			continue // списка исключений может не быть вовсе
		}
		if err != nil {
			return nil, err
		}
		r.paths(doc)
	}

	if err := r.handoff(); err != nil {
		return nil, err
	}
	r.stale()

	sort.Slice(r.found, func(i, j int) bool {
		a, b := r.found[i], r.found[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return r.found, nil
}

type pass struct {
	cfg      Config
	tests    map[string]bool
	allow    map[string]int
	top      map[string]bool
	base     map[string]bool
	policies map[string]bool
	seen     map[string]bool
	found    []Finding
}

// add гасит повтор: один и тот же номер названа в плане десяток раз, а
// исправляют его один раз.
func (r *pass) add(file string, line int, k Kind, tok, msg string) {
	key := file + "\x00" + string(k) + "\x00" + tok
	if r.seen[key] {
		return
	}
	r.seen[key] = true
	r.found = append(r.found, Finding{File: file, Line: line, Kind: k, Token: tok, Msg: msg})
}

// ---------- разметка ----------

type mdLine struct {
	n       int
	text    string
	table   bool
	section string
	ignore  bool
	spans   []string
}

type mdDoc struct {
	name  string
	lines []mdLine
}

var (
	headRe = regexp.MustCompile(`^##\s+([0-9]+)\.`)
	spanRe = regexp.MustCompile("`([^`]+)`")
)

func readMarkdown(root, name string) (*mdDoc, error) {
	b, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		return nil, err
	}
	doc := &mdDoc{name: name}
	fenced := false
	section := ""
	for i, text := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(text), "```") {
			fenced = !fenced
			continue
		}
		if fenced {
			continue
		}
		if m := headRe.FindStringSubmatch(text); m != nil {
			section = m[1]
		}
		l := mdLine{
			n:       i + 1,
			text:    text,
			table:   strings.HasPrefix(strings.TrimSpace(text), "|"),
			section: section,
			ignore:  strings.Contains(text, Marker),
		}
		for _, s := range spanRe.FindAllStringSubmatch(text, -1) {
			l.spans = append(l.spans, s[1])
		}
		doc.lines = append(doc.lines, l)
	}
	return doc, nil
}

// ---------- проверка 1: номера ----------

// numRe — номер в прозе. Слева обязана стоять не-буква и не-цифра, иначе
// «W» из середины слова стала бы номером.
var numRe = regexp.MustCompile(`(?:^|[^\p{L}\p{N}_])([TW][0-9]+)`)

// rangeRe — «W6–W10»: диапазон утверждает всё, что между концами. Именно
// такой формой был записан ложный тезис «T21–T29 проходят в netns».
var rangeRe = regexp.MustCompile(`([TW])([0-9]+)\s*[–—-]\s*([TW])([0-9]+)`)

// numbers проверяет номера. specTables=true сужает чтение до таблиц §8:
// в остальном тексте спеки номера стоят как ссылки на будущее.
func (r *pass) numbers(doc *mdDoc, specTables bool) {
	for _, l := range doc.lines {
		if l.ignore {
			continue
		}
		if specTables && (l.section != "8" || !l.table) {
			continue
		}
		for _, tok := range numTokens(l.text) {
			if r.tests[tok] || r.allow[tok] > 0 {
				continue
			}
			r.add(doc.name, l.n, KindTest, tok,
				"Go-теста с таким номером нет; напишите его или внесите строку в "+AllowList)
		}
	}
}

func numTokens(text string) []string {
	var out []string
	for _, m := range numRe.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	for _, m := range rangeRe.FindAllStringSubmatch(text, -1) {
		if m[1] != m[3] {
			continue
		}
		from, _ := strconv.Atoi(m[2])
		to, _ := strconv.Atoi(m[4])
		if from >= to || to-from > 64 {
			continue
		}
		for i := from; i <= to; i++ {
			out = append(out, m[1]+strconv.Itoa(i))
		}
	}
	return out
}

// collectTestNumbers собирает номера из имён Go-тестов и их doc-комментариев.
func collectTestNumbers(root string) (map[string]bool, error) {
	// В имени номер слипается с «Test», поэтому слева граница не требуется.
	inName := regexp.MustCompile(`[TW][0-9]+`)
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch name := d.Name(); {
			case name == "refs", name == ".git", name == "testdata", strings.HasPrefix(name, "_"):
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			text := fn.Name.Name
			if fn.Doc != nil {
				text += "\n" + fn.Doc.Text()
			}
			for _, tok := range inName.FindAllString(text, -1) {
				out[tok] = true
			}
		}
		return nil
	})
	return out, err
}

// ---------- проверка 1b: прозаический список ненаписанного ----------

// bulletHeadRe — жирная голова пункта: «- **W6, W7**», «- **W30–W31**».
// Объявлением считается только она. Номера в теле причины — ссылки на то, чем
// свойство закрыто уровнем ниже («покрыто W23 по счётчику инстансов»), и
// прочесть их как объявление значило бы краснеть на каждом честном доводе.
var bulletHeadRe = regexp.MustCompile(`^-\s+\*\*([^*]+)\*\*`)

// unwritten сверяет прозаический список ненаписанного с машинным.
//
// Списков ненаписанного в проекте два: абзац в регистре и AllowList. Первый
// объясняет, второй утверждает, и разъезжаются они молча — к моменту, когда
// проверка появилась, проза числила ненаписанными W8, W14 и W33, тесты
// которых давно существовали. Ловить это дисциплиной уже пробовали.
//
// Краснеет ровно один случай: номер объявлен ненаписанным, а тест с ним есть и
// строки в AllowList нет. Остальные два перекрыты и без того — «нет теста и
// нет строки» краснит numbers, «есть строка и есть тест» краснит stale, — и
// повторять их здесь значило бы печатать одну гниль дважды.
//
// Границы участка: пометка открывает; заголовок закрывает всегда, а обычный
// абзац — только после того, как список начался. До первого пункта не
// закрывает ничто, иначе пометку нельзя было бы поставить отдельной строкой
// перед списком.
func (r *pass) unwritten(doc *mdDoc) {
	var in, started bool
	for _, l := range doc.lines {
		if strings.Contains(l.text, MarkerUnwritten) {
			in, started = true, false
			continue
		}
		if !in {
			continue
		}
		t := strings.TrimSpace(l.text)
		if t == "" {
			continue
		}
		m := bulletHeadRe.FindStringSubmatch(t)
		switch {
		case m != nil:
			started = true
		case strings.HasPrefix(t, "#"):
			in = false // заголовок закрывает участок всегда
			continue
		case strings.HasPrefix(t, "-"), strings.HasPrefix(l.text, " "), strings.HasPrefix(l.text, "\t"):
			continue // пункт без жирной головы или продолжение предыдущего
		default:
			in = !started // абзац после начала списка закрывает участок
			continue
		}
		if l.ignore {
			continue
		}
		for _, tok := range numTokens(m[1]) {
			if !r.tests[tok] || r.allow[tok] > 0 {
				continue
			}
			r.add(doc.name, l.n, KindProse, tok,
				"Go-тест с таким номером есть, а проза объявляет его ненаписанным; "+
					"уберите номер отсюда или внесите строку в "+AllowList)
		}
	}
}

// ---------- проверка 2: имена политик ----------

// flagRe — snake_case-имя, за которым сразу стоит «=»: так политики названы в
// разделах «что должно сломаться при выключении» (`ipv6_block=off`).
var flagRe = regexp.MustCompile("^([a-z][a-z0-9]*(?:_[a-z0-9]+)+)=")

// cellRe — ячейка таблицы, в которой нет ничего, кроме имени: так устроена
// колонка политики в регистрах.
var cellRe = regexp.MustCompile("^`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`$")

func (r *pass) policyNames(doc *mdDoc) {
	for _, l := range doc.lines {
		if l.ignore {
			continue
		}
		var names []string
		for _, s := range l.spans {
			if m := flagRe.FindStringSubmatch(s); m != nil {
				names = append(names, m[1])
			}
		}
		if l.table {
			for _, cell := range strings.Split(l.text, "|") {
				if m := cellRe.FindStringSubmatch(strings.TrimSpace(cell)); m != nil {
					names = append(names, m[1])
				}
			}
		}
		for _, name := range names {
			if r.policies[name] || r.allow[name] > 0 {
				continue
			}
			r.add(doc.name, l.n, KindPolicy, name,
				"в internal/policy такой политики нет; зарегистрируйте её или внесите строку в "+AllowList)
		}
	}
}

// ---------- проверка 3: пути ----------

var (
	lineSuffix = regexp.MustCompile(`:[0-9]+(?:,[0-9]+)*$`)
	symbolTail = regexp.MustCompile(`^([a-z][a-zA-Z0-9_]*)\.[A-Z][A-Za-z0-9_]*$`)
	bareFile   = regexp.MustCompile(`^[A-Za-z0-9_.-]+\.(?:go|md|ya?ml)$`)
	numericSeg = regexp.MustCompile(`^[0-9][0-9a-fA-F.:]*$`)
)

func (r *pass) paths(doc *mdDoc) {
	for _, l := range doc.lines {
		if l.ignore {
			continue
		}
		for _, s := range l.spans {
			r.checkPath(doc.name, l.n, s)
		}
	}
}

// checkPath разбирает один кандидат. Всё, в чём линтер не уверен, он молча
// пропускает: список отказов — в implementation-notes.md.
func (r *pass) checkPath(file string, line int, raw string) {
	p, ok := normalizePath(raw)
	if !ok {
		return
	}
	if r.allow[p] > 0 {
		return
	}
	if strings.Contains(p, "/") {
		if !r.top[strings.SplitN(p, "/", 2)[0]] {
			return // не наше дерево: чужой референс, импорт, CIDR
		}
		if _, err := os.Stat(filepath.Join(r.cfg.Root, filepath.FromSlash(p))); err == nil {
			return
		}
		r.add(file, line, KindPath, p, "файла или каталога нет")
		return
	}
	if !bareFile.MatchString(p) || r.base[p] {
		return
	}
	r.add(file, line, KindPath, p, "файла с таким именем в дереве нет")
}

// normalizePath приводит кандидата к пути от корня и отвечает, стоит ли его
// вообще проверять.
func normalizePath(raw string) (string, bool) {
	p := strings.Trim(raw, " \t")
	if p == "" || strings.ContainsAny(p, " \t") {
		return "", false // команда или фраза, а не путь
	}
	p = strings.Trim(p, "«»\"'()[],;:.")
	if strings.ContainsAny(p, "*?<>$~|\\'") || strings.Contains(p, "…") || strings.Contains(p, "...") {
		return "", false // шаблон, сокращение или притяжательная форма
	}
	if strings.Contains(p, "://") || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "", false // URL или абсолютный путь вне репозитория
	}
	hadLine := lineSuffix.MatchString(p)
	p = lineSuffix.ReplaceAllString(p, "")
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimSuffix(p, "/")
	if p == "" || strings.Contains(p, "//") {
		return "", false
	}
	seg := strings.Split(p, "/")
	if numericSeg.MatchString(seg[0]) {
		return "", false // 0.0.0.0/0, fe80::/10 и прочая адресация
	}
	if m := symbolTail.FindStringSubmatch(seg[len(seg)-1]); m != nil {
		if len(seg) == 1 {
			return "", false // pkg.Symbol без каталога — не путь
		}
		seg[len(seg)-1] = m[1]
		p = strings.Join(seg, "/")
	}
	if len(seg) == 1 && hadLine {
		// Голое имя файла со ссылкой на строку — так в этом репозитории
		// цитируют refs/: свои файлы цитируют полным путём.
		return "", false
	}
	return p, true
}

func topLevel(root string) (map[string]bool, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, e := range ents {
		if name := e.Name(); name != ".git" && name != "refs" {
			out[name] = true
		}
	}
	return out, nil
}

func basenames(root string) (map[string]bool, error) {
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch name := d.Name(); {
			case name == "refs", name == ".git", strings.HasPrefix(name, "_"):
				return fs.SkipDir
			}
			return nil
		}
		out[d.Name()] = true
		return nil
	})
	return out, err
}

// ---------- проверка 4: HANDOFF.json ----------

var (
	jsonStr  = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	branchRe = regexp.MustCompile(`^worktree-[A-Za-z0-9_.-]+$`)
	hashRe   = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	hasDigit = regexp.MustCompile(`[0-9]`)
	hasAlpha = regexp.MustCompile(`[a-f]`)
)

// handoff читает HANDOFF.json построчно, а не через json.Unmarshal: находке
// нужен номер строки. Разбор всё же делается — чтобы линтер падал на битом
// JSON, а не молчал на нём.
func (r *pass) handoff() error {
	b, err := os.ReadFile(filepath.Join(r.cfg.Root, fileHandoff))
	if err != nil {
		return err
	}
	var any interface{}
	if err := json.Unmarshal(b, &any); err != nil {
		return fmt.Errorf("%s: %w", fileHandoff, err)
	}
	for i, text := range strings.Split(string(b), "\n") {
		for _, m := range jsonStr.FindAllStringSubmatch(text, -1) {
			val := strings.NewReplacer(`\"`, `"`, `\n`, " ", `\\`, `\`).Replace(m[1])
			if strings.Contains(val, Marker) {
				continue
			}
			for _, tok := range strings.Fields(val) {
				r.checkPath(fileHandoff, i+1, tok)
				r.checkRef(i+1, tok)
			}
		}
	}
	return nil
}

func (r *pass) checkRef(line int, raw string) {
	if r.cfg.ResolveRef == nil {
		return
	}
	tok := strings.Trim(raw, "«»\"'()[],;:.")
	switch {
	case branchRe.MatchString(tok):
	case hashRe.MatchString(tok) && hasDigit.MatchString(tok) && hasAlpha.MatchString(tok):
	default:
		return
	}
	if r.allow[tok] > 0 || r.cfg.ResolveRef(tok) {
		return
	}
	r.add(fileHandoff, line, KindRef, tok, "в этом репозитории не разрешается")
}

// ---------- список исключений ----------

var allowRe = regexp.MustCompile("^- `([^`]+)`")

func readAllowList(root string) (map[string]int, error) {
	out := map[string]int{}
	b, err := os.ReadFile(filepath.Join(root, AllowList))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for i, text := range strings.Split(string(b), "\n") {
		if m := allowRe.FindStringSubmatch(strings.TrimSpace(text)); m != nil {
			out[m[1]] = i + 1
		}
	}
	return out, nil
}

// stale краснеет на строке списка, которая больше не нужна. Без этого список
// исключений превращается в свалку и линтер перестаёт что-либо утверждать.
func (r *pass) stale() {
	for tok, line := range r.allow {
		var why string
		switch {
		case r.tests[tok]:
			why = "тест с таким номером уже есть"
		case r.policies[tok]:
			why = "политика уже зарегистрирована"
		default:
			p, ok := normalizePath(tok)
			if !ok {
				continue
			}
			if strings.Contains(p, "/") {
				if _, err := os.Stat(filepath.Join(r.cfg.Root, filepath.FromSlash(p))); err != nil {
					continue
				}
			} else if !r.base[p] {
				continue
			}
			why = "файл уже существует"
		}
		r.add(AllowList, line, KindStale, tok, why+"; удалите строку")
	}
}
