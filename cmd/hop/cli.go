package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/outbound"
	"github.com/shafed/hop/internal/policy"
	"github.com/shafed/hop/internal/store"
)

// Поверхность CLI §5.9: подкоманды, флаги-модификаторы, коды возврата.
//
// Форма — подкоманды, а не флаги, и это не косметика. Сценарии §1 требуют
// `hop sub add <url>` и `hop node add <ссылка>`, то есть глагол с аргументом, а
// глагол с аргументом флагом не выражается: `-sub <url>` работает ровно до
// второго аргумента и до второго глагола над той же сущностью.
//
// Бинарь один (§5.9). `hop agent` — фоновый режим, его запускает автозапуск
// §6.13; остальные подкоманды обязаны стать тонким клиентом к нему через сокет
// §3.3. Сокета ещё нет, и глаголы, которым без него нечего делать, названы в
// таблице честно — они отказывают с причиной, а не отсутствуют.

// options — флаги-модификаторы. Ни один из них не глагол: глаголы стоят в
// таблице commands.
type options struct {
	socket    string
	ifname    string
	addr      string
	mtu       int
	table     int
	heartbeat time.Duration
	tokenFile string
	debug     bool
	json      bool
}

func defaultOptions() options {
	return options{
		socket:    ipc.DefaultPath,
		ifname:    "hop0",
		addr:      "10.255.0.1/24",
		mtu:       1400,
		table:     8420,
		heartbeat: time.Second,
		tokenFile: defaultTokenFile(),
	}
}

// command — одна подкоманда.
type command struct {
	// verb и sub: «node add» — это verb=node, sub=add. Разбито на два поля, а
	// не хранится строкой, потому что грамматика §5.9 проверяется по глаголам,
	// а разбор аргументов — по паре.
	verb string
	sub  string
	args string
	help string
	// reads — читающая команда, у неё есть `--json` (§5.9).
	reads bool
	// waits — почему глагола ещё нет. Непусто ровно у тех, кому нужен сокет
	// §3.3. Такая команда отказывает с названной причиной: «неизвестная
	// команда» на глагол, который спека обещает, — это ложь про продукт.
	waits string
	setup func(*flag.FlagSet, *options)
	run   func(*cli, *options, []string) error
}

func (c *command) name() string {
	if c.sub == "" {
		return c.verb
	}
	return c.verb + " " + c.sub
}

// retiredFlags — переезд с временного интерфейса Р40 на подкоманды.
//
// Флаги удаляются, а не остаются псевдонимами: PLAN.md (этап 9) решил это
// заранее — «два интерфейса к одному стору разойдутся», — и довод верен
// буквально, потому что подкоманды растут (`node rm` появился отдельным
// глаголом), а флаги нет.
//
// Цена решения — чужой скрипт, который перестанет работать. Молча её платить
// нельзя: «неизвестная команда -sub» сообщает, что интерфейс сменился, и не
// сообщает, на что. Таблица существует ровно затем, чтобы отказ назвал замену.
var retiredFlags = map[string]string{
	"sub":     "hop sub add <url>",
	"node":    "hop node add <ссылка>",
	"nodes":   "hop nodes",
	"rm":      "hop node rm <id>",
	"probe":   "hop probe",
	"routing": "hop routing",
	"down":    "hop down",
	"status":  "hop status",
}

// commands — грамматика §5.9 целиком.
//
// Порядок — читательский: сперва туннель, потом наблюдение, потом ввод узлов,
// потом настройки.
var commands = []*command{
	{
		verb: "agent",
		help: "фоновый режим: поднять туннель и вести его (§5.9, автозапуск §6.13)",
		setup: func(fs *flag.FlagSet, o *options) {
			fs.StringVar(&o.socket, "socket", o.socket, "управляющий сокет сервиса")
			fs.StringVar(&o.ifname, "ifname", o.ifname, "имя интерфейса")
			fs.StringVar(&o.addr, "addr", o.addr, "адрес туннеля")
			fs.IntVar(&o.mtu, "mtu", o.mtu, "MTU")
			fs.IntVar(&o.table, "table", o.table, "таблица маршрутизации туннеля")
			fs.DurationVar(&o.heartbeat, "heartbeat", o.heartbeat, "интервал heartbeat")
			fs.StringVar(&o.tokenFile, "token-file", o.tokenFile, "где лежит attach-token")
			fs.BoolVar(&o.debug, "debug", o.debug, "подробный лог")
		},
		run: (*cli).runAgent,
	},
	{
		verb:  "up",
		help:  "поднять туннель",
		waits: "поднимать туннель умеет только `hop agent`: командой это станет вместе с сокетом клиентов (§3.3)",
	},
	{
		verb: "down",
		help: "снять туннель",
		setup: func(fs *flag.FlagSet, o *options) {
			fs.StringVar(&o.socket, "socket", o.socket, "управляющий сокет сервиса")
			fs.StringVar(&o.tokenFile, "token-file", o.tokenFile, "где лежит attach-token")
		},
		run: (*cli).runDown,
	},
	{
		verb:  "status",
		help:  "состояние туннеля",
		reads: true,
		setup: func(fs *flag.FlagSet, o *options) {
			fs.StringVar(&o.socket, "socket", o.socket, "управляющий сокет сервиса")
		},
		run: (*cli).runStatus,
	},
	{
		verb:  "nodes",
		help:  "узлы и группы из стора",
		reads: true,
		run:   (*cli).runNodes,
	},
	{
		verb:  "events",
		help:  "журнал переключений",
		waits: "события живут в кольце связки и рассылаются через сокет клиентов (§3.3), которого ещё нет",
	},
	{
		verb:  "bypass",
		help:  "осознанный выпуск трафика мимо туннеля (§1/С6)",
		waits: "обход держит связка в памяти (§5.6), и снаружи он достижим только через сокет клиентов (§3.3)",
	},
	{
		verb:  "auto",
		help:  "автопереключение по живости (§1/С3)",
		waits: "выбор узла держит связка: команда придёт вместе с сокетом клиентов (§3.3)",
	},
	{
		verb:  "autoconnect",
		help:  "автоподключение при входе (§6.13)",
		waits: "автозапуск ставит инсталлятор, а переключает его связка через сокет клиентов (§3.3)",
	},
	{
		verb: "sub",
		sub:  "add",
		args: "<url>",
		help: "скачать подписку, слить её в группу и выйти (§5.8, §6.16)",
		setup: func(fs *flag.FlagSet, o *options) {
			fs.StringVar(&o.ifname, "ifname", o.ifname, "имя интерфейса туннеля (сокет качалки биндится мимо него, §6.8)")
		},
		run: (*cli).runSubAdd,
	},
	{
		verb: "node",
		sub:  "add",
		args: "<ссылка>",
		help: "добавить один узел в группу manual (Р10)",
		run:  (*cli).runNodeAdd,
	},
	{
		verb: "node",
		sub:  "rm",
		args: "<id>",
		help: "удалить узел или очистить группу (§1/С8)",
		run:  (*cli).runNodeRm,
	},
	{
		verb:  "probe",
		help:  "проверить узлы через outbound, без туннеля и без прав (§5.4, §6.7)",
		reads: true,
		setup: func(fs *flag.FlagSet, o *options) {
			fs.StringVar(&o.ifname, "ifname", o.ifname, "имя интерфейса туннеля (пробы биндятся мимо него, §6.8)")
		},
		run: (*cli).runProbe,
	},
	{
		verb:  "routing",
		help:  "списки §6.10 и апстримы §5.7: что действует и откуда взялось",
		reads: true,
		run:   (*cli).runRouting,
	},
}

// Коды возврата §5.9.
//
// Третий существует потому, что fail-close — штатное состояние, а не поломка:
// без него мониторинг вокруг hop вынужден разбирать текст, чтобы отличить «всё
// работает, живых узлов нет» от «утилита упала».
var (
	// errAgentUnavailable — код 2. Фоновой половины продукта нет: сокет не
	// открылся. Это не ошибка конфигурации и не отказ пользователю.
	errAgentUnavailable = errors.New("фоновая половина hop недоступна")
	// errNoLiveNodes — код 3, §5.6. Узлы есть, живых среди них нет.
	errNoLiveNodes = errors.New("живых узлов нет")
)

// codeFor — единственная карта кодов возврата.
//
// Одна на весь бинарь по той же причине, по какой одна точка формирования
// вывода: код возврата — контракт с чужой автоматикой, и разъехавшись в одной
// команде, он остаётся зелёным для всех проверок, кроме той, что смотрит
// именно на неё.
//
// Политика exit_codes схлопывает карту до 0/1 — состояние до этого прохода,
// когда fail() отвечал единицей на всё подряд.
func codeFor(err error) int {
	switch {
	case err == nil:
		return 0
	case !policy.ExitCodes.On():
		return 1
	case errors.Is(err, errAgentUnavailable):
		return 2
	case errors.Is(err, errNoLiveNodes):
		return 3
	default:
		return 1
	}
}

// outboundPath — физический путь §6.8 в том объёме, в каком его нужно CLI.
//
// Интерфейс, а не *outbound.Selector, ради одного шва: настоящий селектор
// спрашивает у ядра интерфейс по умолчанию, и проверка кодов возврата тогда
// зависела бы от маршрутов машины, на которой её запускают.
type outboundPath interface {
	Interface() (string, error)
	HTTPClient() *http.Client
	Close() error
}

// cli — один запуск команды.
type cli struct {
	stdout      io.Writer
	stderr      io.Writer
	newOutbound func(tun string) (outboundPath, error)
}

func newCLI(stdout, stderr io.Writer) *cli {
	return &cli{
		stdout: stdout,
		stderr: stderr,
		newOutbound: func(tun string) (outboundPath, error) {
			s, err := outbound.New(tun)
			if err != nil {
				return nil, err
			}
			return s, nil
		},
	}
}

// dispatch — разбор аргументов, выполнение и код возврата.
func (c *cli) dispatch(args []string) int {
	err := c.execute(args)
	if err != nil {
		fmt.Fprintln(c.stderr, "hop:", err)
	}
	return codeFor(err)
}

func (c *cli) execute(args []string) error {
	if len(args) == 0 {
		usage(c.stderr)
		return errors.New("команда не названа")
	}

	// `help` стоит здесь, а не в таблице команд: таблица иначе ссылалась бы на
	// usage, а usage читает таблицу, и Go считает это циклом инициализации.
	if args[0] == "help" {
		usage(c.stdout)
		return nil
	}
	if first := args[0]; strings.HasPrefix(first, "-") {
		name := strings.TrimLeft(strings.SplitN(first, "=", 2)[0], "-")
		if name == "h" || name == "help" {
			usage(c.stdout)
			return nil
		}
		if repl, ok := retiredFlags[name]; ok {
			return fmt.Errorf("флаг -%s снят вместе с временным интерфейсом Р40: теперь `%s` (§5.9)", name, repl)
		}
		usage(c.stderr)
		return fmt.Errorf("флаги в hop — только модификаторы подкоманд (§5.9), а %s стоит вместо глагола", first)
	}

	cmd, rest, err := lookup(args)
	if err != nil {
		usage(c.stderr)
		return err
	}
	if cmd.waits != "" {
		return fmt.Errorf("`hop %s` ещё не написан: %s", cmd.name(), cmd.waits)
	}

	fs := flag.NewFlagSet("hop "+cmd.name(), flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	opts := defaultOptions()
	if cmd.setup != nil {
		cmd.setup(fs, &opts)
	}
	if cmd.reads {
		fs.BoolVar(&opts.json, "json", false, "машинный вывод вместо таблицы (§5.9)")
	}
	if err := fs.Parse(rest); err != nil {
		return fmt.Errorf("`hop %s`: %w", cmd.name(), err)
	}
	return cmd.run(c, &opts, fs.Args())
}

// lookup находит команду по одному или двум первым аргументам.
//
// Двусловные проверяются первыми: иначе `node` заслонил бы `node add`.
func lookup(args []string) (*command, []string, error) {
	if len(args) > 1 {
		for _, c := range commands {
			if c.sub != "" && c.verb == args[0] && c.sub == args[1] {
				return c, args[2:], nil
			}
		}
	}
	for _, c := range commands {
		if c.sub == "" && c.verb == args[0] {
			return c, args[1:], nil
		}
	}
	// Глагол существует, но требует второго слова.
	var subs []string
	for _, c := range commands {
		if c.verb == args[0] {
			subs = append(subs, c.name())
		}
	}
	if len(subs) > 0 {
		return nil, nil, fmt.Errorf("`hop %s` требует второго слова: %s", args[0], strings.Join(subs, ", "))
	}
	return nil, nil, fmt.Errorf("неизвестная команда %q", args[0])
}

// lookupVerb — команда по одному глаголу, для проверок грамматики.
func lookupVerb(verb string) (*command, bool) {
	for _, c := range commands {
		if c.verb == verb {
			return c, true
		}
	}
	return nil, false
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "hop — VPN поверх Xray-core. Форма: hop <команда> [аргументы] [--флаги]")
	fmt.Fprintln(out)
	for _, c := range commands {
		mark := "  "
		if c.waits != "" {
			mark = "· " // ещё не написан
		}
		fmt.Fprintf(out, "%s%-16s %s\n", mark, strings.TrimSpace(c.name()+" "+c.args), c.help)
	}
	fmt.Fprintf(out, "  %-16s %s\n", "help", "этот список")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "· — глагол §5.9, которому нужен сокет клиентов (§3.3); он ещё не написан")
	fmt.Fprintln(out, "у читающих команд есть --json, коды возврата: 0 выполнено, 1 ошибка,")
	fmt.Fprintln(out, "2 фоновая половина недоступна, 3 живых узлов нет (fail-close §5.6)")
}

// connect — соединение с фоновой половиной продукта.
//
// Отказ соединения — код 2, а не 1: агент просто не поднят, чинить в
// конфигурации нечего.
//
// Сегодня по ту сторону сокета стоит сервис (§3.1), а не связка: сокета §3.3
// ещё нет. Смысл кода от этого не меняется — «фоновой половины нет», — а
// адресат заменится под тем же кодом.
func (c *cli) connect(path string) (*ipc.Client, error) {
	cl, err := ipc.Connect(path)
	if err != nil {
		return nil, fmt.Errorf("%w: сокет %s: %v", errAgentUnavailable, path, err)
	}
	return cl, nil
}

func (c *cli) runStatus(o *options, _ []string) error {
	cl, err := c.connect(o.socket)
	if err != nil {
		return err
	}
	defer cl.Close()

	st, err := cl.Status()
	if err != nil {
		return err
	}
	return emit(c.stdout, statusView(st), o.json)
}

func (c *cli) runDown(o *options, _ []string) error {
	cl, err := c.connect(o.socket)
	if err != nil {
		return err
	}
	defer cl.Close()

	if err := cl.Stop(); err != nil {
		return err
	}
	return removeToken(o.tokenFile)
}

func (c *cli) runNodes(o *options, _ []string) error {
	return withStore(func(st *store.Store) error {
		return emit(c.stdout, nodesView(st), o.json)
	})
}

func (c *cli) runRouting(o *options, _ []string) error {
	// Читающая команда, и она же — проверка файла: settings.json с кривым
	// правилом до этого места не доводит, потому что отказывает store.Open
	// (§5.6). Отдельной команды «проверить конфиг» поэтому не нужно, а отказ
	// на кривом файле даёт код 1 — это поломка конфигурации, а не fail-close.
	root, err := storeRoot()
	if err != nil {
		return err
	}
	return withStore(func(st *store.Store) error {
		return emit(c.stdout, settingsView(st, filepath.Join(root, "settings.json")), o.json)
	})
}

func (c *cli) runSubAdd(o *options, args []string) error {
	if len(args) != 1 {
		return errors.New("`hop sub add` берёт ровно одну ссылку на подписку")
	}
	physical, err := c.newOutbound(o.ifname)
	if err != nil {
		return err
	}
	defer physical.Close()

	return withStore(func(st *store.Store) error {
		return addSubscription(context.Background(), st, args[0], c.stdout, physical.HTTPClient())
	})
}

func (c *cli) runNodeAdd(_ *options, args []string) error {
	if len(args) != 1 {
		return errors.New("`hop node add` берёт ровно одну ссылку; для пачки есть `hop sub add`")
	}
	return withStore(func(st *store.Store) error {
		return addNode(st, args[0], c.stdout)
	})
}

func (c *cli) runNodeRm(_ *options, args []string) error {
	if len(args) != 1 {
		return errors.New("`hop node rm` берёт ровно один id — узла или группы")
	}
	return withStore(func(st *store.Store) error {
		return removeNode(st, args[0], c.stdout)
	})
}

// runProbe печатает результат и только потом решает про код возврата.
//
// Порядок именно такой: код 3 не отменяет вывода. Мониторинг читает код,
// человек читает строки — и человеку нужно видеть, какие именно узлы молчат.
func (c *cli) runProbe(o *options, _ []string) error {
	physical, err := c.newOutbound(o.ifname)
	if err != nil {
		return err
	}
	defer physical.Close()

	var v probeOut
	err = withStore(func(st *store.Store) error {
		var err error
		v, err = probeNodes(context.Background(), st, physical.Interface)
		return err
	})
	if err != nil {
		return err
	}
	if err := emit(c.stdout, v, o.json); err != nil {
		return err
	}
	if v.Alive == 0 {
		return fmt.Errorf("%w: ни один из %d узлов не ответил (fail-close §5.6)", errNoLiveNodes, len(v.Nodes))
	}
	return nil
}

func (c *cli) runAgent(o *options, _ []string) error {
	level := slog.LevelInfo
	if o.debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(c.stderr, &slog.HandlerOptions{Level: level}))

	cl, err := c.connect(o.socket)
	if err != nil {
		return err
	}
	defer cl.Close()

	physical, err := outbound.New(o.ifname)
	if err != nil {
		return err
	}
	defer physical.Close()

	return run(log, cl, o.tokenFile, o.heartbeat,
		tunnelParams(o.ifname, o.addr, o.mtu, o.table),
		physical.Interface, physical.DialDirect, physical.Control)
}

func main() {
	os.Exit(newCLI(os.Stdout, os.Stderr).dispatch(os.Args[1:]))
}
