// Package cli — команды `hop` (§5.9).
//
// Поверхность v1 — CLI, и она же приёмка: все сценарии §1 (С1–С7) обязаны
// выполняться этими командами. Вся логика живёт в агенте (§3.3), здесь только
// разбор аргументов, один запрос в сокет агента и печать ответа.
//
// Одно исключение из «тонкого клиента», вынужденное и записанное в
// «Deviations» (C11):
//
//   - при недоступном агенте `status` спрашивает сервис напрямую — иначе
//     фаза `orphaned`, которую §2 обязывает показывать, не видна никому, а
//     `down` не снимает осиротевший туннель.
//
// Формат вывода — человекочитаемый; `status` и `nodes` умеют `--json`, потому
// что машине нужен стабильный формат, а человеку таблица.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/shafed/hop/internal/events"
	"github.com/shafed/hop/internal/ipc"
)

// Env — всё, от чего зависит команда. Швы (Fetch, Up, Down) существуют затем,
// чтобы приёмка §1 проверялась без сети и без root (§8.1).
type Env struct {
	Out io.Writer
	Err io.Writer

	// Socket — сокет агента (§3.3), Service — управляющий сокет сервиса (§3.1).
	//
	// Каталога стора здесь нет намеренно: клиент не открывает стор ни на
	// запись, ни на чтение (§3.3), и под системным пользователем `hop` (§6.8)
	// не смог бы. Всё, что он про узлы знает, он спросил у агента.
	Socket  string
	Service string

	// Up — запуск агента: блокирует, пока туннель жив. pin непуст — узел
	// фиксируется сразу (§С3).
	Up func(ctx context.Context, pin string) error
	// Down — снятие туннеля сервисом (§С7).
	Down func() error
}

// errUsage — ошибка употребления команды: main печатает справку, а не только
// текст ошибки.
var errUsage = errors.New("неверные аргументы")

// Run выполняет одну команду.
func Run(ctx context.Context, env Env, args []string) error {
	env.fill()
	if len(args) == 0 {
		Usage(env.Err)
		return errUsage
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "up":
		return cmdUp(ctx, env, rest)
	case "down":
		return cmdDown(env, rest)
	case "status":
		return cmdStatus(env, rest)
	case "nodes":
		return cmdNodes(env, rest)
	case "events":
		return cmdEvents(ctx, env, rest)
	case "bypass":
		return cmdBypass(env, rest)
	case "auto":
		return cmdAuto(env, rest)
	case "sub":
		return cmdSub(ctx, env, rest)
	case "node":
		return cmdNode(ctx, env, rest)
	case "help", "-h", "--help":
		Usage(env.Out)
		return nil
	default:
		fmt.Fprintf(env.Err, "hop: неизвестная команда %q\n", cmd)
		Usage(env.Err)
		return errUsage
	}
}

// IsUsage — стоит ли считать ошибку ошибкой употребления.
func IsUsage(err error) bool { return errors.Is(err, errUsage) }

// Usage — справка §5.9.
func Usage(w io.Writer) {
	fmt.Fprint(w, `hop — VPN поверх Xray-core

команды:
  up [--node <id>]        поднять туннель; --node фиксирует узел
  down                    снять туннель
  status [--json]         состояние туннеля, активный узел, причина переключения
  nodes [--json]          узлы с состоянием и латентностью
  events [--follow]       события переключения
  bypass --on|--off       выпустить трафик мимо туннеля
  auto on|off             автопереключение
  sub add <url> [--name <имя>]
  sub update [<id>]
  sub rm <id>
  sub list                подписки
  node add <ссылка>
  node rm <id>
  node ping <id>          узлы поштучно

глобальные флаги идут до команды: hop -socket <путь> nodes
`)
}

func (e *Env) fill() {
	if e.Out == nil {
		e.Out = os.Stdout
	}
	if e.Err == nil {
		e.Err = os.Stderr
	}
	if e.Socket == "" {
		e.Socket = events.DefaultPath
	}
	if e.Service == "" {
		e.Service = ipc.DefaultPath
	}
}

// flags — набор флагов подкоманды. Ошибка разбора уже напечатана самим flag.
func flags(env Env, name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Err)
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	return nil
}

// dial — соединение с агентом. Отдельной ошибки «агент не запущен» здесь нет:
// её формулирует вызывающий, потому что для одних команд это отказ, а для
// других повод сходить в стор или к сервису.
func dial(env Env) (*events.Client, error) { return events.Dial(env.Socket) }

// writeJSON — машинный вывод `--json`.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
