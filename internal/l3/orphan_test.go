//go:build linux

// Отказ `hop up` внутри окна orphaned (§6.2) и выход из этого окна (§5.6).
//
// Оба свойства проверяются на L3, а не на фейках, потому что состояние, о
// котором идёт речь, создаётся только настоящим сервисом: туннель поднят,
// агента, который его поднял, больше нет, дедлайн ещё не истёк. Фейковая
// связка такого состояния не имеет — у неё нет ни туннеля, ни дедлайна.
package l3

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runHop выполняет уже собранную команду и возвращает вывод вместе с кодом
// возврата: отказ здесь — предмет проверки, а не помеха, и t.Fatal на ненулевом
// коде убил бы тест раньше, чем тот успел бы прочитать отказ.
//
// Команда собирается у вызывающего, а не здесь из `args ...string`: глагол §5.9
// обязан стоять строковым литералом прямо в exec.Command, иначе его не видит
// охрана грамматики (grammar_test.go), и стенд может звать глагол, которого в
// продукте нет.
func runHop(t *testing.T, cmd *exec.Cmd) (string, int) {
	t.Helper()
	out, err := cmd.CombinedOutput()
	if ee := (*exec.ExitError)(nil); errors.As(err, &ee) {
		return string(out), ee.ExitCode()
	}
	if err != nil {
		t.Fatalf("hop %v: %v", cmd.Args[1:], err)
	}
	return string(out), 0
}

// orphanWithFreshAgent воспроизводит ровно то состояние, о котором идёт спор:
// туннель осиротел, а живой агент забрать его не может.
//
// Три условия, и каждое обязательно. Первое — туннель поднят и агент убит без
// `hop down`: Detach тут не годится, окно должно быть настоящим (T24).
// Второе — у нового агента СВОЙ файл токена: с тем же файлом реаттач проходит,
// это и есть T24, и проверять было бы нечего. Третье — автоподключение §6.13
// выключено: иначе новый агент попробует поднять туннель на старте, отказ
// уедет в его лог, процесс выйдет, и `hop up` спрашивать будет некого.
//
// Возвращает путь к токену нового агента: `hop down` его чистит, и тесту нужно
// назвать тот же файл.
func orphanWithFreshAgent(t *testing.T, deadline time.Duration) (*service, string) {
	t.Helper()
	s := startService(t, deadline)
	s.startAgent(filepath.Join(t.TempDir(), "token"))

	if out, code := runHop(t, exec.Command(hopAgent(t), "autoconnect", "off")); code != 0 {
		t.Fatalf("hop autoconnect off: код %d: %s", code, out)
	}
	killAgentAndWaitOrphaned(t, s)

	fresh := filepath.Join(t.TempDir(), "token2")
	if _, err := os.Stat(fresh); err == nil {
		t.Fatal("токен нового агента обязан быть свежим, иначе это проверка T24, а не эта")
	}
	s.spawnAgent(fresh)
	s.waitClientSocket()
	return s, fresh
}

// noSocket — путь, на котором связки заведомо нет: так `hop status` отвечает
// половиной сервиса, а не половиной связки (harness_test.go, phaseAt).
func noSocket(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "нет.sock")
}

// W69 — `hop up` внутри окна orphaned отказывает смыслом, а не состоянием
// (§5.6).
//
// До этого прохода команда печатала «tunnel: операция недопустима в текущем
// состоянии: orphaned, ожидалось down» — фразу конечного автомата про фазу,
// которую пользователь не наблюдает (`hop status` показывает её, только когда
// связки нет вовсе), не снимает ни одним глаголом и ни на что не влияет.
// §5.6 требует от закрытия обратного: назвать себя и оставить выход.
//
// Проверяется и отсутствие прежней фразы, и присутствие новой. Одного
// присутствия мало: подклеенный к жаргону человеческий хвост прошёл бы такую
// проверку, а жаргон остался бы на месте.
//
// Третья половина — что отказ ничего не сделал: туннель после него тот же.
// Отказ, снявший чужой туннель по дороге, был бы хуже прежней фразы.
func TestW69UpInsideOrphanWindowRefusesWithMeaning(t *testing.T) {
	s, _ := orphanWithFreshAgent(t, 30*time.Second)

	out, code := runHop(t, exec.Command(hopAgent(t), "up", "-client-socket", s.client))
	if code == 0 {
		t.Fatalf("`hop up` внутри окна orphaned дал успех: %s", out)
	}
	if strings.Contains(out, "ожидалось down") {
		t.Fatalf("в отказе осталась фраза машины состояний (§5.6): %s", out)
	}
	// Что это такое, чем оно кончится и чем из него выйти — по пункту.
	for _, want := range []string{
		ifname,          // о каком туннеле речь
		"осиротел",      // что с ним
		"attach-token",  // почему этот агент его не забрал
		"`hop down`",    // выход первый — снять сейчас
		"сервис уберёт", // выход второй — дождаться дедлайна
		" с:",           // сколько ждать
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в отказе нет %q — §5.6 требует назвать себя и оставить выход:\n%s", want, out)
		}
	}

	// Спрашивается сервис, а не связка: связка отвечает своей половиной, а её
	// половина про осиротевший туннель говорит «down» — она его не поднимала.
	// Замерено этим же тестом: `s.phase()` здесь даёт "down" при живом
	// интерфейсе, и проверка была бы зелена по чужой причине.
	if ph := phaseAt(t, s.sock, noSocket(t)); ph != "orphaned" {
		t.Fatalf("после отказа сервис в фазе %q, ожидалось orphaned: отказ тронул туннель", ph)
	}
	if !linkExists(ifname) {
		t.Fatal("после отказа интерфейс исчез: отказ снял туннель, о котором только сообщал")
	}
	t.Logf("отказ (код %d):\n%s", code, strings.TrimSpace(out))
}

// W70 — выход, названный в W69, существует: `hop down` при живой связке снимает
// осиротевший туннель, которого у связки нет.
//
// До этого прохода команда печатала «туннель снят» и не снимала ничего: связка
// отвечает только за свой туннель, осиротевший ей не принадлежит, её `Down`
// возвращает успех, ничего не сделав, — и `hop down` докладывал об этом успехе
// как о снятом туннеле. Ложь дороже прежней фразы W69: там пользователю не
// сказали, что делать, здесь ему сказали, что уже сделано.
//
// Проверяется не сообщение, а машина: интерфейс исчез, фаза стала down. И
// сразу за этим — что выход ведёт куда обещано: следующий `hop up` проходит.
func TestW70DownRemovesTheOrphanTheAgentDoesNotOwn(t *testing.T) {
	s, fresh := orphanWithFreshAgent(t, 30*time.Second)

	out, code := runHop(t, exec.Command(hopAgent(t),
		"down", "-client-socket", s.client, "-socket", s.sock, "-token-file", fresh))
	if code != 0 {
		t.Fatalf("`hop down` дал %d: %s", code, out)
	}
	if !strings.Contains(out, "туннель снят") {
		t.Errorf("`hop down` не сказал, что туннель снят:\n%s", out)
	}

	waitLink(t, ifname, false)
	// Фаза спрашивается у сервиса мимо связки: связка ответила бы своей
	// половиной (у неё туннеля не было и до команды), и «down» в её ответе
	// ничего не доказывало бы.
	if ph := phaseAt(t, s.sock, noSocket(t)); ph != "down" {
		t.Fatalf("после `hop down` сервис в фазе %q — осиротевший туннель остался", ph)
	}

	// Выход обязан вести к цели, а не просто отработать (§5.6).
	if out, code := runHop(t, exec.Command(hopAgent(t), "up", "-client-socket", s.client)); code != 0 {
		t.Fatalf("`hop up` после `hop down` дал %d: %s", code, out)
	}
	waitLink(t, ifname, true)
	if ph := s.phase(); ph != "up" {
		t.Fatalf("после `hop up` phase = %q, ожидалось up", ph)
	}
}

// W70, вторая половина: штатный путь остался штатным.
//
// Проход, починивший `hop down` для осиротевшего туннеля, поставил `dropOrphan`
// на дорогу КАЖДОЙ команды `down` — в том числе той, где связка сама подняла
// туннель и сама его снимает. До этого прохода стенд не звал `hop down` вовсе,
// то есть штатный путь не охранял никто, а теперь на нём стоит новый код,
// который ходит к сервису после каждого успешного `Down` связки.
//
// Проверяется, что он там ничего не делает: одно «туннель снят», ни слова про
// осиротевший туннель, интерфейс исчез, сервис в down. Слово «осиротевший» —
// не косметика: оно и есть признак того, что сработала ветка, которой на этом
// пути срабатывать нечем, и пользователю рассказали про уборку чужого туннеля
// там, где он снял свой.
func TestW70NormalDownStaysNormal(t *testing.T) {
	s := startService(t, orphanDeadline)
	tok := filepath.Join(t.TempDir(), "token")
	s.startAgent(tok)

	out, code := runHop(t, exec.Command(hopAgent(t),
		"down", "-client-socket", s.client, "-socket", s.sock, "-token-file", tok))
	if code != 0 {
		t.Fatalf("штатный `hop down` дал %d: %s", code, out)
	}
	if n := strings.Count(out, "туннель снят"); n != 1 {
		t.Errorf("«туннель снят» встретилось %d раз, ожидался ровно один:\n%s", n, out)
	}
	if strings.Contains(out, "осиротевш") {
		t.Errorf("на штатном пути сработала уборка осиротевшего туннеля:\n%s", out)
	}

	waitLink(t, ifname, false)
	if ph := phaseAt(t, s.sock, noSocket(t)); ph != "down" {
		t.Fatalf("после штатного `hop down` сервис в фазе %q", ph)
	}
	s.verifySnapshot()
}
