//go:build linux

package packaging

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// machineCommands — всё, чем install.sh способен изменить машину.
var machineCommands = []string{"systemctl", "groupadd", "groupdel", "usermod", "useradd"}

// TestStagedInstallChangesNothingOutsideTheStagingRoot — граница между двумя
// режимами скрипта, и она единственная причина, по которой поставку вообще
// можно гонять в обычном гейте.
//
// Утверждение сильнее, чем «-destdir раскладывает файлы»: в режиме раскладки не
// зовётся НИ ОДНА команда, меняющая машину. Проверяется подменой PATH —
// заглушки пишут своё имя в файл и выходят нулём, поэтому пойманный вызов
// краснеет отчётом «скрипт позвал systemctl», а не отказом скрипта, у которого
// была бы дюжина других причин.
//
// Ноль, а не отказ, у заглушки намеренно: заглушка, падающая при вызове,
// проверяла бы, что скрипт умирает от чужой ошибки, а не что он воздержался.
func TestStagedInstallChangesNothingOutsideTheStagingRoot(t *testing.T) {
	mark := filepath.Join(t.TempDir(), "calls")
	env := stubEnv(t, mark)
	dest := t.TempDir()

	out, err := runScript(t, env, "install", "-bindir", fakeBinDir(t), "-destdir", dest)
	if err != nil {
		t.Fatalf("install -destdir отказал: %v\n%s", err, out)
	}
	assertNoMachineCommands(t, mark, "install")

	out, err = runScript(t, env, "uninstall", "-destdir", dest)
	if err != nil {
		t.Fatalf("uninstall -destdir отказал: %v\n%s", err, out)
	}
	assertNoMachineCommands(t, mark, "uninstall")
}

// TestUninstallRemovesEverythingInstallPlaced — §8.5 I3 («файлы удалены») в той
// единственной части, которую здесь вообще можно проверить.
//
// Смысл не в четырёх известных путях, а в том, что список поставки один:
// install и uninstall читают одну и ту же функцию payload(). Два списка
// разошлись бы молча и в ту сторону, где это заметят позже всего, — удалением
// занимаются, когда установка давно забыта.
func TestUninstallRemovesEverythingInstallPlaced(t *testing.T) {
	dest := stagedInstall(t)

	placed := stagedFiles(t, dest)
	if len(placed) == 0 {
		t.Fatal("install -destdir не положил ни одного файла: дальше проверять нечего")
	}

	out, err := runScript(t, nil, "uninstall", "-destdir", dest)
	if err != nil {
		t.Fatalf("uninstall -destdir отказал: %v\n%s", err, out)
	}

	if left := stagedFiles(t, dest); len(left) != 0 {
		t.Errorf("после uninstall осталось: %s\n(поставлено было: %s)",
			strings.Join(left, ", "), strings.Join(placed, ", "))
	}
}

// TestInstallRefusesBeforeWritingAnythingWhenAPayloadFileIsMissing — половина
// поставки на машине хуже, чем никакой.
//
// Скрипт проверяет наличие всех источников отдельным проходом ДО первой
// записи; порядок проверок здесь и есть проверяемое утверждение. Красным этот
// тест делает не отказ (отказать легко), а файл, успевший лечь до отказа.
func TestInstallRefusesBeforeWritingAnythingWhenAPayloadFileIsMissing(t *testing.T) {
	bindir := fakeBinDir(t)
	// hopd идёт в поставке вторым: если проверка не отделена от записи, hop
	// успеет лечь на место.
	if err := os.Remove(filepath.Join(bindir, "hopd")); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()

	out, err := runScript(t, nil, "install", "-bindir", bindir, "-destdir", dest)
	if err == nil {
		t.Fatalf("install без hopd не отказал:\n%s", out)
	}
	if !strings.Contains(out, "hopd") {
		t.Errorf("отказ не называет, чего не хватает:\n%s", out)
	}
	if left := stagedFiles(t, dest); len(left) != 0 {
		t.Errorf("отказ случился после записи: в раскладке уже лежит %s", strings.Join(left, ", "))
	}
}

// stubEnv — окружение, в котором машиноменяющие команды подменены заглушками.
func stubEnv(t *testing.T, mark string) []string {
	t.Helper()
	dir := t.TempDir()
	body := "#!/bin/sh\nprintf '%s %s\\n' \"$(basename \"$0\")\" \"$*\" >> \"$HOP_STUB_MARK\"\nexit 0\n"
	for _, name := range machineCommands {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := append([]string{}, os.Environ()...)
	env = slices.DeleteFunc(env, func(kv string) bool {
		return strings.HasPrefix(kv, "PATH=") || strings.HasPrefix(kv, "HOP_STUB_MARK=")
	})
	return append(env, "PATH="+dir+":"+os.Getenv("PATH"), "HOP_STUB_MARK="+mark)
}

func assertNoMachineCommands(t *testing.T, mark, phase string) {
	t.Helper()
	b, err := os.ReadFile(mark)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if called := strings.TrimSpace(string(b)); called != "" {
		t.Errorf("%s -destdir позвал команды, меняющие машину:\n%s", phase, called)
	}
}
