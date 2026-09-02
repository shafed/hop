//go:build linux

// Package packaging — охрана поставки §6.13: unit-файлы systemd и скрипт
// dev-install из `packaging/`.
//
// ЭТО ИНСТРУМЕНТАРИЙ, А НЕ СТРОКА РЕГИСТРА. Ни T-, ни W-номера здесь нет
// намеренно: регистр §8 нумерует утверждения о продукте, а поставка — то, чем
// продукт доезжает до машины. Имена тестов поэтому называют существо, как у
// охраны стенда L3 (internal/l3/grammar_test.go).
//
// Что эти тесты проверить НЕ могут и не притворяются, что могут: настоящую
// установку. Ни `systemctl enable`, ни groupadd на машине разработчика не
// запускаются вообще (HANDOFF.json → autostart_decision.verification_available_here
// — «Nothing is to be installed on the developer's own machine»). Настоящая
// установка проверяется одноразовым раннером: .github/workflows/install-linux.yml.
//
// Почему тесты идут в обычном `go test ./...`, а не под флагом: ровно тот урок,
// который стоит в HANDOFF.json → gate.rule_learned. Охрана, которую гейт не
// зовёт, краснеет через проход после поломки.
package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot — корень модуля. Тест запускается с рабочим каталогом пакета.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("корень модуля не найден по %s: %v", root, err)
	}
	return root
}

func installScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "packaging", "install.sh")
}

// fakeBinDir — каталог с заглушками вместо собранных hop и hopd.
//
// Заглушки, а не настоящие бинари: скрипт занимается раскладкой, а не сборкой,
// и `go build` двух команд (одна из них — 50 МБ с Xray внутри) в обычном
// `go test ./...` стоил бы дороже всего, что здесь проверяется. Единственное,
// что от файла требуется дальше, — быть исполняемым: systemd-analyze проверяет
// именно это (см. TestSystemdAcceptsTheStagedUnits).
func fakeBinDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"hop", "hopd"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// runScript зовёт install.sh и возвращает его вывод целиком.
func runScript(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{installScript(t)}, args...)...)
	cmd.Dir = repoRoot(t)
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// stagedInstall раскладывает поставку в свежий каталог и отдаёт его.
func stagedInstall(t *testing.T) string {
	t.Helper()
	dest := t.TempDir()
	out, err := runScript(t, nil, "install", "-bindir", fakeBinDir(t), "-destdir", dest)
	if err != nil {
		t.Fatalf("install -destdir отказал: %v\n%s", err, out)
	}
	return dest
}

// stagedFiles — все файлы раскладки путями от корня раскладки.
func stagedFiles(t *testing.T, dest string) []string {
	t.Helper()
	var got []string
	err := filepath.WalkDir(dest, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dest, p)
		if err != nil {
			return err
		}
		got = append(got, "/"+filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// unitDir — каталог unit-файлов в исходниках.
func unitDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "packaging", "systemd")
}

// execStart — argv из строки ExecStart= одного unit-файла.
//
// Разбор нарочно наивный (по пробелам): unit-файлы этого продукта не
// пользуются ни кавычками, ни продолжением строки, и наивный разбор,
// столкнувшись с ними, промолчать не сможет — argv разъедется и тест
// покраснеет, а не пропустит.
func execStart(t *testing.T, unit string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(unitDir(t), unit))
	if err != nil {
		t.Fatal(err)
	}
	var argv []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		if argv != nil {
			t.Fatalf("%s: две строки ExecStart=; охрана разбирает одну", unit)
		}
		argv = strings.Fields(strings.TrimPrefix(line, "ExecStart="))
	}
	if len(argv) == 0 {
		t.Fatalf("%s: нет строки ExecStart=", unit)
	}
	return argv
}

// units — оба unit-файла: имя файла и каталог, куда его кладёт поставка.
var units = []struct {
	file    string
	destDir string // относительно корня раскладки
	user    bool
}{
	{"hopd.service", "/usr/lib/systemd/system", false},
	{"hop-agent.service", "/usr/lib/systemd/user", true},
}
