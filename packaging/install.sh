#!/bin/sh
# dev-install из §9 PLAN.md: ровно то, что однажды сделает postinst настоящего
# пакета, и ничего сверх. Пакетов (.deb/.rpm) в этом репозитории пока нет
# намеренно — HANDOFF.json → autostart_decision.decision_1_scope.
#
# Два режима, и разница между ними — не косметика:
#
#   -destdir DIR   раскладка в отдельный каталог. Ни одной команды, меняющей
#                  машину: ни groupadd, ни usermod, ни systemctl. Это то, что
#                  проверяется в гейте (internal/packaging), и то, чем
#                  пользуется будущая сборка пакета.
#   без -destdir   настоящая установка: требует root, заводит группу, включает
#                  юниты. Локально не проверена ничем и проверена быть не может
#                  (см. .github/workflows/install-linux.yml).
#
# Скрипт НЕ собирает бинари сам. Причина замерена не здесь: `go build` под sudo
# уходит в кеш root и лезет в сеть за модулями (тот же довод стоит в
# .github/workflows/ci.yml у задачи l3-linux). Собирать — до sudo:
#
#   go build -o dist/hop ./cmd/hop && go build -o dist/hopd ./cmd/hopd
#   sudo packaging/install.sh install
set -eu

# Раскладка. Абсолютные пути, без -prefix: ExecStart в unit-файлах — тоже
# абсолютный путь, и всякий -prefix означал бы правку unit-файла на лету, то
# есть второй источник истины о том, где лежит бинарь. Согласие «путь из
# ExecStart» ↔ «путь, куда кладёт скрипт» держит охрана
# internal/packaging/units_test.go, а не внимательность.
BIN_DIR=/usr/bin
SYSTEM_UNIT_DIR=/usr/lib/systemd/system
USER_UNIT_DIR=/usr/lib/systemd/user

# Группа §6.1: ей открыт управляющий сокет. Имя обязано совпадать с умолчанием
# флага -group у hopd (cmd/hopd/main.go) — это тоже под охраной.
GROUP=hop

SERVICE_UNIT=hopd.service
AGENT_UNIT=hop-agent.service

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

usage() {
	cat >&2 <<USAGE
использование:
  $0 install   [-bindir DIR] [-destdir DIR]
  $0 uninstall [-destdir DIR]

  -bindir DIR    откуда взять собранные hop и hopd (умолчание: $here/../dist)
  -destdir DIR   раскладка в DIR вместо машины: без root, без systemctl
USAGE
	exit 2
}

action=${1:-}
[ -n "$action" ] || usage
shift

bindir=$here/../dist
destdir=

while [ $# -gt 0 ]; do
	case $1 in
	-bindir)
		[ $# -ge 2 ] || usage
		bindir=$2
		shift 2
		;;
	-destdir)
		[ $# -ge 2 ] || usage
		destdir=$2
		shift 2
		;;
	*) usage ;;
	esac
done

say() { printf '%s\n' "$*"; }
die() {
	printf '%s: %s\n' "$(basename -- "$0")" "$*" >&2
	exit 1
}

# Список поставки одним местом: install кладёт его, uninstall снимает его же.
# Два списка разошлись бы на первой же новой единице поставки, и разошлись бы
# молча — удалением занимаются в тот день, когда установка уже забыта.
#
# Формат строки: «источник|назначение|режим».
#
# Список читается через временный файл, а не через `payload | while`: конвейер
# уводит тело цикла в подоболочку, и die внутри него завершил бы подоболочку, а
# не установку — отказ на проверке файлов прошёл бы дальше и начал писать.
payload() {
	cat <<PAYLOAD
$bindir/hop|$BIN_DIR/hop|755
$bindir/hopd|$BIN_DIR/hopd|755
$here/systemd/$SERVICE_UNIT|$SYSTEM_UNIT_DIR/$SERVICE_UNIT|644
$here/systemd/$AGENT_UNIT|$USER_UNIT_DIR/$AGENT_UNIT|644
PAYLOAD
}

list=$(mktemp)
trap 'rm -f "$list"' EXIT INT TERM

do_install() {
	payload >"$list"
	while IFS='|' read -r src dst mode; do
		[ -f "$src" ] || die "нет файла $src (собрать: go build -o $bindir/hop ./cmd/hop и то же для hopd)"
	done <"$list"
	# Отдельным проходом: отказ обязан случиться ДО первой записи, иначе
	# половина поставки остаётся на машине.
	while IFS='|' read -r src dst mode; do
		install -D -m "$mode" "$src" "$destdir$dst"
		say "поставлено: $destdir$dst"
	done <"$list"

	if [ -n "$destdir" ]; then
		say ""
		say "раскладка в $destdir. На машине не изменено ничего:"
		say "  группа $GROUP не заведена, юниты не включены, systemctl не звался."
		return
	fi

	[ "$(id -u)" = 0 ] || die "настоящая установка требует root (запуск: sudo $0 install)"

	if getent group "$GROUP" >/dev/null 2>&1; then
		say "группа $GROUP уже есть"
	else
		groupadd --system "$GROUP"
		say "заведена группа $GROUP"
	fi

	# $SUDO_USER, а не $USER: под sudo второй равен root, и добавление root в
	# группу не даёт ничего — право нужно тому человеку, который запустил sudo.
	if [ -n "${SUDO_USER:-}" ]; then
		usermod -aG "$GROUP" "$SUDO_USER"
		say ""
		say "!! $SUDO_USER добавлен в группу $GROUP."
		say "!! Членство в $GROUP — это право поднимать туннель: управляющий"
		say "!! сокет сервиса открыт этой группе (§6.1)."
		say "!! Действует со следующего логина."
	else
		say ""
		say "!! \$SUDO_USER пуст: в группу $GROUP никто не добавлен."
		say "!! Без членства в $GROUP агент не достучится до сервиса:"
		say "!!   usermod -aG $GROUP <пользователь>"
	fi

	systemctl daemon-reload
	systemctl enable --now "$SERVICE_UNIT"
	# --global: включение для всех будущих пользовательских сессий, а не для
	# текущей (§8.5 I1 — «агент стартует при логине», без второго действия).
	systemctl --global enable "$AGENT_UNIT"
	say ""
	say "сервис включён и запущен; агент включён для всех сессий."
	say "агент поднимется при следующем логине (или: systemctl --user start $AGENT_UNIT)."
}

do_uninstall() {
	if [ -z "$destdir" ]; then
		[ "$(id -u)" = 0 ] || die "удаление требует root (запуск: sudo $0 uninstall)"
		# Отказ каждой из этих команд — не повод бросить удаление на середине:
		# unit мог быть не включён, сервис мог не работать, а файлы обязаны
		# уйти в любом случае (§8.5 I3).
		systemctl --global disable "$AGENT_UNIT" || true
		systemctl disable --now "$SERVICE_UNIT" || true
	fi

	payload >"$list"
	while IFS='|' read -r src dst mode; do
		if [ -e "$destdir$dst" ]; then
			rm -f "$destdir$dst"
			say "снято: $destdir$dst"
		fi
	done <"$list"

	if [ -n "$destdir" ]; then
		return
	fi

	systemctl daemon-reload
	say ""
	say "группа $GROUP оставлена намеренно: её gid может стоять на файлах,"
	say "и удаление группы — не откат установки, а отдельное решение."
	say "снять вручную: groupdel $GROUP"
}

case $action in
install) do_install ;;
uninstall) do_uninstall ;;
*) usage ;;
esac
