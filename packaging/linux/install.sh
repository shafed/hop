#!/usr/bin/env bash
# Установка hop на Linux.
#
# §5.2: права запрашиваются один раз — здесь. Дальше сервис живёт под systemd,
# агент — под пользователем, и sudo больше не нужен ни разу.
#
# Скрипт идемпотентен: повторный запуск поверх установленной версии обновляет
# бинари и юниты, не трогая ни группу, ни стор пользователя (I4, §8.5).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
. "$here/common.sh"

# BUILD_DIR — откуда берутся собранные бинари. dist/ — то, что уже в .gitignore.
BUILD_DIR="${BUILD_DIR:-$(cd "$here/../.." && pwd)/dist}"

require_root

[ -x "$BUILD_DIR/hopd" ] || die "нет $BUILD_DIR/hopd (собрать: go build -o dist/hopd ./cmd/hopd)"
[ -x "$BUILD_DIR/hop" ] || die "нет $BUILD_DIR/hop (собрать: go build -o dist/hop ./cmd/hop)"
command -v systemctl >/dev/null || die "нужен systemd: другого автозапуска (§6.13) на Linux инсталлятор не умеет"

user="$(target_user)"

# Группа заводится до бинарей: сервис резолвит её на старте и падает, если её
# нет (cmd/hopd/group_unix.go). Системная — у неё нет своего пользователя и она
# не должна попадать в диапазон обычных gid.
if getent group "$HOP_GROUP" >/dev/null; then
	echo "группа $HOP_GROUP уже есть"
else
	groupadd --system "$HOP_GROUP"
	echo "создана группа $HOP_GROUP"
fi

if [ -n "$user" ]; then
	if id -nG "$user" | tr ' ' '\n' | grep -qx "$HOP_GROUP"; then
		echo "$user уже в группе $HOP_GROUP"
	else
		usermod -aG "$HOP_GROUP" "$user"
		echo "$user добавлен в группу $HOP_GROUP (членство подхватится при следующем логине)"
	fi
else
	echo "hop: пользователь не определён, группу $HOP_GROUP придётся выдать вручную: usermod -aG $HOP_GROUP ИМЯ" >&2
fi

# Обновление поверх работающей установки: сервис останавливается до подмены
# бинаря. Иначе install(1) упрётся в ETXTBSY на запущенном файле, а systemd
# рестартует полуподменённый.
if systemctl is-active --quiet "$DAEMON_UNIT" 2>/dev/null; then
	systemctl stop "$DAEMON_UNIT"
	echo "остановлен работавший $DAEMON_UNIT"
fi

install -D -o root -g root -m 0755 "$BUILD_DIR/hopd" "$SBINDIR/hopd"
install -D -o root -g root -m 0755 "$BUILD_DIR/hop" "$BINDIR/hop"
echo "установлены $SBINDIR/hopd и $BINDIR/hop"

# Каталог стора агента — §6.14: 0700 и владелец-человек. Права выставляются и
# при обновлении: каталог, оставшийся с прежней версии слишком открытым,
# инсталлятор обязан сузить, а содержимое (профили, история проб) сохранить.
if [ -n "$user" ]; then
	group="$(id -gn "$user")"
	install -d -o "$user" -g "$group" -m 0700 "$(store_dir "$user")"
	echo "каталог стора $(store_dir "$user") — 0700, владелец $user"
fi

# Юниты подставляются из шаблонов: PREFIX не обязан быть /usr/local, а
# ExecStart с чужим путём — это юнит, который молча не стартует.
sed -e "s|@SBINDIR@|$SBINDIR|g" -e "s|@GROUP@|$HOP_GROUP|g" \
	"$here/hopd.service" >"$UNIT_DIR/$DAEMON_UNIT"
chmod 0644 "$UNIT_DIR/$DAEMON_UNIT"

install -d -m 0755 "$USER_UNIT_DIR"
sed -e "s|@BINDIR@|$BINDIR|g" "$here/hop.service" >"$USER_UNIT_DIR/$AGENT_UNIT"
chmod 0644 "$USER_UNIT_DIR/$AGENT_UNIT"
echo "установлены юниты $UNIT_DIR/$DAEMON_UNIT и $USER_UNIT_DIR/$AGENT_UNIT"

# tun грузится заранее и при каждой загрузке: см. комментарий к MODULES_CONF.
install -d -m 0755 "$(dirname "$MODULES_CONF")"
printf 'tun\n' >"$MODULES_CONF"
chmod 0644 "$MODULES_CONF"
modprobe tun 2>/dev/null || echo "hop: modprobe tun не удался — проверить, что модуль есть в ядре" >&2

systemctl daemon-reload
# §6.13: сервис — при старте ОС.
systemctl enable --now "$DAEMON_UNIT"
# §6.13: агент — при логине. --global кладёт ссылку в USER_UNIT_DIR и включает
# юнит всем пользователям сразу; персональное `systemctl --user enable` для
# этого потребовало бы живой сессии, которой у инсталлятора нет.
systemctl --global enable "$AGENT_UNIT"

# Агент здесь намеренно не запускается. Запуск означал бы поднятый туннель, то
# есть подменённые маршруты машины, — а установка не обязана менять состояние
# сети. §6.13 требует «при логине», и ровно это включено выше.
echo
echo "готово. сервис: systemctl status $DAEMON_UNIT"
echo "агент стартует при следующем логине; сейчас — systemctl --user start $AGENT_UNIT"
if [ -n "$user" ]; then
	echo "чтобы членство в группе $HOP_GROUP подействовало, нужен перелогин $user"
fi
