#!/usr/bin/env bash
# Установка hop на Linux.
#
# §5.2: права запрашиваются один раз — здесь. Дальше сервис живёт под systemd,
# агент — под системным пользователем hop, и sudo больше не нужен ни разу.
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

# Группа заводится до бинарей: обе стороны резолвят её на старте и падают, если
# её нет (internal/ipc/group_unix.go). Системная — она не должна попадать в
# диапазон обычных gid.
if getent group "$HOP_GROUP" >/dev/null; then
	echo "группа $HOP_GROUP уже есть"
else
	groupadd --system "$HOP_GROUP"
	echo "создана группа $HOP_GROUP"
fi

# Системный пользователь агента — §1 С1. Не косметика упаковки: правило §6.8
# выводит мимо туннеля всех, кто работает под UID агента, и пока агент делил UID
# с человеком, мимо туннеля уходил весь человек целиком — туннель поднят, статус
# зелёный, а в туннеле пусто (C25).
#
# --system кладёт UID ниже SYS_UID_MAX, и это ровно то, что проверяет агент:
# loopguard отказывается ставить правило на UID из пользовательского диапазона.
# Без логина и без домашнего каталога: своего $HOME агенту не нужно, стор ему
# заводит юнит через StateDirectory=.
if id -u "$HOP_USER" >/dev/null 2>&1; then
	echo "пользователь $HOP_USER уже есть"
else
	useradd --system --gid "$HOP_GROUP" --home-dir "$STORE_DIR" --no-create-home \
		--shell /usr/sbin/nologin --comment "hop agent" "$HOP_USER"
	echo "создан системный пользователь $HOP_USER (uid $(id -u "$HOP_USER"))"
fi

# Проверка, а не доверие: заведи дистрибутив пользователя в обычном диапазоне —
# и правило §6.8 увело бы мимо туннеля этот UID вместе со всем, что под ним
# запущено. Агент откажется его ставить, но узнать об этом лучше здесь.
hop_uid="$(id -u "$HOP_USER")"
sys_uid_max="$(awk '/^SYS_UID_MAX/ {print $2}' /etc/login.defs 2>/dev/null || true)"
sys_uid_max="${sys_uid_max:-999}"
if [ "$hop_uid" -gt "$sys_uid_max" ]; then
	die "у пользователя $HOP_USER непригодный uid $hop_uid (> SYS_UID_MAX=$sys_uid_max): правило §6.8 отказалось бы работать"
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

# Каталог стора — §2 и §6.14: 0700 и владелец $HOP_USER. Юнит заводит его сам
# (StateDirectory=), но до первого старта агента его ещё нет, а перенос ниже уже
# нужен — поэтому каталог создаётся здесь.
install -d -o "$HOP_USER" -g "$HOP_GROUP" -m 0700 "$STORE_DIR"
echo "каталог стора $STORE_DIR — 0700, владелец $HOP_USER"

# Перенос прежнего стора — I4 (§8.5): установка поверх предыдущей версии обязана
# сохранить профили. До системного пользователя они лежали в каталоге человека,
# куда агент больше не заглядывает; молча оставить их там значило бы показать
# пользователю пустой `hop nodes` и потребовать завести подписки заново.
#
# Переносится копией, а не перемещением, и только в пустой каталог: у прежнего
# стора остаётся владелец-человек и целое содержимое, поэтому откатиться на
# старую версию можно в любой момент. Повторный запуск инсталлятора ничего не
# перезаписывает (идемпотентность).
if [ -n "$user" ]; then
	old_store="$(old_store_dir "$user")"
	if [ -d "$old_store" ] && [ -z "$(ls -A "$STORE_DIR" 2>/dev/null)" ] && [ -n "$(ls -A "$old_store" 2>/dev/null)" ]; then
		cp -a "$old_store"/. "$STORE_DIR"/
		chown -R "$HOP_USER:$HOP_GROUP" "$STORE_DIR"
		chmod 0700 "$STORE_DIR"
		find "$STORE_DIR" -type f -exec chmod 0600 {} +
		echo "стор перенесён: $old_store -> $STORE_DIR (прежний оставлен на месте)"
	fi
fi

# Юниты подставляются из шаблонов: PREFIX не обязан быть /usr/local, а
# ExecStart с чужим путём — это юнит, который молча не стартует.
sed -e "s|@SBINDIR@|$SBINDIR|g" -e "s|@GROUP@|$HOP_GROUP|g" \
	"$here/hopd.service" >"$UNIT_DIR/$DAEMON_UNIT"
chmod 0644 "$UNIT_DIR/$DAEMON_UNIT"

# Юнит агента — системный, а не пользовательский (§6.13): агент стартует при
# старте ОС и логина не ждёт.
sed -e "s|@BINDIR@|$BINDIR|g" -e "s|@GROUP@|$HOP_GROUP|g" \
	-e "s|@USER@|$HOP_USER|g" -e "s|@DAEMON_UNIT@|$DAEMON_UNIT|g" \
	"$here/hop.service" >"$UNIT_DIR/$AGENT_UNIT"
chmod 0644 "$UNIT_DIR/$AGENT_UNIT"
echo "установлены юниты $UNIT_DIR/$DAEMON_UNIT и $UNIT_DIR/$AGENT_UNIT"

# Пользовательский юнит прежней версии снимается: оставленный включённым, он
# поднял бы при логине второго агента — под UID человека, то есть ровно тот
# случай, из-за которого весь этот переезд и затеян (C25).
if [ -f "$USER_UNIT_DIR/$AGENT_UNIT" ]; then
	systemctl --global disable "$AGENT_UNIT" 2>/dev/null || true
	rm -f "$USER_UNIT_DIR/$AGENT_UNIT"
	echo "снят пользовательский юнит прежней версии $USER_UNIT_DIR/$AGENT_UNIT"
fi

# tun грузится заранее и при каждой загрузке: см. комментарий к MODULES_CONF.
install -d -m 0755 "$(dirname "$MODULES_CONF")"
printf 'tun\n' >"$MODULES_CONF"
chmod 0644 "$MODULES_CONF"
modprobe tun 2>/dev/null || echo "hop: modprobe tun не удался — проверить, что модуль есть в ядре" >&2

systemctl daemon-reload
# §6.13: сервис и агент — при старте ОС.
systemctl enable --now "$DAEMON_UNIT"
systemctl enable "$AGENT_UNIT"

# Агент здесь намеренно не запускается. Запуск означал бы поднятый туннель, то
# есть подменённые маршруты машины, — а установка не обязана менять состояние
# сети. §6.13 требует «при старте ОС», и ровно это включено выше.
echo
echo "готово. сервис: systemctl status $DAEMON_UNIT"
echo "агент стартует при следующей загрузке; сейчас — systemctl start $AGENT_UNIT"
if [ -n "$user" ]; then
	echo "чтобы членство в группе $HOP_GROUP подействовало, нужен перелогин $user"
fi
