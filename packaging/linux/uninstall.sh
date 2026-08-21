#!/usr/bin/env bash
# Снятие hop с Linux.
#
# Снимается ровно то, что поставил install.sh, и ничего сверх (I3, §8.5).
# Данные пользователя — профили, история проб — переживают снятие: их убирает
# только --purge, и только по явной просьбе.
#
# Скрипт идемпотентен: второй запуск на уже снятой системе — не ошибка.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
. "$here/common.sh"

purge=no
while [ $# -gt 0 ]; do
	case "$1" in
	--purge) purge=yes ;;
	*) die "неизвестный аргумент: $1 (есть только --purge)" ;;
	esac
	shift
done

require_root

user="$(target_user)"

# Агент снимается первым, сервис вторым: иначе у агента отвалится heartbeat, и
# он успеет пройти путь orphaned, которого при штатном снятии быть не должно.
#
# --global disable и файл в USER_UNIT_DIR — уборка за прежней версией, где юнит
# агента был пользовательским (§6.13 до системного пользователя). Установка
# поверх снимает его сама, но снятие обязано убрать и то, чего уже нет в этой
# версии: иначе оставленный включённым юнит поднял бы при логине агента под UID
# человека (C25).
if command -v systemctl >/dev/null; then
	systemctl disable --now "$AGENT_UNIT" 2>/dev/null || true
	systemctl --global disable "$AGENT_UNIT" 2>/dev/null || true
	systemctl disable --now "$DAEMON_UNIT" 2>/dev/null || true
fi

rm -f "$UNIT_DIR/$DAEMON_UNIT" "$UNIT_DIR/$AGENT_UNIT" "$USER_UNIT_DIR/$AGENT_UNIT"
if command -v systemctl >/dev/null; then
	systemctl daemon-reload || true
fi

rm -f "$SBINDIR/hopd" "$BINDIR/hop"
rm -f "$MODULES_CONF"

# Сокет остаётся на диске, если сервис убили SIGKILL: unlink делает Go при
# закрытии слушателя, а SIGKILL до него не доходит.
rm -f "$SOCKET"

# Каталог в /run заводит systemd (RuntimeDirectory=) и убирает он же при
# остановке юнита. Но убитый по SIGKILL агент уходит вместе с юнитом не всегда,
# а I3 требует, чтобы не осталось ничего.
rm -rf "$RUNTIME_DIR"

# Стор — данные пользователя, и переживает снятие: его убирает только --purge.
# Поэтому пользователь снимается тоже под --purge: удалённая учётка оставила бы
# каталог с числовым владельцем, который следующий useradd в системе получил бы
# вместе с чужими ключами.
if [ "$purge" = yes ]; then
	rm -rf "$STORE_DIR"
	echo "удалён стор $STORE_DIR"
	if id -u "$HOP_USER" >/dev/null 2>&1; then
		userdel "$HOP_USER" && echo "снят пользователь $HOP_USER"
	fi
	# Группа снимается последней: пока существовали сокеты, она была их
	# владельцем, а пока существовал пользователь — его основной группой.
	if getent group "$HOP_GROUP" >/dev/null; then
		groupdel "$HOP_GROUP" && echo "снята группа $HOP_GROUP"
	fi
else
	if [ -d "$STORE_DIR" ]; then
		echo "стор $STORE_DIR сохранён (удалить: $0 --purge)"
		echo "вместе с ним сохранены пользователь $HOP_USER и группа $HOP_GROUP: без них каталог осиротел бы"
	else
		if id -u "$HOP_USER" >/dev/null 2>&1; then
			userdel "$HOP_USER" && echo "снят пользователь $HOP_USER"
		fi
		if getent group "$HOP_GROUP" >/dev/null; then
			groupdel "$HOP_GROUP" && echo "снята группа $HOP_GROUP"
		fi
	fi
fi

# Стор прежней версии, оставшийся в каталоге человека после переноса.
if [ "$purge" = yes ] && [ -n "$user" ] && [ -d "$(old_store_dir "$user")" ]; then
	rm -rf "$(old_store_dir "$user")"
	echo "удалён стор прежней версии $(old_store_dir "$user")"
fi

echo "hop снят"
