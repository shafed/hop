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

# Сервис снимается первым. Агента отдельно останавливать не нужно: у него
# отваливается heartbeat, и он уходит сам (cmd/hop/main.go) — это тот же путь,
# которым он уходит при перезагрузке.
if command -v systemctl >/dev/null; then
	systemctl --global disable "$AGENT_UNIT" 2>/dev/null || true
	systemctl disable --now "$DAEMON_UNIT" 2>/dev/null || true
fi

rm -f "$UNIT_DIR/$DAEMON_UNIT" "$USER_UNIT_DIR/$AGENT_UNIT"
if command -v systemctl >/dev/null; then
	systemctl daemon-reload || true
fi

rm -f "$SBINDIR/hopd" "$BINDIR/hop"
rm -f "$MODULES_CONF"

# Сокет остаётся на диске, если сервис убили SIGKILL: unlink делает Go при
# закрытии слушателя, а SIGKILL до него не доходит.
rm -f "$SOCKET"

# Группа снимается последней: пока существовал сокет, она была его владельцем.
if getent group "$HOP_GROUP" >/dev/null; then
	groupdel "$HOP_GROUP" && echo "снята группа $HOP_GROUP"
fi

if [ "$purge" = yes ]; then
	if [ -n "$user" ]; then
		rm -rf "$(store_dir "$user")"
		echo "удалён стор $(store_dir "$user")"
	else
		echo "hop: пользователь не определён, стор придётся удалить вручную" >&2
	fi
else
	if [ -n "$user" ] && [ -d "$(store_dir "$user")" ]; then
		echo "стор $(store_dir "$user") сохранён (удалить: $0 --purge)"
	fi
fi

echo "hop снят"
