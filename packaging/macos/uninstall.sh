#!/usr/bin/env bash
# Снятие hop с macOS.
#
# Снимается ровно то, что поставил install.sh (I3, §8.5). Данные пользователя —
# профили, история проб — переживают снятие: их убирает только --purge.
#
# Скрипт идемпотентен: второй запуск на уже снятой системе — не ошибка.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
. "$here/common.sh"

# Разбор через while, а не `for arg in "$@"`: на macOS в PATH под sudo лежит
# bash 3.2, а он спотыкается о пустой "$@" при включённом set -u.
purge=no
while [ $# -gt 0 ]; do
	case "$1" in
	--purge) purge=yes ;;
	*) die "неизвестный аргумент: $1 (есть только --purge)" ;;
	esac
	shift
done

require_root
[ "$(uname -s)" = Darwin ] || die "это деинсталлятор macOS"

user="$(target_user)"

# Агент снимается первым, чтобы он не переподключался к ещё живому демону.
if [ -n "$user" ]; then
	uid="$(user_uid "$user")"
	launchctl bootout "gui/$uid/$AGENT_LABEL" >/dev/null 2>&1 || true
	rm -f "$(agent_plist "$user")"
fi

launchctl bootout "system/$DAEMON_LABEL" >/dev/null 2>&1 || true
rm -f "$DAEMON_PLIST"

rm -f "$LIBEXECDIR/hopd" "$BINDIR/hop"
rm -f "$DAEMON_LOG"

# Сокет остаётся на диске, если демон убили SIGKILL: unlink делает Go при
# закрытии слушателя, а SIGKILL до него не доходит.
rm -f "$SOCKET"

# Группа снимается последней: пока существовал сокет, она была его владельцем.
if dseditgroup -o read "$HOP_GROUP" >/dev/null 2>&1; then
	dseditgroup -o delete -n . "$HOP_GROUP"
	echo "снята группа $HOP_GROUP"
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
