#!/usr/bin/env bash
# Установка hop на macOS (§5.10).
#
# Единственный запрос прав за всё время жизни продукта — sudo на этой команде.
# Дальше демон живёт под launchd, агент — под пользователем, и ни SMJobBless,
# ни Developer ID не нужны: инсталлятор идёт мимо них.
#
# Скрипт идемпотентен: повторный запуск обновляет бинари и plist, не трогая
# группу и стор пользователя (I4, §8.5).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
. "$here/common.sh"

BUILD_DIR="${BUILD_DIR:-$(cd "$here/../.." && pwd)/dist}"

require_root
[ "$(uname -s)" = Darwin ] || die "это инсталлятор macOS"

[ -x "$BUILD_DIR/hopd" ] || die "нет $BUILD_DIR/hopd (собрать: go build -o dist/hopd ./cmd/hopd)"
[ -x "$BUILD_DIR/hop" ] || die "нет $BUILD_DIR/hop (собрать: go build -o dist/hop ./cmd/hop)"

user="$(target_user)"

# Группа заводится до бинарей: сервис резолвит её на старте и падает, если её
# нет (cmd/hopd/group_unix.go).
if dseditgroup -o read "$HOP_GROUP" >/dev/null 2>&1; then
	echo "группа $HOP_GROUP уже есть"
else
	dseditgroup -o create -n . "$HOP_GROUP"
	echo "создана группа $HOP_GROUP"
fi

if [ -n "$user" ]; then
	if dseditgroup -o checkmember -m "$user" "$HOP_GROUP" >/dev/null 2>&1; then
		echo "$user уже в группе $HOP_GROUP"
	else
		dseditgroup -o edit -a "$user" -t user -n . "$HOP_GROUP"
		echo "$user добавлен в группу $HOP_GROUP"
	fi
else
	echo "hop: пользователь не определён, группу придётся выдать вручную: dseditgroup -o edit -a ИМЯ -t user $HOP_GROUP" >&2
fi

# Обновление поверх работающей установки: демон снимается до подмены бинаря,
# иначе launchd рестартует полуподменённый файл.
if launchctl print "system/$DAEMON_LABEL" >/dev/null 2>&1; then
	launchctl bootout "system/$DAEMON_LABEL" || true
	echo "снят работавший $DAEMON_LABEL"
fi

# Каталоги создаются только если их нет: /usr/local/bin на Intel-маках
# принадлежит пользователю Homebrew, и менять его владельца установка не вправе.
[ -d "$LIBEXECDIR" ] || install -d -o root -g wheel -m 0755 "$LIBEXECDIR"
[ -d "$BINDIR" ] || install -d -o root -g wheel -m 0755 "$BINDIR"
install -o root -g wheel -m 0755 "$BUILD_DIR/hopd" "$LIBEXECDIR/hopd"
install -o root -g wheel -m 0755 "$BUILD_DIR/hop" "$BINDIR/hop"
echo "установлены $LIBEXECDIR/hopd и $BINDIR/hop"

# Каталог стора агента — §6.14: 0700 и владелец-человек. Права выставляются и
# при обновлении, содержимое (профили, история проб) сохраняется.
if [ -n "$user" ]; then
	group="$(id -gn "$user")"
	install -d -o "$user" -g "$group" -m 0700 "$(store_dir "$user")"
	echo "каталог стора $(store_dir "$user") — 0700, владелец $user"
fi

# §5.10: plist демона — root:wheel, 644.
sed -e "s|@LIBEXECDIR@|$LIBEXECDIR|g" -e "s|@SOCKET@|$SOCKET|g" \
	-e "s|@GROUP@|$HOP_GROUP|g" -e "s|@LOG@|$DAEMON_LOG|g" \
	"$here/$DAEMON_LABEL.plist" >"$DAEMON_PLIST"
chown root:wheel "$DAEMON_PLIST"
chmod 0644 "$DAEMON_PLIST"

launchctl bootstrap system "$DAEMON_PLIST"
echo "загружен $DAEMON_LABEL ($DAEMON_PLIST)"

# LaunchAgent кладётся в дом пользователя и принадлежит ему: launchd не грузит
# агентский plist, принадлежащий кому-то ещё.
if [ -n "$user" ]; then
	group="$(id -gn "$user")"
	plist="$(agent_plist "$user")"
	install -d -o "$user" -g "$group" -m 0755 "$(dirname "$plist")"
	sed -e "s|@BINDIR@|$BINDIR|g" -e "s|@SOCKET@|$SOCKET|g" \
		"$here/$AGENT_LABEL.plist" >"$plist"
	chown "$user:$group" "$plist"
	chmod 0644 "$plist"
	echo "установлен $plist"

	# Загрузка в живую сессию — удобство, а не обязанность: §6.13 выполнен уже
	# тем, что plist лежит на месте с RunAtLoad. На машине без GUI-сессии
	# (ssh, CI) домена gui/UID нет, и это не повод считать установку неудачной.
	uid="$(user_uid "$user")"
	if launchctl bootout "gui/$uid/$AGENT_LABEL" >/dev/null 2>&1; then
		echo "снят работавший $AGENT_LABEL"
	fi
	if launchctl bootstrap "gui/$uid" "$plist" 2>/dev/null; then
		echo "загружен $AGENT_LABEL в сессию $user"
	else
		echo "hop: сессии gui/$uid нет, агент стартует при следующем логине" >&2
	fi
fi

echo
echo "готово. демон: sudo launchctl print system/$DAEMON_LABEL"
echo "лог демона: $DAEMON_LOG"
