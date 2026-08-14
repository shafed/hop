# Пути и метки, общие для install.sh и uninstall.sh на macOS. Причина общего
# файла та же, что на Linux: разошедшиеся списки — это файл, который снятие не
# нашло, и I3 (§8.5) увидел бы это только ночью.

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
# §5.10: демон живёт в /usr/local/libexec (или в префиксе Homebrew).
LIBEXECDIR="$PREFIX/libexec"

DAEMON_LABEL=io.github.shafed.hopd
AGENT_LABEL=io.github.shafed.hop
# §5.10: plist демона — в /Library/LaunchDaemons, root:wheel, 644.
DAEMON_PLIST="/Library/LaunchDaemons/$DAEMON_LABEL.plist"
AGENT_PLIST_NAME="$AGENT_LABEL.plist"

# Имя группы совпадает с умолчанием сервиса (-group у hopd): менять его тут
# без правки сервиса нечем, поэтому оно не переменная окружения.
HOP_GROUP=hop

# Сокет на macOS — /var/run, а не /run: корневая файловая система только для
# чтения, каталога /run на macOS нет и создать его нечем. Значение обязано
# совпадать с -socket в обоих plist.
SOCKET=/var/run/hop.sock
DAEMON_LOG=/var/log/hopd.log

die() {
	echo "hop: $*" >&2
	exit 1
}

require_root() {
	[ "$(id -u)" = 0 ] || die "нужны права root: запускать через sudo (§5.10 — единственный sudo за всё время жизни)"
}

# target_user — человек, которому ставится LaunchAgent. Под sudo это тот, кто
# позвал установку: агент живёт без привилегий (§5.2), и plist обязан лечь в
# его домашний каталог, а не в root-овый.
target_user() {
	if [ -n "${HOP_USER:-}" ]; then
		echo "$HOP_USER"
	elif [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
		echo "$SUDO_USER"
	else
		echo ""
	fi
}

# user_home на macOS берётся из Directory Services: /etc/passwd здесь не
# источник истины для обычных учётных записей.
user_home() {
	dscl . -read "/Users/$1" NFSHomeDirectory 2>/dev/null | awk '{print $2}'
}

user_uid() {
	id -u "$1"
}

# store_dir повторяет defaultStoreDir агента (cmd/hop/main.go): на macOS он
# такой же, как на Linux, ~/Library/Application Support агент не использует.
store_dir() {
	echo "$(user_home "$1")/.local/share/hop"
}

agent_plist() {
	echo "$(user_home "$1")/Library/LaunchAgents/$AGENT_PLIST_NAME"
}
