# Пути и имена, общие для install.sh и uninstall.sh.
#
# Один источник намеренно: разойдись эти два списка хоть на один путь — снятие
# оставило бы файл в системе, и I3 (§8.5) поймал бы это только на следующем
# ночном прогоне. Дублировать пути в двух скриптах дешевле ровно до первой
# правки.

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
SBINDIR="$PREFIX/sbin"
UNIT_DIR=/etc/systemd/system
USER_UNIT_DIR=/etc/systemd/user

# Имя группы совпадает с умолчанием сервиса (-group у hopd): менять его тут
# без правки сервиса нечем, поэтому оно не переменная окружения.
HOP_GROUP=hop
DAEMON_UNIT=hopd.service
AGENT_UNIT=hop.service

# Сокет поднимает сам сервис (ipc.DefaultPath). Инсталлятор его не создаёт, но
# обязан знать путь: после снятия сервиса убитого по SIGKILL файл остаётся, а
# I3 требует, чтобы не осталось ничего.
SOCKET=/run/hop.sock

# Модуль tun грузится по требованию не везде: /dev/net/tun появляется только
# вместе с модулем, а открыть несуществующий путь автозагрузку не запускает.
# Отсюда файл modules-load.d — иначе сервис, поднявшийся при старте ОС (§6.13),
# упрётся в отсутствующее устройство.
MODULES_CONF=/etc/modules-load.d/hop.conf

die() {
	echo "hop: $*" >&2
	exit 1
}

require_root() {
	[ "$(id -u)" = 0 ] || die "нужны права root: запускать через sudo"
}

# target_user — пользователь, для которого ставится агент. Под sudo это тот,
# кто позвал установку, а не root: агент живёт без привилегий (§5.2), и его
# каталоги обязаны принадлежать человеку, а не root.
target_user() {
	if [ -n "${HOP_USER:-}" ]; then
		echo "$HOP_USER"
	elif [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
		echo "$SUDO_USER"
	else
		echo ""
	fi
}

user_home() {
	getent passwd "$1" | cut -d: -f6
}

# store_dir повторяет defaultStoreDir агента (cmd/hop/main.go): XDG_DATA_HOME
# инсталлятору неизвестен — он пользовательский, — поэтому берётся путь по
# умолчанию.
store_dir() {
	echo "$(user_home "$1")/.local/share/hop"
}
