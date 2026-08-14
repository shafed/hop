# Имена и пути, общие для install.ps1, uninstall.ps1 и fetch-wintun.ps1.
#
# Один источник намеренно: разойдись списки — снятие оставило бы службу или
# задачу, и I3 (§8.5) поймал бы это только ночью.

# Каталог установки. Рядом с бинарями лежит wintun.dll: библиотека грузится по
# имени из каталога модуля, и «рядом» — это её штатный способ поставки (§7.2,
# docs/wintun.md).
$InstallDir = Join-Path $env:ProgramFiles 'hop'

$ServiceName = 'hopd'
$ServiceDisplayName = 'hop tunnel service'
$ServiceDescription = 'hop: привилегированный сервис туннеля (TUN, маршруты, отказ за умершим агентом)'

# Задача планировщика — автозапуск агента при логине (§6.13).
$AgentTaskName = 'hop-agent'

# Труба управляющей границы (ipc.DefaultPath). SDDL на ней ставит сам сервис;
# инсталлятор её только проверяет — см. install.ps1.
$PipeName = 'hop'
$PipePath = '\\.\pipe\hop'

# §6.1 в терминах Windows: доступ классу, а не всем. Здесь ровно два условия,
# которые проверяет установка, — они же проверены в internal/ipc.
$PipeMustAllowSid = 'IU'  # интерактивные пользователи — иначе агент не подключится
$PipeMustDenySid = 'WD'   # Everyone — ошибка hiddify, которую §6.1 запрещает повторять

# Версия wintun закреплена вместе с контрольной суммой: в репозиторий бинарь не
# кладётся, он скачивается при сборке. Решение и его причины — docs/wintun.md.
$WintunVersion = '0.14.1'
$WintunSha256 = '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51'
$WintunUrl = "https://www.wintun.net/builds/wintun-$WintunVersion.zip"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'нужны права администратора: запускать из консоли с повышением'
    }
}

# Get-BuildDir — где лежат собранные бинари. dist/ в корне репозитория: он уже
# в .gitignore, и туда же fetch-wintun.ps1 кладёт библиотеку.
function Get-BuildDir {
    Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'dist'
}

# Get-StoreDir повторяет defaultStoreDir агента (cmd/hop/main.go): на Windows
# UserHomeDir даёт профиль, и стор ложится внутрь него.
function Get-StoreDir {
    Join-Path $env:USERPROFILE '.local\share\hop'
}
