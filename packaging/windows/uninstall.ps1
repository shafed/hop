# Снятие hop с Windows.
#
# Снимается ровно то, что поставил install.ps1 (I3, §8.5). Профили пользователя
# переживают снятие: их убирает только -Purge.
#
# Скрипт идемпотентен: второй запуск на уже снятой системе — не ошибка.
[CmdletBinding()]
param(
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

Assert-Admin

# Задача снимается первой, чтобы агент не переподключался к ещё живой службе.
if (Get-ScheduledTask -TaskName $AgentTaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $AgentTaskName -Confirm:$false
    Write-Host "снята задача $AgentTaskName"
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    # Remove-Service есть только в PowerShell 6+; sc.exe работает везде.
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete вернул $LASTEXITCODE" }
    Write-Host "снята служба $ServiceName"
}

if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Host "удалён $InstallDir"
}

$store = Get-StoreDir
if ($Purge) {
    if (Test-Path $store) {
        Remove-Item -Path $store -Recurse -Force
        Write-Host "удалён стор $store"
    }
}
elseif (Test-Path $store) {
    Write-Host "стор $store сохранён (удалить: .\uninstall.ps1 -Purge)"
}

Write-Host 'hop снят'
