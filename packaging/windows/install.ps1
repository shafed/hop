# Установка hop на Windows.
#
# §5.2: права запрашиваются один раз — здесь. Служба живёт под LocalSystem,
# агент — задачей планировщика от имени обычного пользователя, и повышения
# больше не требуется ни разу.
#
# Скрипт идемпотентен: повторный запуск поверх установленной версии обновляет
# файлы и перезапускает службу, не трогая профили пользователя (I4, §8.5).
[CmdletBinding()]
param(
    [string]$BuildDir
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

Assert-Admin
if (-not $BuildDir) { $BuildDir = Get-BuildDir }

$need = @('hopd.exe', 'hop.exe', 'wintun.dll')
foreach ($f in $need) {
    if (-not (Test-Path (Join-Path $BuildDir $f))) {
        if ($f -eq 'wintun.dll') {
            throw "нет $BuildDir\wintun.dll — сначала .\packaging\windows\fetch-wintun.ps1 (§7.2, docs/wintun.md)"
        }
        throw "нет $BuildDir\$f (собрать: go build -o dist\$f .\cmd\$($f -replace '\.exe$',''))"
    }
}

# Обновление поверх работающей установки: служба останавливается до подмены
# файлов, иначе копирование упрётся в занятый hopd.exe.
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') {
    Write-Host "останавливаю работающую службу $ServiceName"
    Stop-Service -Name $ServiceName -Force
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($f in $need) {
    Copy-Item -Path (Join-Path $BuildDir $f) -Destination (Join-Path $InstallDir $f) -Force
}
$wintunLicense = Join-Path $BuildDir 'wintun-LICENSE.txt'
if (Test-Path $wintunLicense) {
    Copy-Item -Path $wintunLicense -Destination $InstallDir -Force
}
Write-Host "файлы установлены в $InstallDir"

# Служба. LocalSystem — умолчание New-Service и то, что нужно: TUN-адаптер,
# маршруты и DNS на адаптере требуют прав, и это единственное место, где они
# есть (§5.2).
$binPath = '"{0}"' -f (Join-Path $InstallDir 'hopd.exe')
if ($svc) {
    # BinaryPathName у Set-Service появился только в PowerShell 6; sc.exe умеет
    # это везде, где есть Windows.
    & sc.exe config $ServiceName binPath= $binPath start= auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe config вернул $LASTEXITCODE" }
    Write-Host "служба $ServiceName обновлена"
}
else {
    New-Service -Name $ServiceName -BinaryPathName $binPath `
        -DisplayName $ServiceDisplayName -Description $ServiceDescription `
        -StartupType Automatic | Out-Null
    Write-Host "служба $ServiceName зарегистрирована (автозапуск — §6.13)"
}

# §6.13: агент — при логине. Задача планировщика, а не ключ Run: у задачи есть
# и уровень прав, и группа-принципал, то есть агент гарантированно стартует
# **без** повышения (§5.2), какими бы правами ни обладал вошедший.
$action = New-ScheduledTaskAction -Execute (Join-Path $InstallDir 'hop.exe') -Argument 'up'
$trigger = New-ScheduledTaskTrigger -AtLogOn
# SID, а не 'BUILTIN\Users': имя группы локализовано, SID — нет.
$principal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
# Ограничение времени выполнения снято: агент живёт, пока живёт сессия, а по
# умолчанию планировщик убил бы его через трое суток.
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $AgentTaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "задача $AgentTaskName зарегистрирована (агент стартует при логине)"

# Служба поднимается сразу: §8.5 I1 требует «зарегистрирован **и запущен**».
try {
    Start-Service -Name $ServiceName
}
catch {
    throw @"
служба не запустилась: $($_.Exception.Message)
Если это ошибка 1053 («служба не ответила»), то дело не в установке: у hopd
пока нет обработчика Windows-службы (golang.org/x/sys/windows/svc), см.
docs/install.md, раздел «Windows: что ещё не сделано».
"@
}

# SDDL трубы (§6.1) ставит сам сервис: дескриптор безопасности рождается вместе
# с объектом трубы, и менять его инсталлятору нечем. Проверяются ровно те два
# условия, что и в internal/ipc: класс IU допущен, Everyone — нет.
$pipeReady = $false
foreach ($i in 1..50) {
    if ([IO.Directory]::GetFiles('\\.\pipe\') -match "\\$PipeName$") { $pipeReady = $true; break }
    Start-Sleep -Milliseconds 100
}
if (-not $pipeReady) { throw "служба запущена, но труба $PipePath не появилась" }

try {
    $sddl = (Get-Acl -Path $PipePath).Sddl
}
catch {
    $sddl = $null
    Write-Warning "SDDL трубы прочитать не удалось ($($_.Exception.Message)) — проверить вручную"
}
if ($sddl) {
    if ($sddl -match ";;;$PipeMustDenySid\)") {
        throw "труба $PipePath открыта Everyone: $sddl (§6.1)"
    }
    if ($sddl -notmatch ";;;$PipeMustAllowSid\)") {
        throw "труба $PipePath закрыта интерактивным пользователям: $sddl (агент не подключится)"
    }
    Write-Host "SDDL трубы проверен: $sddl"
}

Write-Host ''
Write-Host "готово. служба: Get-Service $ServiceName"
Write-Host "агент стартует при следующем логине; сейчас — & '$InstallDir\hop.exe' up"
