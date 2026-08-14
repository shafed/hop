# Кладёт wintun.dll рядом с собранными бинарями.
#
# Библиотека не хранится в репозитории (§7.2, решение в docs/wintun.md): она
# скачивается по закреплённой версии и обязана совпасть с закреплённой
# контрольной суммой. Несовпадение — это отказ, а не предупреждение: подмена
# подписанной библиотеки в цепочке поставки — ровно тот случай, ради которого
# сумма закреплена.
[CmdletBinding()]
param(
    [string]$Destination,
    [ValidateSet('amd64', 'arm64', 'x86')]
    [string]$Arch = 'amd64'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not $Destination) { $Destination = Get-BuildDir }
New-Item -ItemType Directory -Force -Path $Destination | Out-Null

# Windows PowerShell 5.1 по умолчанию не берёт TLS 1.2, а www.wintun.net не
# отдаёт ничего старше.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$work = Join-Path ([IO.Path]::GetTempPath()) ("wintun-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    $zip = Join-Path $work "wintun-$WintunVersion.zip"
    Write-Host "качаю $WintunUrl"
    Invoke-WebRequest -Uri $WintunUrl -OutFile $zip -UseBasicParsing

    $got = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
    if ($got -ne $WintunSha256) {
        throw "контрольная сумма не совпала: ожидалось $WintunSha256, получено $got"
    }
    Write-Host "sha256 совпал: $got"

    Expand-Archive -Path $zip -DestinationPath $work -Force
    $dll = Join-Path $work "wintun\bin\$Arch\wintun.dll"
    if (-not (Test-Path $dll)) { throw "в архиве нет $dll" }

    Copy-Item -Path $dll -Destination (Join-Path $Destination 'wintun.dll') -Force

    # Лицензия готовых бинарей лежит в самом архиве и едет вместе с библиотекой:
    # распространять DLL без неё нельзя (docs/wintun.md).
    $license = Get-ChildItem -Path (Join-Path $work 'wintun') -Filter 'LICENSE*' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($license) {
        Copy-Item -Path $license.FullName -Destination (Join-Path $Destination 'wintun-LICENSE.txt') -Force
    }
    else {
        Write-Warning 'в архиве нет файла LICENSE — проверить условия распространения перед релизом'
    }

    Write-Host "wintun $WintunVersion ($Arch) положен в $Destination"
}
finally {
    Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
}
