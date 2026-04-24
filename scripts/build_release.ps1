param(
    [switch]$DownloadNpcap
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
$JapaneseSuffix = -join ([int[]](0x30D0, 0x30A4, 0x30C8, 0x9001, 0x53D7, 0x4FE1, 0x30C4, 0x30FC, 0x30EB) | ForEach-Object { [char]$_ })
$AppName = "LLDP$JapaneseSuffix"
$LauncherName = (-join ([int[]](0x8D77, 0x52D5) | ForEach-Object { [char]$_ })) + ".bat"
$ReleaseDir = Join-Path $Root "dist\$AppName"
$DriversDir = Join-Path $ReleaseDir "drivers"
$NpcapVersion = "1.87"
$NpcapInstallerName = "npcap-$NpcapVersion.exe"
$NpcapUrl = "https://npcap.com/dist/$NpcapInstallerName"
$LocalDriversDir = Join-Path $Root "drivers"
$LocalNpcapInstaller = Join-Path $LocalDriversDir $NpcapInstallerName
$PyInstallerWorkDir = Join-Path $Root ".pyinstaller-work"
$PyInstallerSpecDir = Join-Path $Root ".pyinstaller-spec"

function Invoke-NativeChecked {
    param(
        [string]$Name,
        [scriptblock]$Command
    )

    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed. Exit code: $LASTEXITCODE"
    }
}

& (Join-Path $PSScriptRoot "bootstrap.ps1")

Invoke-NativeChecked "pytest" { & $VenvPython -m pytest }

if (Test-Path $PyInstallerWorkDir) {
    Remove-Item -LiteralPath $PyInstallerWorkDir -Recurse -Force
}
if (Test-Path $PyInstallerSpecDir) {
    Remove-Item -LiteralPath $PyInstallerSpecDir -Recurse -Force
}

Invoke-NativeChecked "PyInstaller" {
    & $VenvPython -m PyInstaller `
        --noconfirm `
        --clean `
        --windowed `
        --name $AppName `
        --workpath $PyInstallerWorkDir `
        --specpath $PyInstallerSpecDir `
        --paths (Join-Path $Root "src") `
        --hidden-import lldp_tool.gui `
        --hidden-import scapy.all `
        (Join-Path $Root "src\lldp_tool\__main__.py")
}

New-Item -ItemType Directory -Force -Path $DriversDir | Out-Null

if ($DownloadNpcap -and -not (Test-Path $LocalNpcapInstaller)) {
    New-Item -ItemType Directory -Force -Path $LocalDriversDir | Out-Null
    Invoke-WebRequest -Uri $NpcapUrl -OutFile $LocalNpcapInstaller
}

$ExistingNpcap = Get-ChildItem -Path $LocalDriversDir -Filter "npcap-*.exe" -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending |
    Select-Object -First 1

if ($ExistingNpcap) {
    Copy-Item -Path $ExistingNpcap.FullName -Destination (Join-Path $DriversDir $ExistingNpcap.Name) -Force
} else {
    Write-Warning "Npcap installer was not bundled. Re-run with -DownloadNpcap if needed."
}

$Launcher = Join-Path $ReleaseDir $LauncherName
$LauncherText = @(
    "@echo off",
    'for %%F in ("%~dp0LLDP*.exe") do start "" "%%~fF" & exit /b'
) -join [Environment]::NewLine
Set-Content -Path $Launcher -Value $LauncherText -Encoding ASCII

Remove-Item -LiteralPath $PyInstallerWorkDir -Recurse -Force
Remove-Item -LiteralPath $PyInstallerSpecDir -Recurse -Force

Write-Host "Release created: $ReleaseDir"
