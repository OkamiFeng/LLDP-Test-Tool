$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"

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

if (-not (Test-Path $VenvPython)) {
    python -m venv (Join-Path $Root ".venv")
    if ($LASTEXITCODE -ne 0) {
        throw "venv creation failed. Exit code: $LASTEXITCODE"
    }
}

Invoke-NativeChecked "pip upgrade" { & $VenvPython -m pip install --upgrade pip }
Invoke-NativeChecked "dependency install" { & $VenvPython -m pip install -e "$Root[dev,build]" }
