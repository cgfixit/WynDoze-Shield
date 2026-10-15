<#
.SYNOPSIS
    Install the project venv and open the WynDoze-InfoScanOverload window.

.DESCRIPTION
    Creates .venv with Python 3.12 when it is missing, installs the server
    extra, and starts the Tkinter launcher. The window generates the dashboard
    password for that process. This script does not write Machine environment
    variables and does not register a scheduled task.
#>
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location -LiteralPath $Root

$Python = Get-Command py -ErrorAction SilentlyContinue
if (-not $Python) {
    throw "Python launcher 'py' was not found. Install Python 3.12 and retry."
}
& py -3.12 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "py -3.12 is not Python 3.12 or newer."
}

$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $VenvPython)) {
    & py -3.12 -m venv (Join-Path $Root ".venv")
}
& $VenvPython -m pip install -e ".[server]"
& $VenvPython -m wyndoze_infoscanoverload.desktop
