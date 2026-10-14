<#
.SYNOPSIS
    Registers a daily WynDoze-InfoScanOverload scan as a Windows Scheduled Task.

.DESCRIPTION
    Creates a scheduled task that runs the WynDoze-InfoScanOverload-agent scan once per day as
    SYSTEM. The token and key are copied from this session into an env file
    under C:\ProgramData\WynDoze-InfoScanOverload. The file DACL is SYSTEM and Administrators
    only. A wrapper script loads that file into the task process and then
    starts WynDoze-InfoScanOverload-agent.exe. Nothing is written with Set-Item to Machine scope.

    Set these in the current session before you run this script as admin:
        $env:RECON_AGENT_TOKEN = "<token>"
        $env:RECON_AGENT_ENCRYPTION_KEY = "<key>"

.PARAMETER ServerUrl
    Ingest endpoint, e.g. https://recon.example.internal/api/scans

.PARAMETER Role
    Endpoint role: backup_server | proxy | repository | domain_controller |
    jumpbox | workstation | other

.PARAMETER PythonExe
    Path to the venv python or the WynDoze-InfoScanOverload-agent.exe shim.

.EXAMPLE
    .\Install-ReconAgentTask.ps1 -ServerUrl https://recon.local/api/scans `
        -Role backup_server -PythonExe C:\recon\.venv\Scripts\WynDoze-InfoScanOverload-agent.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ServerUrl,
    [Parameter(Mandatory = $true)]
    [ValidateSet("backup_server", "proxy", "repository", "domain_controller",
        "jumpbox", "workstation", "other")]
    [string] $Role,
    [Parameter(Mandatory = $true)] [string] $PythonExe,
    [string] $CacheDir = "C:\ProgramData\WynDoze-InfoScanOverload\cache",
    [string] $TaskName = "ReconAgentDailyScan",
    [string] $At = "02:30",
    [string] $StateDir = "C:\ProgramData\WynDoze-InfoScanOverload"
)

$ErrorActionPreference = "Stop"

function ConvertTo-QuotedArg {
    param([Parameter(Mandatory = $true)][string] $Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function Protect-ReconPath {
    param([Parameter(Mandatory = $true)][string] $Path, [switch] $Directory)
    $rights = if ($Directory) { "(OI)(CI)F" } else { "F" }
    & icacls.exe $Path /inheritance:r /grant:r "*S-1-5-18:$rights" "*S-1-5-32-544:$rights" | Out-Null
}

$token = [Environment]::GetEnvironmentVariable("RECON_AGENT_TOKEN", "Process")
$key = [Environment]::GetEnvironmentVariable("RECON_AGENT_ENCRYPTION_KEY", "Process")
if (-not $token -or -not $key) {
    throw "Set RECON_AGENT_TOKEN and RECON_AGENT_ENCRYPTION_KEY in this session before registering the task."
}

New-Item -ItemType Directory -Force -Path $StateDir, $CacheDir | Out-Null
Protect-ReconPath -Path $StateDir -Directory

$envFile = Join-Path $StateDir "agent.env"
$wrapper = Join-Path $StateDir "Invoke-ReconAgentScan.ps1"
$quotedUrl = ConvertTo-QuotedArg $ServerUrl
$quotedCache = ConvertTo-QuotedArg $CacheDir
$quotedExe = ConvertTo-QuotedArg $PythonExe
$quotedEnv = ConvertTo-QuotedArg $envFile

@(
    "RECON_AGENT_TOKEN=$token"
    "RECON_AGENT_ENCRYPTION_KEY=$key"
) | Set-Content -LiteralPath $envFile -Encoding ascii
Protect-ReconPath -Path $envFile

@(
    '$ErrorActionPreference = "Stop"'
    "Get-Content -LiteralPath $quotedEnv | ForEach-Object {"
    "    if (`$_ -match '^(?<name>[A-Za-z0-9_]+)=(?<value>.*)$') {"
    '        Set-Item -Path ("Env:" + $Matches.name) -Value $Matches.value'
    "    }"
    "}"
    "& $quotedExe scan --server-url $quotedUrl --role $Role --cache-dir $quotedCache"
) | Set-Content -LiteralPath $wrapper -Encoding ascii
Protect-ReconPath -Path $wrapper

$taskArguments = "-NoProfile -NonInteractive -File $(ConvertTo-QuotedArg $wrapper)"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskArguments
$trigger = New-ScheduledTaskTrigger -Daily -At $At
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" `
    -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -DontStopOnIdleEnd `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RandomDelay (New-TimeSpan -Minutes 30) `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "Registered scheduled task '$TaskName' (daily at $At, role=$Role)."
