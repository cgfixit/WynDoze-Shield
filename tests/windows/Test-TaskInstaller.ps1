<# Synthetic installer contract check. Never registers a task or changes ACLs. #>
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"

function Assert-True($Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

# On Windows validate the mocks against the real 5.1 module metadata first.
if ($env:OS -eq "Windows_NT") {
    Assert-True ((Get-Command New-ScheduledTaskTrigger).Parameters.ContainsKey("RandomDelay")) "Trigger metadata"
    Assert-True (-not (Get-Command New-ScheduledTaskSettingsSet).Parameters.ContainsKey("RandomDelay")) "Settings metadata"
}

function New-ScheduledTaskAction {
    [CmdletBinding()] param([string] $Execute, [string] $Argument)
    return @{ Execute = $Execute; Argument = $Argument }
}
function New-ScheduledTaskTrigger {
    [CmdletBinding()] param([switch] $Daily, [string] $At, [TimeSpan] $RandomDelay)
    return @{ RandomDelay = $RandomDelay }
}
function New-ScheduledTaskPrincipal {
    [CmdletBinding()] param([string] $UserId, [string] $LogonType, [string] $RunLevel)
    return @{ UserId = $UserId }
}
function New-ScheduledTaskSettingsSet {
    [CmdletBinding()] param(
        [switch] $StartWhenAvailable, [switch] $DontStopOnIdleEnd,
        [switch] $AllowStartIfOnBatteries, [switch] $DontStopIfGoingOnBatteries,
        [TimeSpan] $ExecutionTimeLimit
    )
    return @{}
}
function Register-ScheduledTask {
    [CmdletBinding()] param($TaskName, $Action, $Trigger, $Principal, $Settings, [switch] $Force)
    $global:WynDozeTaskFixture = @{ Action = $Action; Trigger = $Trigger; Principal = $Principal }
}
function icacls.exe {
    $global:LASTEXITCODE = $global:WynDozeAclExit
}

$root = Join-Path ([IO.Path]::GetTempPath()) ("wyndoze-task-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $root | Out-Null
try {
    $state = Join-Path $root ("state " + [char]0x00E9 + " with ' apostrophe")
    $exe = Join-Path $root "fake agent.ps1"
    '@{ Args = $args } | ConvertTo-Json | Set-Content -LiteralPath $env:WYNDOZE_TEST_ARGS; $global:LASTEXITCODE = 3' |
        Set-Content -LiteralPath $exe -Encoding UTF8
    $env:WYNDOZE_TEST_ARGS = Join-Path $root "args.json"
    $env:RECON_AGENT_TOKEN = "synthetic-test-token"
    $env:RECON_AGENT_ENCRYPTION_KEY = "synthetic-test-key"
    $global:WynDozeAclExit = 0
    $installer = Join-Path $PSScriptRoot "../../deploy/windows/Install-ReconAgentTask.ps1"
    & $installer -ServerUrl "https://example.invalid/api/scans" -Role workstation `
        -PythonExe $exe -StateDir $state -CacheDir (Join-Path $root "cache with spaces")
    Assert-True ($global:WynDozeTaskFixture.Trigger.RandomDelay.TotalMinutes -eq 30) "Jitter must be on trigger"
    Assert-True ($global:WynDozeTaskFixture.Principal.UserId -eq "SYSTEM") "SYSTEM principal preserved"
    $wrapper = Join-Path $state "Invoke-ReconAgentScan.ps1"
    $expected = '-NoProfile -NonInteractive -File "' + $wrapper + '"'
    Assert-True ($global:WynDozeTaskFixture.Action.Argument -eq $expected) "Native -File path needs double quotes"
    $engine = (Get-Process -Id $PID).Path
    & $engine -NoProfile -NonInteractive -File $wrapper
    Assert-True ($LASTEXITCODE -eq 3) "Wrapper must propagate the agent exit code"
    $seen = Get-Content -Raw -LiteralPath $env:WYNDOZE_TEST_ARGS | ConvertFrom-Json
    Assert-True ($seen.Args[0] -eq "scan") "Wrapper must call scan"
    Assert-True ($seen.Args[4] -eq "workstation") "Role argument preserved"
    $global:WynDozeTaskFixture = $null
    $global:WynDozeAclExit = 5
    $failed = $false
    $badState = Join-Path $root "acl-failure"
    try {
        & $installer -ServerUrl "https://example.invalid/api/scans" -Role workstation `
            -PythonExe $exe -StateDir $badState -CacheDir (Join-Path $root "cache")
    } catch {
        $failed = $true
    }
    Assert-True $failed "ACL failure must stop installation"
    Assert-True ($null -eq $global:WynDozeTaskFixture) "ACL failure must not register"
    Assert-True (-not (Test-Path (Join-Path $badState "agent.env"))) "ACL failure must not write secrets"
    Write-Host "Task installer contract passed; no task or ACL was changed."
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
