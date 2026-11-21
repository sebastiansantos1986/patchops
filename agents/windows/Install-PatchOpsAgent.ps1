<#
.SYNOPSIS
  Installs the PatchOps Windows agent (read-only inventory) on this computer.

.EXAMPLE
  # From an elevated PowerShell, in the folder that contains PatchOpsAgent.ps1:
  powershell -ExecutionPolicy Bypass -File .\Install-PatchOpsAgent.ps1 -ApiUrl https://patchops-api.example.com/api -EnrollmentToken '<token>'

.DESCRIPTION
  - Copies PatchOpsAgent.ps1 to C:\Program Files\PatchOps (only administrators can change it).
  - Stores the API URL in C:\ProgramData\PatchOps\agent.json and the enrollment token encrypted
    for this computer (DPAPI) in secrets.bin. That folder is readable only by SYSTEM and Administrators.
  - Registers the "PatchOps Agent" scheduled task: runs as SYSTEM at startup and every IntervalMinutes.
  - Runs the agent once so the device shows up in PatchOps right away.
  Re-running it updates the agent and settings in place. Remove it with Uninstall-PatchOpsAgent.ps1.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$ApiUrl,
  [Parameter(Mandatory = $true)][string]$EnrollmentToken,
  [string]$TenantId = 'default',
  [ValidateRange(15, 1440)][int]$IntervalMinutes = 60,
  [switch]$AllowHttp
)

$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this from an elevated PowerShell (Run as administrator).' }

$ApiUrl = $ApiUrl.TrimEnd('/')
if ($ApiUrl -notmatch '/api$') { $ApiUrl = "$ApiUrl/api" }
$uri = [Uri]$ApiUrl
if ($uri.Scheme -ne 'https' -and -not $AllowHttp -and $uri.Host -notin @('localhost', '127.0.0.1')) { throw 'Use an https:// API URL (or -AllowHttp for a lab network).' }

$source = Join-Path $PSScriptRoot 'PatchOpsAgent.ps1'
if (-not (Test-Path $source)) { throw "Keep PatchOpsAgent.ps1 next to this installer ($source not found)." }

$programDirectory = Join-Path $env:ProgramFiles 'PatchOps'
$dataDirectory = Join-Path $env:ProgramData 'PatchOps'
$agentPath = Join-Path $programDirectory 'PatchOpsAgent.ps1'

New-Item -ItemType Directory -Force -Path $programDirectory, $dataDirectory | Out-Null
Copy-Item $source $agentPath -Force
Unblock-File $agentPath -ErrorAction SilentlyContinue

# Lock the data folder down to SYSTEM and Administrators (it holds the device token).
& icacls.exe $dataDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

# Reuse the agent's own functions for settings and DPAPI-protected secrets.
. $agentPath -NoRun
$existing = $null
if (Test-Path $SettingsPath) { $existing = Get-Content $SettingsPath -Raw | ConvertFrom-Json }
$sameServer = $existing -and $existing.api_url -eq $ApiUrl
$deviceId = $null
if ($sameServer) { $deviceId = $existing.device_id }
Save-AgentSettings ([pscustomobject]@{ api_url = $ApiUrl; tenant_id = $TenantId; device_id = $deviceId; interval_minutes = $IntervalMinutes; installed_at = (Get-Date).ToUniversalTime().ToString('o') })
$agentToken = $null
if ($sameServer -and (Test-Path $SecretsPath)) { try { $agentToken = (Read-AgentSecrets).agent_token } catch { } }
Save-AgentSecrets ([pscustomobject]@{ enrollment_token = $EnrollmentToken; agent_token = $agentToken })

$taskName = 'PatchOps Agent'
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$agentPath`""
$atStartup = New-ScheduledTaskTrigger -AtStartup
$atStartup.Delay = 'PT5M'
$repeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$runAs = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($atStartup, $repeat) -Principal $runAs -Settings $settings -Description 'PatchOps read-only inventory agent' -Force | Out-Null

Write-Host 'Running the first check-in...'
Start-ScheduledTask -TaskName $taskName
$deadline = (Get-Date).AddMinutes(3)
do { Start-Sleep -Seconds 3 } while ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running' -and (Get-Date) -lt $deadline)
$log = Join-Path $dataDirectory 'agent.log'
if (Test-Path $log) { Get-Content $log -Tail 3 }
$result = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
if ($result -eq 0) { Write-Host "PatchOps agent installed. It reports every $IntervalMinutes minutes." -ForegroundColor Green }
else { Write-Warning "Installed, but the first check-in failed (result $result). See $log." }
