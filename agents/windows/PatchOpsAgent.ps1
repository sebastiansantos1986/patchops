<#
.SYNOPSIS
  PatchOps Windows agent: reads device and app inventory and reports it to PatchOps.

.DESCRIPTION
  Read-only. Runs as SYSTEM from the "PatchOps Agent" scheduled task (see Install-PatchOpsAgent.ps1).
  Each run: enrolls once with the enrollment token, then sends a heartbeat and the inventory
  (OS version and build, installed apps, installed updates, BitLocker, signed-in user).
  It never installs, removes or changes anything on the device.

  Settings:  C:\ProgramData\PatchOps\agent.json   (API URL, device ID; no secrets)
  Secrets:   C:\ProgramData\PatchOps\secrets.bin  (enrollment + device token, DPAPI-encrypted for this computer)
  Log:       C:\ProgramData\PatchOps\agent.log
  The folder is readable only by SYSTEM and Administrators.

.PARAMETER Inventory
  Print the inventory JSON and exit without contacting PatchOps (to check what would be sent).
#>
[CmdletBinding()]
param(
  [switch]$Inventory,
  [switch]$NoRun
)

$ErrorActionPreference = 'Stop'
$AgentVersion = '1.0.0'
$DataDirectory = Join-Path $env:ProgramData 'PatchOps'
$SettingsPath = Join-Path $DataDirectory 'agent.json'
$SecretsPath = Join-Path $DataDirectory 'secrets.bin'
$LogPath = Join-Path $DataDirectory 'agent.log'

function Write-AgentLog([string]$Message) {
  try {
    if ((Test-Path $LogPath) -and (Get-Item $LogPath).Length -gt 1MB) { Move-Item $LogPath "$LogPath.old" -Force }
    Add-Content -Path $LogPath -Value ("{0}  {1}" -f (Get-Date).ToString('s'), $Message)
  } catch { }
  Write-Verbose $Message
}

# ---------- settings and secrets ----------

function Read-AgentSettings {
  if (-not (Test-Path $SettingsPath)) { throw "PatchOps is not installed: $SettingsPath is missing. Run Install-PatchOpsAgent.ps1." }
  return Get-Content $SettingsPath -Raw | ConvertFrom-Json
}

function Save-AgentSettings($Settings) {
  $Settings | ConvertTo-Json -Depth 4 | Set-Content -Path $SettingsPath -Encoding UTF8
}

function Protect-AgentSecret([string]$Text) {
  Add-Type -AssemblyName System.Security
  $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
  return [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
}

function Unprotect-AgentSecret([byte[]]$Bytes) {
  Add-Type -AssemblyName System.Security
  $plain = [Security.Cryptography.ProtectedData]::Unprotect($Bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
  return [Text.Encoding]::UTF8.GetString($plain)
}

function Read-AgentSecrets {
  if (-not (Test-Path $SecretsPath)) { return [pscustomobject]@{ enrollment_token = $null; agent_token = $null } }
  return (Unprotect-AgentSecret ([IO.File]::ReadAllBytes($SecretsPath))) | ConvertFrom-Json
}

function Save-AgentSecrets($Secrets) {
  [IO.File]::WriteAllBytes($SecretsPath, (Protect-AgentSecret ($Secrets | ConvertTo-Json -Compress)))
}

# ---------- inventory (read-only) ----------

function Get-InstalledApps {
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  # Per-user installs (e.g. some Chrome, Teams, Zoom) for every signed-in user profile.
  foreach ($hive in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
    $paths += "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
  }
  $seen = @{}
  $apps = New-Object System.Collections.Generic.List[object]
  foreach ($path in $paths) {
    foreach ($entry in (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)) {
      $name = [string]$entry.DisplayName
      if ([string]::IsNullOrWhiteSpace($name)) { continue }
      if ($entry.SystemComponent -eq 1 -or $entry.ParentKeyName -or $entry.ReleaseType -match 'Update|Hotfix') { continue }
      $version = [string]$entry.DisplayVersion
      $key = "$name|$version"
      if ($seen.ContainsKey($key)) { continue }
      $seen[$key] = $true
      $source = 'machine'
      if ($path -like 'Registry::HKEY_USERS*') { $source = 'user' }
      $apps.Add([ordered]@{
        name = $name.Trim()
        version = $version.Trim()
        publisher = ([string]$entry.Publisher).Trim()
        install_source = $source
        bundle_identifier = [string]$entry.PSChildName
      })
    }
  }
  return ,$apps.ToArray()
}

function Get-InstalledUpdates {
  try { return ,@(Get-HotFix -ErrorAction Stop | Where-Object { $_.HotFixID -match '^KB\d+$' } | ForEach-Object { $_.HotFixID.ToUpper() } | Sort-Object -Unique) }
  catch { return ,@() }
}

function Get-DiskEncrypted {
  try {
    $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    return [bool]($volume.ProtectionStatus -eq 'On' -or [int]$volume.ProtectionStatus -eq 1)
  } catch { return $null }
}

function Get-SignedInUser {
  try {
    $user = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
    if ($user) { return $user }
  } catch { }
  try { return (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -ErrorAction Stop).LastLoggedOnUser } catch { return '' }
}

function Get-RebootPending {
  return (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
         (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
}

function Get-PatchOpsInventory {
  $os = Get-CimInstance Win32_OperatingSystem
  $system = Get-CimInstance Win32_ComputerSystem
  $bios = Get-CimInstance Win32_BIOS
  $current = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $ubr = if ($current.UBR) { [int]$current.UBR } else { 0 }
  $build = [int]$os.BuildNumber
  $caption = if ($build -ge 22000) { 'Windows 11' } else { 'Windows 10' }
  $lastBoot = $os.LastBootUpTime
  $architecture = switch ($env:PROCESSOR_ARCHITECTURE) { 'ARM64' { 'arm64' } 'AMD64' { 'x86_64' } default { $env:PROCESSOR_ARCHITECTURE } }
  return [ordered]@{
    captured_at = (Get-Date).ToUniversalTime().ToString('o')
    hostname = $env:COMPUTERNAME
    serial_number = ([string]$bios.SerialNumber).Trim()
    model = ("{0} {1}" -f $system.Manufacturer, $system.Model).Trim()
    manufacturer = ([string]$system.Manufacturer).Trim()
    architecture = $architecture
    os = [ordered]@{ name = $caption; version = "10.0.$build.$ubr"; build = "$build"; release = [string]$current.DisplayVersion; edition = [string]$os.Caption }
    assigned_user = Get-SignedInUser
    disk_encrypted = Get-DiskEncrypted
    uptime_seconds = [int]((Get-Date) - $lastBoot).TotalSeconds
    last_reboot_at = $lastBoot.ToUniversalTime().ToString('o')
    reboot_pending = [bool](Get-RebootPending)
    installed_kbs = Get-InstalledUpdates
    software = Get-InstalledApps
  }
}

# ---------- talking to PatchOps ----------

function Invoke-PatchOps([string]$Method, [string]$Path, $Body, [string]$Authorization) {
  $settings = $script:Settings
  $uri = $settings.api_url.TrimEnd('/') + $Path
  $json = $Body | ConvertTo-Json -Depth 6 -Compress
  $headers = @{ Authorization = $Authorization }
  # UTF-8 bytes so app names like "Forcepoint™ Endpoint" arrive intact.
  return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json)) -UseBasicParsing -TimeoutSec 60
}

function Get-StatusCode($ErrorRecord) {
  try { return [int]$ErrorRecord.Exception.Response.StatusCode } catch { return 0 }
}

function Register-PatchOpsDevice($Snapshot, $Secrets) {
  if (-not $Secrets.enrollment_token) { throw 'No enrollment token is stored. Reinstall with -EnrollmentToken.' }
  $body = [ordered]@{
    tenant_id = $script:Settings.tenant_id
    hostname = $Snapshot.hostname
    platform = 'windows'
    serial_number = $Snapshot.serial_number
    model = $Snapshot.model
    architecture = $Snapshot.architecture
    assigned_user = $Snapshot.assigned_user
    agent_version = $AgentVersion
  }
  $response = Invoke-PatchOps 'Post' '/agent/enroll' $body ("Enrollment " + $Secrets.enrollment_token)
  $script:Settings.device_id = $response.device_id
  $Secrets.agent_token = $response.agent_token
  Save-AgentSettings $script:Settings
  Save-AgentSecrets $Secrets
  Write-AgentLog "Enrolled as $($response.device_id)"
}

function Send-PatchOpsReport($Snapshot, $Secrets) {
  $auth = "Bearer " + $Secrets.agent_token
  $heartbeat = [ordered]@{
    device_id = $script:Settings.device_id
    seen_at = $Snapshot.captured_at
    hostname = $Snapshot.hostname
    model = $Snapshot.model
    architecture = $Snapshot.architecture
    assigned_user = $Snapshot.assigned_user
    disk_encrypted = $Snapshot.disk_encrypted
    uptime_seconds = $Snapshot.uptime_seconds
    last_reboot_at = $Snapshot.last_reboot_at
    reboot_pending = $Snapshot.reboot_pending
    installed_kbs = $Snapshot.installed_kbs
    installed_kbs_at = $Snapshot.captured_at
    agent_version = $AgentVersion
    online = $true
  }
  Invoke-PatchOps 'Post' '/agent/heartbeat' $heartbeat $auth | Out-Null
  $inventory = [ordered]@{ device_id = $script:Settings.device_id; captured_at = $Snapshot.captured_at; os = $Snapshot.os; software = $Snapshot.software }
  $result = Invoke-PatchOps 'Post' '/agent/inventory' $inventory $auth
  Write-AgentLog ("Reported {0} apps, {1} updates" -f $result.software_count, @($Snapshot.installed_kbs).Count)
}

function Invoke-PatchOpsCycle {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $script:Settings = Read-AgentSettings
  $secrets = Read-AgentSecrets
  $snapshot = Get-PatchOpsInventory
  if (-not $script:Settings.device_id -or -not $secrets.agent_token) { Register-PatchOpsDevice $snapshot $secrets }
  try {
    Send-PatchOpsReport $snapshot $secrets
  } catch {
    $status = Get-StatusCode $_
    # 401/404: the server no longer knows this device (e.g. its database was reset). Enroll again once.
    if ($status -eq 401 -or $status -eq 404) {
      Write-AgentLog "Server returned $status; enrolling again"
      $secrets.agent_token = $null
      Register-PatchOpsDevice $snapshot $secrets
      Send-PatchOpsReport $snapshot $secrets
    } else { throw }
  }
}

if ($NoRun) { return }
if ($Inventory) { Get-PatchOpsInventory | ConvertTo-Json -Depth 6; return }
try {
  Invoke-PatchOpsCycle
} catch {
  Write-AgentLog ("Error: " + $_.Exception.Message)
  exit 1
}
