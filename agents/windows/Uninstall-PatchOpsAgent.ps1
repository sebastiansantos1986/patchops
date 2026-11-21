<#
.SYNOPSIS
  Removes the PatchOps Windows agent, its scheduled task, settings and tokens from this computer.
  The device stays listed in PatchOps until you remove it there.
#>
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this from an elevated PowerShell (Run as administrator).' }
Unregister-ScheduledTask -TaskName 'PatchOps Agent' -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:ProgramFiles 'PatchOps') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:ProgramData 'PatchOps') -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'PatchOps agent removed.' -ForegroundColor Green
