<#
.SYNOPSIS
  PatchOps: report installed Windows updates (KB numbers) to Intune.

.DESCRIPTION
  Deploy as the DETECTION script of an Intune Remediation (Devices > Scripts and
  remediations > Remediations). Leave the remediation script empty.
  It never changes the device: it reads the installed-update list and writes one
  line of output that PatchOps reads through Microsoft Graph:

      PATCHOPS_KBS:KB5034441,KB5033375,...

  Settings: Run this script using the logged-on credentials = No (runs as SYSTEM),
  Enforce script signature check = No (or sign it), Run script in 64-bit PowerShell = Yes.
  Schedule: Daily.

  Intune keeps the first 2,048 characters of output, so newest KBs are listed first.
#>

$kbs = New-Object System.Collections.Generic.List[string]

# 1. Component-based servicing (cumulative updates, servicing stacks, many .NET updates)
try {
    Get-HotFix -ErrorAction Stop | ForEach-Object {
        if ($_.HotFixID -match '^KB\d{6,8}$') { $kbs.Add($_.HotFixID.ToUpper()) }
    }
} catch { }

# 2. Windows Update history (adds updates that Get-HotFix does not list)
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $total    = $searcher.GetTotalHistoryCount()
    if ($total -gt 0) {
        $searcher.QueryHistory(0, [Math]::Min($total, 400)) |
            Where-Object { $_.ResultCode -eq 2 } |            # 2 = Succeeded
            ForEach-Object {
                foreach ($match in [regex]::Matches([string]$_.Title, 'KB\d{6,8}')) { $kbs.Add($match.Value.ToUpper()) }
            }
    }
} catch { }

$unique = $kbs | Sort-Object { [int64]($_ -replace '\D', '') } -Descending -Unique
$output = 'PATCHOPS_KBS:' + ($unique -join ',')
if ($output.Length -gt 2000) {
    $output = $output.Substring(0, 2000)
    $output = $output.Substring(0, $output.LastIndexOf(','))
}

Write-Output $output
exit 0   # always "compliant": this script only reports
