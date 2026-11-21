# PatchOps agent for Windows

A read-only PowerShell agent. Every hour (and at startup) it reports to PatchOps:

- computer name, serial number, manufacturer and model, CPU architecture
- Windows version, build and update revision (e.g. 10.0.26100.7171, 24H2)
- installed apps (machine-wide and per-user) with versions and publishers
- installed updates (KB numbers), BitLocker status, signed-in user, last reboot, pending reboot

It never installs, removes or changes anything. It runs as the "PatchOps Agent" scheduled task under SYSTEM.

## Install on a test PC

1. Copy this folder to the PC (or unzip `PatchOps-Agent-Windows-kit.zip`).
2. Open **PowerShell as administrator** in that folder and run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Install-PatchOpsAgent.ps1 `
     -ApiUrl https://<your-patchops-api>/api `
     -EnrollmentToken '<enrollment token>'
   ```

3. The installer runs a first check-in and prints the result. The PC appears in PatchOps within a minute,
   listed as seen by **PatchOps Agent** (merged with its Intune / CrowdStrike record by serial number).

Options: `-IntervalMinutes 30` (default 60), `-TenantId`, and `-AllowHttp` for a lab server without HTTPS.

To see exactly what would be sent, without sending anything:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Program Files\PatchOps\PatchOpsAgent.ps1" -Inventory
```

## Where things live

| What | Where |
|---|---|
| Agent script | `C:\Program Files\PatchOps\PatchOpsAgent.ps1` (only administrators can change it) |
| Settings (API URL, device ID) | `C:\ProgramData\PatchOps\agent.json` |
| Enrollment and device tokens | `C:\ProgramData\PatchOps\secrets.bin`, encrypted for this computer (DPAPI) |
| Log | `C:\ProgramData\PatchOps\agent.log` |

`C:\ProgramData\PatchOps` is readable only by SYSTEM and Administrators.

## Remove

```powershell
powershell -ExecutionPolicy Bypass -File .\Uninstall-PatchOpsAgent.ps1
```

## Deploying with Intune (later)

Wrap the folder as a Win32 app (`IntuneWinAppUtil.exe`) with install command
`powershell -ExecutionPolicy Bypass -File .\Install-PatchOpsAgent.ps1 -ApiUrl … -EnrollmentToken …`,
uninstall command `powershell -ExecutionPolicy Bypass -File .\Uninstall-PatchOpsAgent.ps1`, and detection rule
"file exists: `C:\Program Files\PatchOps\PatchOpsAgent.ps1`". If your organisation requires signed scripts,
sign the three `.ps1` files with your code-signing certificate first.
