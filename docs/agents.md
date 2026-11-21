# PatchOps agents on test computers

Two read-only agents report straight to PatchOps. They add what Intune, Jamf and CrowdStrike don't always
have (every installed app with its exact version, installed KBs, the signed-in user) and show up as
**PatchOps Agent** under "Seen by" on each device.

| | Windows | Mac |
|---|---|---|
| What it is | PowerShell script + scheduled task (SYSTEM) | Native app + per-user LaunchAgent |
| Reports | hourly and at startup | every 15 minutes while the user is logged in |
| Make the kit | `npm run windows:package` | `npm run macos:package` (on a Mac with Xcode command line tools) |
| Kit | `dist/PatchOps-Agent-Windows-kit.zip` | `clients/macos/PatchOpsAgent/dist/PatchOps-Agent-macOS-kit.zip` |
| Install | `Install-PatchOpsAgent.ps1 -ApiUrl … -EnrollmentToken …` (admin) | `PATCHOPS_API_URL=… sh install-on-mac.sh` (as the user) |
| Remove | `Uninstall-PatchOpsAgent.ps1` | `sh uninstall-on-mac.sh` |

Both need two values from your PatchOps server: the **API URL** (`https://…/api`) and the **enrollment token**
(`PATCHOPS_ENROLLMENT_TOKEN`). Treat the token like a password: anyone who has it can enroll a device.

## 1. Host PatchOps so the test computers can reach it

The test computers can't reach PatchOps on your Mac (`127.0.0.1`). The repository includes a Render
Blueprint (`render.yaml`) with the API, the dashboard and a Postgres database:

1. In Render choose **New → Blueprint**, pick this repository and apply it.
2. Render generates `PATCHOPS_ENROLLMENT_TOKEN`, `PATCHOPS_DASHBOARD_PASSWORD` and `PATCHOPS_SESSION_SECRET`.
   Find them under the API service → **Environment**.
3. Add your connector values there too (`INTUNE_*`, `JAMF_*`, `CROWDSTRIKE_*`, same as your `.env`).
   They are stored as Render environment variables; your `.env` never leaves your Mac.
4. The API URL is `https://<api service name>.onrender.com/api`. Check `https://…/api/health`.

Plan limits to know before relying on it:

- **Free web services sleep after 15 minutes without traffic** and take about a minute to wake. Agents
  wake it, but syncs restart from scratch more often. A paid instance type doesn't sleep.
- **Free Postgres databases expire 30 days after creation.** Enrolled devices, rules and dashboards live
  there. Use a paid database for anything you want to keep.
- The free instance has 512 MB of memory. A full Intune + CrowdStrike sync of a large fleet may need a bigger
  instance; if the service restarts during a sync, move up one size.
- The service's disk is temporary, so the sync cache is rebuilt after each restart (first sync is slower).

## 2. Windows test PCs

See `agents/windows/README.md`. In short, on each PC in an elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-PatchOpsAgent.ps1 -ApiUrl https://<api>/api -EnrollmentToken '<token>'
```

## 3. Mac test Macs

On your Mac: `npm run macos:package`. Copy `PatchOps-Agent-macOS-kit.zip` to the test Mac, unzip it, and as
the Mac's user (not sudo):

```sh
cd PatchOps-Agent-macOS-kit
PATCHOPS_API_URL=https://<api>/api sh install-on-mac.sh
```

It asks for the enrollment token. The app has a local (ad-hoc) signature, not an Apple Developer ID, so the
installer clears the download quarantine flag on this one app. For wider rollout, sign it with a Developer ID
and notarize it, or deploy it with Jamf.

## Checking it works

- Windows: `C:\ProgramData\PatchOps\agent.log` shows "Enrolled as …" and "Reported N apps, M updates".
- Mac: `launchctl print gui/$(id -u)/com.patchops.agent.lab` shows the agent running.
- PatchOps: open the device; **Seen by → PatchOps agent** shows the last check-in, or run in Explore:
  `e/ Device f/ DiscoveredBy = "PatchOps Agent"`.
