# Posture: Intune + Jamf dashboard

**Posture** is the first page you see after signing in. It pulls device data from Microsoft Intune and Jamf Pro. It matches each computer across both systems by serial number and adds the installed-app inventory collected by the PatchOps agent. The page then answers four questions:

- **Device health:** is the disk encrypted, does Intune consider the device compliant, has it checked in recently, and is it enrolled in the right MDM?
- **OS currency:** which Macs and PCs are behind on updates, or on releases that no longer get security fixes?
- **Outdated apps:** which installed applications are behind your approved version, or behind the newest version already deployed in your fleet?
- **Executive summary:** a 0–100 posture score with a daily trend, the top risks ranked, and a CSV export.

Until you connect Intune or Jamf, the page shows a **sample fleet** with a banner saying so. Real PatchOps agent check-ins are always included.

The connectors only **read** data. PatchOps never changes anything in Intune or Jamf.

---

## 1. Connect Microsoft Intune (about 5 minutes)

**Permissions summary:** Microsoft Graph **application** permissions, read-only, with admin consent.

| Permission | Required? | Used for |
|---|---|---|
| `DeviceManagementManagedDevices.Read.All` | Required | Devices, compliance, encryption, OS build, last sync, discovered apps |
| `DeviceManagementConfiguration.Read.All` | Optional | Exact installed-KB lists from the PatchOps Remediation script |
| `GroupMember.Read.All` and `User.Read.All` | Optional | Queries on Entra ID groups, e.g. excluding `GRP-Intune-Users-France-Finland` |

No write permissions and no delegated permissions are needed. Granting admin consent requires the Global Administrator or Privileged Role Administrator role in Microsoft Entra ID; creating the app registration can be done by an Application Administrator.

1. Open the [Microsoft Entra admin center](https://entra.microsoft.com) and go to **Identity → Applications → App registrations → New registration**.
2. Name it `PatchOps Posture`, choose **Accounts in this organizational directory only**, leave the Redirect URI empty, and click **Register**.
3. On the app's **Overview** page, copy the **Application (client) ID** and the **Directory (tenant) ID**.
4. Go to **API permissions → Add a permission → Microsoft Graph → Application permissions**. Add **`DeviceManagementManagedDevices.Read.All`**, then click **Grant admin consent for <your organization>**.
5. Go to **Certificates & secrets → Client secrets → New client secret**. Choose an expiry and copy the secret **Value** immediately; it is shown only once.

## 2. Connect Jamf Pro (about 5 minutes)

1. In Jamf Pro, go to **Settings → System → API roles and clients**.
2. On the **API Roles** tab, click **New**, name it `PatchOps read-only`, and add the privilege **Read Computers**. Save.
3. On the **API Clients** tab, click **New**, name it `PatchOps Posture`, assign the `PatchOps read-only` role, toggle **Enable API client**, and save.
4. Click **Generate client secret** and copy both the **Client ID** and the **Client Secret**.
5. Your Jamf URL is the address you sign in to, for example `https://yourcompany.jamfcloud.com`.

## 2b. Connect CrowdStrike Falcon (optional, about 3 minutes)

1. In the Falcon console, go to **Support and resources → API clients and keys → Create API client**.
2. Name it `PatchOps Posture` and tick only **Read** permissions:
   - **Hosts → Read** (required): devices and sensor health.
   - **Assets → Read** (optional): installed applications, from Falcon Discover / Exposure Management.
   - **Vulnerabilities → Read** (optional): open CVEs with remediation, from Falcon Spotlight.

   Create the client, then copy the **Client ID** and **Secret**. The secret is shown only once. You can add scopes later; the secret stays the same.
3. Add both to `.env` as `CROWDSTRIKE_CLIENT_ID` and `CROWDSTRIKE_CLIENT_SECRET`.

PatchOps detects your Falcon cloud (US-1, US-2, EU-1 or GovCloud) automatically. Only if sign-in fails with a cloud error, add `CROWDSTRIKE_CLOUD=us-2` (or `eu-1`, `us-gov-1`).

It reads Windows and Mac **workstations**: hostname, serial number, OS build, sensor version, last seen, reduced-functionality mode and containment status. Servers are skipped unless `CROWDSTRIKE_INCLUDE_SERVERS=true`.

CrowdStrike adds these checks:
- **Not in CrowdStrike:** active in Jamf/Intune but with no Falcon host record.
- **Sensor not reporting:** the device is active but Falcon hasn't seen it for more than 7 days.
- **Reduced functionality mode.**
- **Network-contained hosts.**

With **Assets: Read**, Falcon's installed-application inventory is used for Windows PCs (and for Macs that Jamf doesn't cover). That makes software rules and outdated-app checks work without Intune.

With **Vulnerabilities: Read**, open CVEs from Spotlight appear on:
- the **Vulnerabilities** page: every CVE, with severity, CVSS, ExPRT rating, exploit status, CISA KEV, affected product, device count and fix;
- each device panel;
- in Explore, as the `Vulnerability` entity (`CVE`, `Severity`, `Score`, `ExPRT`, `ExploitStatus`, `KEV`, `Product`, `KB`) and the device fields `OpenCVEs`, `CriticalCVEs`, `ExploitedCVEs` and `HighestCVSS`.

KBs that Spotlight recommends become `MissingPatch` records with `Method = spotlight`. Actively exploited CVEs count as critical in the posture score.

If a scope or license is missing, that part shows **Missing permission** on the **Data Sources** page; everything else keeps working.

**Data Sources** shows, for every connected system:
- each API capability and its permission status;
- every field returned, with how often it's filled and an example;
- raw sample records, with secrets redacted.

Each device panel also has the full raw record from every source.

In Explore it adds the fields `InCrowdStrike`, `CrowdStrikeReporting`, `CrowdStrikeLastSeenAt`, `CrowdStrikeSensorVersion`, `CrowdStrikeRFM`, `CrowdStrikeContained` and `CrowdStrikeTags`. **Add widget** offers a ready-made *Devices Not Syncing CrowdStrike* template.

If Intune isn't connected yet, CrowdStrike also supplies Windows OS builds, so tracked KBs and Windows version checks still work.

## 3. Add the credentials and restart

In the PatchOps folder, copy the example file and fill in what you collected:

```bash
cp .env.example .env
open -e .env        # or edit it with any text editor
```

```dotenv
INTUNE_TENANT_ID=00000000-0000-0000-0000-000000000000
INTUNE_CLIENT_ID=00000000-0000-0000-0000-000000000000
INTUNE_CLIENT_SECRET=paste-the-secret-value

JAMF_URL=https://yourcompany.jamfcloud.com
JAMF_CLIENT_ID=paste-the-client-id
JAMF_CLIENT_SECRET=paste-the-client-secret
```

Stop `npm run dev` (Ctrl+C) and start it again. The first sync runs when you open **Posture**, and then again every 30 minutes. **Sync now** forces an immediate sync. The source cards at the top show what each system returned, or the exact error if a credential or permission is wrong.

`.env` is listed in `.gitignore`. Never commit it.

You can connect just one system: Intune only, or Jamf only.

### On Render

Add the same variables under the API service's **Environment** settings instead of using a `.env` file.

---

## Dashboards, Explore and Device rules

Three more pages in the sidebar turn the merged fleet into reports, in the same style as Cyclops:

- **Dashboards:** saved reporting views. Out of the box you get *IT - Security Agents Status* (one installed/missing donut per required agent, plus removal-progress trends for software being uninstalled), *Windows Patch Rollout* and *Device Health*. **Add widget** builds donuts, trends, numbers, breakdowns or device tables from queries. **Download PDF** prints the dashboard. Clicking any segment, bar or number opens the matching devices in Explore.
- **Explore:** ask which devices match. The **Builder** tab lets anyone add conditions without learning the syntax: pick a field, an operator in plain words ("within the last", "is at least") and a value, then use **+ Has / doesn't have…** for related records (software, updates, CVEs, the user and their groups) and **+ Either/or group** for OR. **Query text** accepts pasted Cyclops queries, and switching back turns them into blocks. The match count and a plain-English summary update as you type.
- **Device rules:** the required/prohibited software list and the Windows updates (KBs) you track.

Every dashboard widget uses the same builder for its categories. Coverage donuts show a headline percentage per platform with the change since last week, and **What counts** spells out each category in plain English.

Trends record one point per day per query, kept for 180 days. A new widget's line appears from its second day.

### Query syntax

```text
e/ Device f/ Platform = windows f/ OSRelease = 11 f/ LastSeenAt < 7d
e/ Device f/ Platform = windows r/ ( e/ SecurityPatch f/ UniquePatchId contains_any (KB5032190,KB5033375) ) f/ LastSeenAt < 7d
e/ Device f/ Platform = macos not r/ ( e/ SoftwareRule f/ Name = "Okta Verify" f/ Status = installed )
e/ Device r/ ( e/ App f/ Name contains chrome f/ Version < 142 )
e/ Device f/ LastSeenAt > 30d or e/ Device f/ Encrypted = false
```

- `e/` picks the entity, and `f/` adds a filter; all filters must match.
- `( f/ A = 1 ) OR ( f/ B = 2 )` matches either; parentheses can be nested.
- `r/ ( … )` requires a related record that matches the inner query; `!r/ ( … )` or `not r/ ( … )` requires that none match. Relations nest: `!r/ ( e/ User r/ ( e/ Group f/ EntityName = "GRP-…" ) )`.
- Related entities: `Software` (or `App`), `SecurityPatch` (installed KBs), `MissingPatch` (tracked KBs the device lacks), `Vulnerability`, `ExtensionAttribute`, `User` (then `Group`), `SoftwareRule` and `Issue`.
- Cyclops device fields work as-is: `CrowdstrikeFalconHostType`, `CrowdStrikeFalconLastSeenAt`, `DiscoveredBy` (Intune, Jamf, CrowdStrike Falcon, PatchOps Agent), `IntuneManagedDeviceOwnerType`, `OSType`, and `EntityName` on software and groups.
- Operators: `=`, `!=`, `<`, `>`, `<=`, `>=`, `contains`, `not_contains`, `contains_any (a,b)`, `in (a,b)`, `not_in (a,b)`, `starts_with`, `exists` and `not_exists`.
- Versions compare as versions, so `OSVersion < 26` and `Version < 142.0.7444` work.
- Dates take durations: `LastSeenAt < 7d` means seen in the last 7 days.
- Cyclops/CrowdStrike field names such as `CrowdstrikeFalconOSDistribution` and `FalconSpotlightOSType` are accepted, so existing queries can be pasted in.

The Explore page lists every field.

### Required and prohibited software

Each rule has three parts, all edited with the builder:

- **Applies to** (optional): which devices are checked, e.g. only workstations.
- **Detection** per platform: the software conditions that count as installed, e.g. name contains `Forcepoint` *and* version is at least `30.9`, or an either/or group for different app names.
- **Falcon sensor** (optional): a CrowdStrike sensor that reported in the last 7 days counts as installed. CrowdStrike rules use this by default, because Intune and Jamf app lists often miss the sensor.

**Preview on my fleet** shows the counts and example devices before you save. Rules saved by earlier versions are upgraded automatically. The defaults are:
- Required: CrowdStrike Falcon, BeyondTrust EPM and Okta Verify.
- Being removed: Tenable Nessus Agent and CyberArk EPM.

Adjust the conditions to the exact names your inventory reports: open a device in Posture and filter its apps to see them. Devices with no app inventory show as "No data" (grey) rather than missing. Violations also feed the posture score.

### Operating system rules

Choose **Add rule → Operating system requirement** to set the OS versions you allow, per platform, with the same builder. For example `OSBuild >= 26100` (Windows 11 24H2 or later) and `OSVersion >= 15.7` for Macs. Devices that match are *compliant*; others get an issue on Posture, and the rule can be added to a dashboard as a compliance donut.

When you pick **Name** in a software condition, the value box lists every app name reported in your fleet (most common first), so you can choose the exact name instead of guessing.

### Appearance

The palette button in the top bar switches the theme (Glacier light, Harbour dark blue, Graphite dark, or match your computer) and the accent colour, including any custom colour. The choice is saved in your browser, so each person can pick their own.

### Group conditions (Entra ID)

Queries can include or exclude users by group: `!r/ ( e/ User r/ ( e/ Group f/ EntityName = "GRP-Intune-Users-France-Finland" ) )`. PatchOps fetches members only for the groups your queries, widgets and rules name (nested groups included), after each Intune sync and the first time a new group appears in Explore. Devices are matched by their primary user's email / UPN. This needs the optional Graph permissions `GroupMember.Read.All` and `User.Read.All` (application, admin consent); without them the query shows a message instead of wrong counts.

### Tracking Windows updates (KBs)

**Build-number inference (no setup).** Monthly Windows updates are cumulative, and each KB moves Windows to a known build. In **Device rules → Track an update**, enter the KB and the build(s) it produces. Microsoft's *Windows 11 update history* page lists them as "KB50xxxxx (OS Build 26100.xxxx)". One KB often covers several releases, for example `26100.7171, 26200.7171`. Any PC on that feature build with an equal or higher revision counts as patched, using the build Intune already reports. This matches how cumulative updates work: a newer one includes the older fixes.

**Exact KB lists (optional: Intune Remediations).** Use this for updates that don't change the build, such as .NET, or to see every installed KB:

1. In the Intune admin center, go to **Devices → Scripts and remediations → Remediations → Create**.
2. Name it `PatchOps - Report installed KBs` and upload `scripts/intune/Detect-InstalledKBs.ps1` as the **detection script**. Leave the remediation script empty.
3. Set *Run this script using the logged-on credentials* = **No**, *Enforce script signature check* = **No** and *Run script in 64-bit PowerShell* = **Yes**.
4. Assign it to your Windows devices with a **Daily** schedule.
5. Open the remediation and copy its ID, the GUID in the browser address bar.
6. In your Entra app registration, add the Graph **application** permission **`DeviceManagementConfiguration.Read.All`** and grant admin consent.
7. Add `INTUNE_KB_SCRIPT_ID=<that GUID>` to `.env` and restart.

The script only reads the update list; it changes nothing on the PC. Device rules shows how many devices are reporting. Remediations requires the Windows licensing Microsoft lists for that feature (normally Windows Enterprise E3/E5 or equivalent). PatchOps reads the results through the Microsoft Graph **beta** endpoint, which Microsoft may change.

## Independent vulnerability data (Apple, Microsoft, CISA)

Operating-system CVEs don't depend on CrowdStrike. The server downloads three free, public feeds once a day; no accounts or keys are needed.
- **Apple:** the SOFA feed maintained by the Mac Admins community from Apple's security notes. It lists every macOS release, the CVEs it fixes, and which are actively exploited. A Mac on 26.6.2 is shown every CVE fixed in later macOS 26 releases.
- **Microsoft:** the MSRC security update API. For every CVE it gives the KB and the exact Windows build that fixes it (12 months are loaded). A PC on build 26200.9711 is shown every CVE fixed in a later 26200 build, with the KB to install.
- **CISA Known Exploited Vulnerabilities:** marks CVEs being exploited in the wild, whatever source found them.

The same feeds give the real "latest" macOS and Windows builds, so **OS currency** compares against what Apple and Microsoft have released rather than the newest version in your fleet.

On the **Vulnerabilities** page each CVE shows its source (Apple, Microsoft and/or CrowdStrike). **Data Sources** shows each feed's status. Third-party app CVEs still come from CrowdStrike Spotlight.

If the server can't reach the internet, set `POSTURE_CVE_FEEDS=false`.

## Java versions and processor architecture (Macs)

- **Architecture** (`arm64` for Apple silicon or `x86_64` for Intel) comes from Jamf hardware inventory. Use it in Explore with `f/ Architecture = x86_64`.
- **Jamf extension attributes** are read too, and are queryable as `r/ ( e/ ExtensionAttribute f/ Name = "…" f/ Value contains … )`.
- To see installed Java runtimes, which Jamf's app list doesn't include, add `scripts/jamf/EA-Java-Versions.sh` as an extension attribute:
  1. In Jamf Pro, go to **Settings → Computer management → Extension attributes → New**.
  2. Name it `Java Versions`, with data type **String** and input type **Script**.
  3. Paste the script.

  After the next inventory update, this finds Macs exposed to a Java issue such as Java4Shell (CVE-2026-114938):

  ```text
  e/ Device f/ Platform = macos f/ Architecture = x86_64 r/ ( e/ ExtensionAttribute f/ Name = "Java Versions" f/ Value contains_any (17., 21., 25., 27.) )
  ```

## Saved data and incremental syncs

PatchOps keeps a private copy of what it last downloaded, in `.patchops-cache/` inside the project folder. The copy holds no API secrets or tokens, the folder is readable only by your account (permissions 700/600), and it's git-ignored. After a restart the dashboard shows that copy immediately and refreshes in the background; the source cards say "(saved copy)" until the refresh finishes.

Syncs fetch only what changed:

| Source | What is re-downloaded |
|---|---|
| Intune | Device list each sync; installed apps only for PCs whose last sync time changed |
| Jamf | Computer inventory (a few requests for the whole fleet) |
| CrowdStrike hosts | Host list (a few requests) |
| CrowdStrike apps and CVEs | Only records changed since the last sync; closed CVEs are removed. A full refresh runs every 24 hours to catch removals |
| Apple and CISA feeds | Only if the file changed (conditional download; the server answers "not modified") |
| Microsoft | Only new or revised monthly documents |

- **Data Sources** shows what each source did on its last sync: incremental, full, or unchanged.
- **Data Sources → Full resync now** re-downloads everything.
- Deleting `.patchops-cache/` has the same effect on the next start.
- If a source rejects an incremental request, PatchOps falls back to a full download automatically.

| Setting | Default | Meaning |
|---|---|---|
| `POSTURE_CACHE` | `true` | Set `false` to keep data in memory only |
| `POSTURE_CACHE_DIR` | `.patchops-cache` | Where the saved copy lives |
| `CROWDSTRIKE_FULL_SYNC_HOURS` | `24` | How often CrowdStrike apps/CVEs are fully re-downloaded |
| `POSTURE_CVE_REFRESH_HOURS` | `24` | How often the public feeds are checked |

## How the checks work

| Check | Severity | Source |
|---|---|---|
| Disk not encrypted (FileVault / BitLocker) | Critical | Jamf, Intune |
| Windows 10 (out of support since Oct 14, 2025) or macOS 3+ releases behind | Critical | Intune, Jamf, agent |
| Reported jailbroken | Critical | Intune |
| Intune non-compliant | High | Intune |
| No check-in for more than 2× the stale threshold | High | All |
| System Integrity Protection disabled | High | Jamf |
| Mac missing from Jamf, or PC missing from Intune | High | Cross-source |
| Watch-listed app (browser, Zoom, Office, VPN…) a major version behind | High | Agent, Jamf, Intune |
| Watch-listed app behind by a minor version or patch | Medium | Agent, Jamf, Intune |
| OS security update pending (behind the newest build of the same release in your fleet) | Medium | All |
| Required software missing / prohibited software still installed | Per rule | App inventory |
| Tracked Windows update missing | Per update | Intune build, Remediation report |
| Intune grace period; Gatekeeper off; unmanaged in Jamf; overdue check-in | Medium | Various |
| Older OS release still supported; macOS firewall off; Mac without an Intune compliance signal; other apps behind | Low | Various |

**Device risk score:** each device starts at 0 and gains 40 points per critical issue, 20 per high, 8 per medium and 3 per low, capped at 100. The **posture score** is the fleet average of `100 − risk`.

**App targets:** if you add an app to the PatchOps catalog with an approved version (Devices → device detail), that version and severity win. Otherwise the target is the newest version of that app already running somewhere in your fleet. That means it flags drift without needing an external vulnerability feed.

**Where app inventory comes from:** the PatchOps agent if installed, otherwise Jamf (Macs), otherwise Intune "discovered apps".

**Daily trend:** one snapshot per day, stored in PostgreSQL when `DATABASE_URL` is set, or in memory when running locally.

## Optional tuning (`.env`)

| Variable | Default | Meaning |
|---|---|---|
| `POSTURE_SYNC_MINUTES` | `30` | How often Intune and Jamf are re-read (minimum 5) |
| `POSTURE_STALE_DAYS` | `14` | Days without a check-in before a device is flagged |
| `POSTURE_LATEST_MACOS` | newest seen | Treat this as the latest macOS (e.g. `26.1`), useful if no Mac in the fleet has it yet |
| `POSTURE_MIN_MACOS` | — | Flag Macs below this version as High |
| `POSTURE_MIN_WINDOWS_BUILD` | `22000` | Flag PCs below this build as High |
| `POSTURE_LATEST_WINDOWS_BUILD` | newest seen | Treat this feature build as current (e.g. `26100`) |
| `INTUNE_INCLUDE_APPS` | `true` | Fetch Intune discovered apps per device (one Graph call per PC) |
| `INTUNE_APP_CONCURRENCY` | `4` | Parallel Graph calls for app inventory (max 10) |
| `INTUNE_KB_SCRIPT_ID` | — | ID of the PatchOps Remediation, for exact installed-KB lists |
| `JAMF_USERNAME` / `JAMF_PASSWORD` | — | Fallback for Jamf versions without API clients |
| `POSTURE_DATA_MODE` | `auto` | `sample` forces demo data; `live` never shows sample data |

## Limits of this first version

- Covers Windows and macOS computers only. iOS, iPadOS and Android devices are skipped.
- Dashboards and rules are shared by every console user; Operators and above can edit them, Reviewers can only view.
- App findings come from version drift and your catalog rather than a vulnerability feed. Adding a vulnerability source (for example NVD, or Microsoft Defender Vulnerability Management) is a natural next step.
- On large tenants (thousands of PCs), Intune app inventory makes one Graph request per device, so the first sync can take a few minutes. Set `INTUNE_INCLUDE_APPS=false` if the PatchOps agent already covers those PCs.
