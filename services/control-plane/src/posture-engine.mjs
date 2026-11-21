// Correlates device records from Intune, Jamf and the PatchOps agent into one
// device list, then evaluates each device against simple, explainable checks.
// Pure functions only: no I/O, so the rules are easy to test and tune.

import { evaluateSoftwareRule, evaluateTrackedPatch } from "./fleet-config.mjs";
import { compareVersions, softwareIdentity } from "./patch-engine.mjs";

export const SEVERITY_WEIGHT = { critical: 40, high: 20, medium: 8, low: 3, info: 0 };
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SOURCE_PRIORITY = { macos: ["jamf", "agent", "intune", "crowdstrike"], windows: ["intune", "agent", "crowdstrike", "jamf"] };
const DAY = 86_400_000;
// Where installed-app inventory is taken from, best first.
const APP_PRIORITY = { macos: ["agent", "jamf", "crowdstrike", "intune"], windows: ["agent", "crowdstrike", "intune", "jamf"] };

// Apps that are frequently targeted or handle untrusted content. Falling behind on
// these is weighted higher than on general utilities.
const WATCHLIST = [
  /chrome/, /firefox/, /edge/, /safari/, /brave/, /zoom/, /slack/, /teams/, /webex/, /acrobat/, /adobe reader/,
  /java\b|jre|jdk/, /microsoft 365|office|word|excel|powerpoint|outlook/, /1password|lastpass|bitwarden/,
  /anyconnect|secure client|globalprotect|forticlient/, /citrix|workspace app/, /docker/, /visual studio code|vscode/,
  /7-zip|winrar/, /notepad\+\+/, /vlc/, /putty/, /node\.?js/, /python/
];

const PLACEHOLDER_SERIALS = new Set(["", "0", "NA", "N/A", "NONE", "UNKNOWN", "DEFAULTSTRING", "TOBEFILLEDBYOEM", "SYSTEMSERIALNUMBER", "NOTAVAILABLE", "0123456789", "CHASSISSERIALNUMBER"]);

export function deviceKey(record) {
  const serial = String(record.serial_number ?? "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (!PLACEHOLDER_SERIALS.has(serial) && serial.length >= 5) return `sn:${serial}`;
  const host = String(record.hostname ?? "").toLowerCase().replace(/\.local$|\..*$/, "").trim();
  return host ? `host:${host}` : `src:${record.source}:${record.source_id}`;
}

const appKeyCache = new Map();
export function appKey(name) {
  const text = String(name ?? "");
  const cached = appKeyCache.get(text);
  if (cached !== undefined) return cached;
  const key = appKeyUncached(text);
  if (appKeyCache.size > 200_000) appKeyCache.clear();
  appKeyCache.set(text, key);
  return key;
}

function appKeyUncached(name) {
  return String(name ?? "")
    .toLowerCase()
    .replace(/\.app$/, "")
    .replace(/\((x64|x86|64-bit|32-bit)\)/g, "")
    .replace(/\b(\d+(\.\d+)*)\b(?=\s*(\(|$))/g, "") // trailing version numbers in display names, e.g. "7-Zip 25.01"
    .replace(/\bupdate \d+$/, "")
    .replace(/\s+/g, " ")
    .trim();
}

const isWatchlisted = (name) => WATCHLIST.some((pattern) => pattern.test(name));
// Built-in Apple apps (Contacts, Find My, Digital Color Meter…) are updated by macOS
// itself, so comparing them across Macs only repeats the OS-currency finding.
// Safari is kept because it can be updated separately and is a high-exposure app.
const MAC_SYSTEM_APP_NAMES = new Set(["contacts", "findmy", "find my", "digital color meter", "calendar", "mail", "messages", "facetime", "maps", "notes", "photos", "preview", "reminders", "music", "tv", "podcasts", "books", "news", "stocks", "home", "weather", "clock", "freeform", "shortcuts", "system settings", "system preferences", "app store", "calculator", "chess", "dictionary", "font book", "image capture", "launchpad", "mission control", "photo booth", "quicktime player", "siri", "stickies", "textedit", "time machine", "voice memos", "activity monitor", "terminal", "console", "disk utility", "keychain access", "migration assistant", "screenshot", "system information", "voiceover utility", "bluetooth file exchange", "colorsync utility", "audio midi setup", "directory utility", "automator", "script editor", "grapher", "boot camp assistant", "airport utility", "passwords", "iphone mirroring", "journal", "games", "image playground", "tips", "magnifier", "screen sharing", "ticket viewer", "wireless diagnostics", "feedback assistant", "archive utility", "about this mac", "finder"]);
export const isMacSystemApp = (app) => {
  const bundle = String(app.bundle_id ?? "").toLowerCase();
  if (bundle === "com.apple.safari") return false;
  if (bundle.startsWith("com.apple.")) return true;
  return !bundle && MAC_SYSTEM_APP_NAMES.has(appKey(app.name));
};
const majorOf = (version) => Number(String(version ?? "").split(".")[0]) || 0;
// macOS jumped from 15 (Sequoia) to 26 (Tahoe), so compare releases by position, not number.
export const macReleaseIndex = (major) => (major >= 26 ? 15 + (major - 25) : major);
const windowsBuild = (version) => Number(String(version ?? "").split(".")[2]) || 0;
const windowsUbr = (version) => Number(String(version ?? "").split(".")[3]) || 0;
const newest = (values) => values.filter(Boolean).reduce((best, value) => (!best || compareVersions(value, best) > 0 ? value : best), null);
const maxSeverity = (severities) => SEVERITY_ORDER.find((level) => severities.includes(level)) ?? null;
const pct = (part, whole) => (whole ? Math.round((part / whole) * 1000) / 10 : null);

export function mergeRecords(records) {
  const groups = new Map();
  for (const record of records) {
    const key = deviceKey(record);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(record);
  }
  return [...groups.entries()].map(([key, group]) => {
    const platform = group.find((record) => record.platform === "macos" || record.platform === "windows")?.platform ?? group[0].platform;
    const priority = SOURCE_PRIORITY[platform] ?? ["intune", "jamf", "agent", "crowdstrike"];
    const ordered = [...group].sort((left, right) => priority.indexOf(left.source) - priority.indexOf(right.source));
    const freshest = [...group].sort((left, right) => Date.parse(right.last_check_in ?? 0) - Date.parse(left.last_check_in ?? 0))[0];
    const first = (pick) => ordered.map(pick).find((value) => value !== undefined && value !== null && value !== "");
    // Freshest precise OS version wins; partial versions (e.g. CrowdStrike "15.6" for macOS) only fill gaps.
    const osSource = [freshest, ...ordered].find((record) => record.os?.version && !record.os_approximate) ?? [freshest, ...ordered].find((record) => record.os?.version) ?? ordered[0];
    // "26.5.0" and "26.5" are the same macOS release; show one form.
    const osVersion = platform === "macos" ? String(osSource.os?.version ?? "").replace(/^(\d+\.\d+)\.0$/, "$1") : osSource.os?.version ?? "";
    const sources = {};
    for (const record of group) {
      sources[record.source] = { id: record.source_id, last_check_in: record.last_check_in, managed: record.managed, compliance: record.compliance, os_version: record.os?.version ?? "", ...(record.sensor ? { sensor: record.sensor } : {}) };
    }
    const appSource = (APP_PRIORITY[platform] ?? ["agent", ...priority]).map((source) => group.find((record) => record.source === source && Array.isArray(record.apps))).find(Boolean);
    const vulnerabilitySource = group.find((record) => Array.isArray(record.vulnerabilities));
    return {
      id: key,
      hostname: first((record) => record.hostname) ?? "Unknown device",
      serial_number: first((record) => record.serial_number) ?? "",
      platform,
      model: first((record) => record.model) ?? "",
      manufacturer: first((record) => record.manufacturer) ?? "",
      os: { name: osSource.os?.name ?? "", version: osVersion, build: osSource.os?.build ?? "" },
      user: { name: first((record) => record.user?.name) ?? "", email: first((record) => record.user?.email) ?? "" },
      last_check_in: freshest.last_check_in ?? null,
      ownership: first((record) => record.ownership) ?? "",
      encrypted: first((record) => record.encrypted),
      compliance: group.find((record) => record.source === "intune")?.compliance ?? null,
      security: {
        sip: first((record) => record.security?.sip),
        gatekeeper: first((record) => record.security?.gatekeeper),
        firewall: first((record) => record.security?.firewall),
        jailbroken: first((record) => record.security?.jailbroken)
      },
      jamf_managed: group.find((record) => record.source === "jamf")?.managed ?? null,
      crowdstrike: group.find((record) => record.source === "crowdstrike")?.sensor ?? null,
      architecture: first((record) => record.architecture) ?? "",
      extension_attributes: group.flatMap((record) => record.extension_attributes ?? []),
      sources,
      apps: appSource ? appSource.apps : [],
      vulnerabilities: vulnerabilitySource ? vulnerabilitySource.vulnerabilities : null,
      raw: Object.fromEntries(group.filter((record) => record.raw).map((record) => [record.source, record.raw])),
      reported_kbs: group.find((record) => Array.isArray(record.reported_kbs))?.reported_kbs ?? null,
      reported_kbs_at: group.find((record) => Array.isArray(record.reported_kbs))?.reported_kbs_at ?? null,
      apps_source: appSource?.source ?? null,
      sample: group.every((record) => record.sample)
    };
  });
}

export function osBaselines(devices, settings = {}) {
  const macVersions = devices.filter((device) => device.platform === "macos").map((device) => device.os.version);
  const winVersions = devices.filter((device) => device.platform === "windows").map((device) => device.os.version);
  const publishedMac = Object.values(settings.macLatestByMajor ?? {});
  const latestMac = settings.latestMacos || newest(publishedMac) || newest(macVersions) || null;
  const latestWin = newest(winVersions);
  const latestWinBuild = Number(settings.latestWindowsBuild) || windowsBuild(latestWin);
  const latestUbrByBuild = {};
  for (const version of winVersions) {
    const build = windowsBuild(version);
    latestUbrByBuild[build] = Math.max(latestUbrByBuild[build] ?? 0, windowsUbr(version));
  }
  // Microsoft's own latest fixed revision per build wins over "newest seen in the fleet".
  for (const [build, ubr] of Object.entries(settings.winLatestUbrByBuild ?? {})) latestUbrByBuild[build] = Math.max(latestUbrByBuild[build] ?? 0, ubr);
  const latestMacByMajor = {};
  for (const version of macVersions) {
    const major = majorOf(version);
    if (!latestMacByMajor[major] || compareVersions(version, latestMacByMajor[major]) > 0) latestMacByMajor[major] = version;
  }
  // Apple's published latest release per major (from the SOFA feed) wins when known.
  for (const [major, version] of Object.entries(settings.macLatestByMajor ?? {})) latestMacByMajor[major] = version;
  return {
    macos: { latest: latestMac, latest_major: majorOf(latestMac), supported_majors: 3, minimum: settings.minMacos || null, latest_by_major: latestMacByMajor, published: publishedMac.length > 0 },
    windows: { latest: latestWin, latest_build: latestWinBuild, minimum_build: Number(settings.minWindowsBuild) || 22000, latest_ubr_by_build: latestUbrByBuild, published: Object.keys(settings.winLatestUbrByBuild ?? {}).length > 0 }
  };
}

function osStatus(device, baselines) {
  const version = device.os.version;
  if (!version) return { status: "unknown", issue: null };
  if (device.platform === "macos") {
    const base = baselines.macos;
    const major = majorOf(version);
    if (base.minimum && compareVersions(version, base.minimum) < 0) return { status: "below_minimum", issue: { id: "os_below_minimum", severity: "high", title: "macOS below required minimum", detail: `Running ${version}; your minimum is ${base.minimum}.` } };
    if (base.latest_major && macReleaseIndex(base.latest_major) - macReleaseIndex(major) >= base.supported_majors) return { status: "unsupported", issue: { id: "os_unsupported", severity: "critical", title: "macOS no longer receiving security updates", detail: `macOS ${major} is ${macReleaseIndex(base.latest_major) - macReleaseIndex(major)} releases behind macOS ${base.latest_major}. Apple generally ships security fixes only for the current and two previous releases.` } };
    const latestForMajor = base.latest_by_major[major];
    if (latestForMajor && compareVersions(version, latestForMajor) < 0) return { status: "update_available", issue: { id: "os_update_available", severity: "medium", title: "macOS security update pending", detail: `Running ${version}; ${latestForMajor} is ${base.published ? "the latest Apple release for macOS " + major : "already deployed elsewhere in the fleet"}.` } };
    if (major < base.latest_major) return { status: "older_release", issue: { id: "os_older_release", severity: "low", title: "Older macOS release", detail: `Running macOS ${major}; macOS ${base.latest_major} is available.` } };
    return { status: "current", issue: null };
  }
  if (device.platform === "windows") {
    const base = baselines.windows;
    const build = windowsBuild(version);
    if (build && build < 22000) return { status: "unsupported", issue: { id: "os_unsupported", severity: "critical", title: "Windows 10 is out of support", detail: `Build ${build}. Windows 10 stopped receiving free security updates on October 14, 2025 unless enrolled in Extended Security Updates.` } };
    if (build && build < base.minimum_build) return { status: "below_minimum", issue: { id: "os_below_minimum", severity: "high", title: "Windows below required build", detail: `Build ${build}; your minimum is ${base.minimum_build}.` } };
    const latestUbr = base.latest_ubr_by_build[build] ?? 0;
    if (windowsUbr(version) < latestUbr) return { status: "update_available", issue: { id: "os_update_available", severity: "medium", title: "Windows cumulative update pending", detail: `Running ${version}; 10.0.${build}.${latestUbr} is ${base.published ? "Microsoft's latest security build for this release" : "already deployed elsewhere in the fleet"}.` } };
    if (build < base.latest_build) return { status: "older_release", issue: { id: "os_older_release", severity: "low", title: "Older Windows feature release", detail: `Build ${build}; build ${base.latest_build} is in use in the fleet.` } };
    return { status: "current", issue: null };
  }
  return { status: "unknown", issue: null };
}

export function appBaselines(devices, catalog = []) {
  const catalogByIdentity = new Map(catalog.map((entry) => [entry.identity, entry]));
  const catalogByName = new Map(catalog.map((entry) => [`${entry.platform}:${appKey(entry.name)}`, entry]));
  const groups = new Map();
  for (const device of devices) {
    for (const app of device.apps ?? []) {
      if (!app.version || (device.platform === "macos" && isMacSystemApp(app))) continue;
      const key = `${device.platform}:${appKey(app.name)}`;
      if (!groups.has(key)) groups.set(key, { key, name: app.name, platform: device.platform, versions: new Map(), bundle_id: app.bundle_id || "" });
      const group = groups.get(key);
      group.versions.set(app.version, (group.versions.get(app.version) ?? 0) + 1);
    }
  }
  const baselines = new Map();
  for (const group of groups.values()) {
    const identity = softwareIdentity(group.platform, { name: group.name, bundle_identifier: group.bundle_id, product_code: group.bundle_id });
    const catalogEntry = catalogByIdentity.get(identity) ?? catalogByName.get(group.key);
    const fleetNewest = newest([...group.versions.keys()]);
    baselines.set(group.key, {
      ...group,
      target_version: catalogEntry?.approved_version ?? fleetNewest,
      target_source: catalogEntry ? "approved_baseline" : "fleet_newest",
      catalog_severity: catalogEntry?.severity ?? null,
      watchlisted: isWatchlisted(appKey(group.name))
    });
  }
  return baselines;
}

function appFindings(device, baselines) {
  const behind = [];
  for (const app of device.apps ?? []) {
    if (!app.version) continue;
    const baseline = baselines.get(`${device.platform}:${appKey(app.name)}`);
    if (!baseline || app.version === baseline.target_version || compareVersions(app.version, baseline.target_version) >= 0) continue;
    const majorGap = majorOf(app.version) < majorOf(baseline.target_version);
    const severity = baseline.catalog_severity ?? (baseline.watchlisted ? (majorGap ? "high" : "medium") : "low");
    behind.push({ name: app.name, version: app.version, target_version: baseline.target_version, target_source: baseline.target_source, severity });
  }
  return behind.sort((left, right) => SEVERITY_WEIGHT[right.severity] - SEVERITY_WEIGHT[left.severity] || left.name.localeCompare(right.name));
}

export function mergeVulnerabilities(device, cveFeeds) {
  const fromVendor = Array.isArray(device.vulnerabilities) ? device.vulnerabilities : null;
  const fromFeeds = cveFeeds?.osCves?.(device) ?? null;
  if (!fromVendor && !fromFeeds) return null;
  const merged = new Map();
  for (const vuln of fromVendor ?? []) {
    const kev = cveFeeds?.kevFor?.(vuln.cve);
    merged.set(vuln.cve, { ...vuln, kev: vuln.kev || Boolean(kev), exploit: kev && !vuln.exploit ? "Actively used" : vuln.exploit, sources: [vuln.source ?? "crowdstrike"] });
  }
  for (const vuln of fromFeeds ?? []) {
    const existing = merged.get(vuln.cve);
    if (existing) {
      existing.sources.push(vuln.source);
      existing.fixed_in = existing.fixed_in ?? vuln.fixed_in;
      if (vuln.kev) existing.kev = true;
    } else {
      merged.set(vuln.cve, { ...vuln, sources: [vuln.source] });
    }
  }
  return [...merged.values()];
}

export function evaluateDevice(device, { baselines, apps, now = Date.now(), staleDays = 14, connected = {}, softwareRules = [], trackedPatches = [], cveFeeds = null }) {
  device = { ...device, vulnerabilities: mergeVulnerabilities(device, cveFeeds) };
  const issues = [];
  const add = (issue) => issues.push(issue);
  const ageDays = device.last_check_in ? (now - Date.parse(device.last_check_in)) / DAY : null;

  if (device.encrypted === false) add({ id: "not_encrypted", severity: "critical", title: device.platform === "macos" ? "FileVault is off" : "BitLocker is off", detail: "Disk is not encrypted. A lost or stolen device exposes all local data." });
  const os = osStatus(device, baselines);
  if (os.issue) add(os.issue);
  if (["noncompliant", "conflict", "error"].includes(device.compliance)) add({ id: "noncompliant", severity: "high", title: "Not compliant in Intune", detail: `Intune compliance state: ${device.compliance}.` });
  if (device.compliance === "ingraceperiod") add({ id: "compliance_grace", severity: "medium", title: "Intune compliance grace period", detail: "Device is failing a compliance policy and will be marked non-compliant when the grace period ends." });
  if (ageDays !== null && ageDays > staleDays * 2) add({ id: "stale", severity: "high", title: "Not checked in for a long time", detail: `Last check-in ${Math.floor(ageDays)} days ago. Posture data may be out of date and the device may be lost or retired.` });
  else if (ageDays !== null && ageDays > staleDays) add({ id: "stale", severity: "medium", title: "Overdue check-in", detail: `Last check-in ${Math.floor(ageDays)} days ago (threshold ${staleDays} days).` });
  if (device.security.sip === false) add({ id: "sip_disabled", severity: "high", title: "System Integrity Protection disabled", detail: "SIP protects core macOS files from modification, including by malware with admin rights." });
  if (device.security.gatekeeper === false) add({ id: "gatekeeper_disabled", severity: "medium", title: "Gatekeeper disabled", detail: "Unsigned or unnotarized apps can run without warning." });
  if (device.security.firewall === false) add({ id: "firewall_disabled", severity: "low", title: "macOS firewall off", detail: "The application firewall is not blocking unsolicited inbound connections." });
  if (device.security.jailbroken === true) add({ id: "jailbroken", severity: "critical", title: "Device reported as jailbroken", detail: "Intune reports this device as jailbroken or rooted." });
  if (device.platform === "macos" && connected.jamf && !device.sources.jamf) add({ id: "missing_mdm", severity: "high", title: "Mac not in Jamf", detail: "This Mac is not enrolled in Jamf Pro, so configuration profiles and security policies are not applied." });
  if (device.platform === "windows" && connected.intune && !device.sources.intune) add({ id: "missing_mdm", severity: "high", title: "PC not in Intune", detail: "This PC is not enrolled in Intune, so compliance and update policies are not applied." });
  const falconAge = device.sources.crowdstrike?.last_check_in ? (now - Date.parse(device.sources.crowdstrike.last_check_in)) / DAY : null;
  device.crowdstrike_reporting = falconAge !== null && falconAge <= 7;
  if (connected.crowdstrike && !device.sources.crowdstrike && ageDays !== null && ageDays <= 30) add({ id: "crowdstrike_missing", severity: "high", title: "Not in CrowdStrike", detail: "This device checked in elsewhere in the last 30 days but has no Falcon sensor record, so it has no EDR coverage." });
  if (device.sources.crowdstrike && falconAge > 7 && ageDays !== null && ageDays <= 7) add({ id: "crowdstrike_not_reporting", severity: "high", title: "CrowdStrike sensor not reporting", detail: `The device is active (last check-in ${Math.floor(ageDays)} days ago) but the Falcon sensor was last seen ${Math.floor(falconAge)} days ago.` });
  if (device.crowdstrike?.rfm) add({ id: "crowdstrike_rfm", severity: "high", title: "Falcon sensor in reduced functionality mode", detail: "The sensor is running with limited protection, often after an unsupported OS or kernel update." });
  if (device.crowdstrike?.contained) add({ id: "crowdstrike_contained", severity: "medium", title: "Host network-contained by CrowdStrike", detail: `Falcon status: ${device.crowdstrike.status}.` });
  if (device.sources.jamf && device.jamf_managed === false) add({ id: "jamf_unmanaged", severity: "medium", title: "Unmanaged in Jamf", detail: "The computer record exists in Jamf but remote management is not active." });
  if (device.platform === "macos" && connected.intune && connected.jamf && device.sources.jamf && !device.sources.intune) add({ id: "no_compliance_signal", severity: "low", title: "No Intune compliance signal", detail: "Mac is managed by Jamf but not registered with Intune, so Conditional Access cannot evaluate it." });

  const behindApps = appFindings(device, apps);
  if (behindApps.length) {
    const severity = maxSeverity(behindApps.map((app) => app.severity));
    add({ id: "apps_outdated", severity, title: `${behindApps.length} app${behindApps.length === 1 ? "" : "s"} behind`, detail: behindApps.slice(0, 4).map((app) => `${app.name} ${app.version} → ${app.target_version}`).join(", ") + (behindApps.length > 4 ? `, +${behindApps.length - 4} more` : "") });
  }

  device.crowdstrike_connected = Boolean(connected.crowdstrike);
  const software = softwareRules.map((rule) => ({ rule_id: rule.id, name: rule.name, kind: rule.kind ?? "software", mode: rule.mode, severity: rule.severity, detect_source: rule.detect_source ?? null, ...evaluateSoftwareRule(rule, device, now) }))
    .filter((entry) => entry.status !== "not_applicable");
  for (const entry of software) {
    if (entry.kind === "os" && entry.status === "missing") { add({ id: "os_rule", severity: entry.severity, title: `${entry.name}: OS doesn't meet the rule`, detail: `This device runs ${entry.match?.name ?? ""} ${entry.match?.version ?? ""}${device.os?.build ? ` (build ${device.os.build})` : ""}, which doesn't meet the “${entry.name}” OS rule.`.replace(/\s+/g, " ") }); continue; }
    if (entry.kind === "os") continue;
    if (entry.mode === "required" && entry.status === "missing") add({ id: "software_missing", severity: entry.severity, title: `${entry.name} missing`, detail: entry.detect_source === "crowdstrike" && !device.apps_source ? `${entry.name} is required but no Falcon sensor has reported for this device in the last 7 days.` : `${entry.name} is required on every ${device.platform === "macos" ? "Mac" : "Windows PC"} in scope but was not found in the installed applications${entry.detect_source === "crowdstrike" ? " and no Falcon sensor is reporting" : ""}.` });
    if (entry.mode === "prohibited" && entry.status === "installed") add({ id: "software_prohibited", severity: entry.severity, title: `${entry.name} still installed`, detail: `${entry.name} is scheduled for removal but is still installed (${entry.match?.name ?? ""} ${entry.match?.version ?? ""}).`.trim() });
  }
  const patches = trackedPatches.map((patch) => ({ kb: patch.kb, title: patch.title, severity: patch.severity, ...evaluateTrackedPatch(patch, device) }))
    .filter((entry) => entry.status !== "not_applicable");
  const missingPatches = patches.filter((entry) => entry.status === "missing");
  if (missingPatches.length) add({ id: "patches_missing", severity: maxSeverity(missingPatches.map((entry) => entry.severity)), title: `${missingPatches.length} tracked Windows update${missingPatches.length === 1 ? "" : "s"} missing`, detail: missingPatches.map((entry) => `${entry.kb}${entry.required_build ? ` (needs build ${entry.required_build})` : ""}`).join(", ") });

  // Open CVEs reported by CrowdStrike Spotlight.
  let vulnSummary = null;
  if (Array.isArray(device.vulnerabilities)) {
    const vulns = device.vulnerabilities;
    vulnSummary = {
      total: vulns.length,
      critical: vulns.filter((vuln) => vuln.severity === "critical").length,
      high: vulns.filter((vuln) => vuln.severity === "high").length,
      medium: vulns.filter((vuln) => vuln.severity === "medium").length,
      low: vulns.filter((vuln) => vuln.severity === "low").length,
      exploited: vulns.filter((vuln) => vuln.kev || vuln.exploit === "Actively used").length,
      max_score: vulns.reduce((max, vuln) => Math.max(max, vuln.score ?? 0), 0) || null
    };
    if (vulnSummary.exploited) add({ id: "cves", severity: "critical", title: `${vulnSummary.exploited} actively exploited CVE${vulnSummary.exploited === 1 ? "" : "s"}`, detail: `${vulns.filter((vuln) => vuln.kev || vuln.exploit === "Actively used").slice(0, 5).map((vuln) => `${vuln.cve}${vuln.product ? ` (${vuln.product})` : ""}`).join(", ")}. Listed by CISA KEV or marked actively used by CrowdStrike.` });
    else if (vulnSummary.critical) add({ id: "cves", severity: "high", title: `${vulnSummary.critical} critical CVE${vulnSummary.critical === 1 ? "" : "s"}`, detail: vulns.filter((vuln) => vuln.severity === "critical").slice(0, 5).map((vuln) => `${vuln.cve}${vuln.product ? ` (${vuln.product})` : ""}`).join(", ") });
    else if (vulnSummary.high) add({ id: "cves", severity: "medium", title: `${vulnSummary.high} high CVE${vulnSummary.high === 1 ? "" : "s"}`, detail: vulns.filter((vuln) => vuln.severity === "high").slice(0, 5).map((vuln) => vuln.cve).join(", ") });
    // KBs Spotlight recommends become missing patches too, so KB queries cover them.
    const tracked = new Set(patches.map((patch) => patch.kb));
    const fromSpotlight = new Map();
    for (const vuln of vulns) for (const kb of vuln.kbs ?? []) {
      if (tracked.has(kb)) continue;
      const entry = fromSpotlight.get(kb) ?? { kb, title: "", severity: "low", status: "missing", method: "spotlight", cves: [] };
      entry.cves.push(vuln.cve);
      if (SEVERITY_WEIGHT[vuln.severity] > SEVERITY_WEIGHT[entry.severity]) entry.severity = vuln.severity;
      fromSpotlight.set(kb, entry);
    }
    for (const entry of fromSpotlight.values()) patches.push({ ...entry, title: `Fixes ${entry.cves.slice(0, 3).join(", ")}${entry.cves.length > 3 ? ` +${entry.cves.length - 3}` : ""}` });
  }

  for (const issue of issues) issue.key = ["apps_outdated", "stale", "patches_missing", "cves"].includes(issue.id) ? issue.id : `${issue.id}:${issue.title}`;
  issues.sort((left, right) => SEVERITY_WEIGHT[right.severity] - SEVERITY_WEIGHT[left.severity]);
  const riskScore = Math.min(100, issues.reduce((sum, issue) => sum + SEVERITY_WEIGHT[issue.severity], 0));
  return {
    ...device,
    os_status: os.status,
    check_in_age_days: ageDays === null ? null : Math.round(ageDays * 10) / 10,
    issues,
    apps_behind: behindApps,
    software,
    patches,
    vuln_summary: vulnSummary,
    risk_score: riskScore,
    risk_level: maxSeverity(issues.map((issue) => issue.severity)) ?? "healthy"
  };
}

export function computePosture(records, { userGroups = {}, catalog = [], now = Date.now(), staleDays = 14, osSettings = {}, connected = {}, softwareRules = [], trackedPatches = [], cveFeeds = null } = {}) {
  const merged = mergeRecords(records).filter((device) => device.platform === "macos" || device.platform === "windows");
  for (const device of merged) {
    const email = String(device.user?.email ?? "").toLowerCase();
    device.user_groups = email ? (typeof userGroups === "function" ? userGroups(email) : userGroups[email] ?? []) : [];
  }
  const baselines = osBaselines(merged, osSettings);
  const apps = appBaselines(merged, catalog);
  const devices = merged.map((device) => evaluateDevice(device, { baselines, apps, now, staleDays, connected, softwareRules, trackedPatches, cveFeeds }))
    .sort((left, right) => right.risk_score - left.risk_score || left.hostname.localeCompare(right.hostname));

  const total = devices.length;
  const encryptionKnown = devices.filter((device) => device.encrypted !== null && device.encrypted !== undefined);
  const complianceKnown = devices.filter((device) => device.compliance && device.compliance !== "unknown");
  const osKnown = devices.filter((device) => device.os_status !== "unknown");
  const inventoried = devices.filter((device) => device.apps_source);
  const checkedIn7 = devices.filter((device) => device.check_in_age_days !== null && device.check_in_age_days <= 7);
  const healthy = devices.filter((device) => !device.issues.some((issue) => issue.severity === "critical" || issue.severity === "high"));
  const score = total ? Math.round(devices.reduce((sum, device) => sum + (100 - device.risk_score), 0) / total) : null;

  const issueTypes = new Map();
  for (const device of devices) {
    for (const issue of device.issues) {
      const key = issue.key;
      if (!issueTypes.has(key)) issueTypes.set(key, { id: key, title: { apps_outdated: "Outdated applications", stale: "Stale check-ins", patches_missing: "Missing tracked Windows updates", cves: "Open CVEs (CrowdStrike Spotlight)" }[issue.id] ?? issue.title, severity: issue.severity, count: 0, platforms: { macos: 0, windows: 0 } });
      const entry = issueTypes.get(key);
      entry.count += 1;
      entry.platforms[device.platform] += 1;
      if (SEVERITY_WEIGHT[issue.severity] > SEVERITY_WEIGHT[entry.severity]) entry.severity = issue.severity;
    }
  }
  const topRisks = [...issueTypes.values()].sort((left, right) => SEVERITY_WEIGHT[right.severity] * right.count - SEVERITY_WEIGHT[left.severity] * left.count);

  const osDistribution = {};
  for (const platform of ["macos", "windows"]) {
    const counts = new Map();
    for (const device of devices.filter((item) => item.platform === platform)) {
      const label = device.os.version || "Unknown";
      const current = counts.get(label) ?? { version: label, name: device.os.name, count: 0, status: device.os_status };
      current.count += 1;
      counts.set(label, current);
    }
    osDistribution[platform] = [...counts.values()].sort((left, right) => compareVersions(right.version, left.version));
  }

  const appSummary = [...apps.values()].map((baseline) => {
    const installs = [...baseline.versions.values()].reduce((sum, count) => sum + count, 0);
    const behindDevices = devices.filter((device) => device.platform === baseline.platform && device.apps_behind.some((app) => appKey(app.name) === appKey(baseline.name)));
    const severity = maxSeverity(behindDevices.flatMap((device) => device.apps_behind.filter((app) => appKey(app.name) === appKey(baseline.name)).map((app) => app.severity))) ?? "none";
    return {
      name: baseline.name,
      platform: baseline.platform,
      installs,
      behind: behindDevices.length,
      current_pct: pct(installs - behindDevices.length, installs),
      target_version: baseline.target_version,
      target_source: baseline.target_source,
      watchlisted: baseline.watchlisted,
      severity,
      versions: [...baseline.versions.entries()].map(([version, count]) => ({ version, count })).sort((left, right) => compareVersions(right.version, left.version))
    };
  }).sort((left, right) => (SEVERITY_WEIGHT[right.severity] ?? 0) * right.behind - (SEVERITY_WEIGHT[left.severity] ?? 0) * left.behind || right.installs - left.installs);

  const count = (predicate) => devices.filter(predicate).length;
  return {
    generated_at: new Date(now).toISOString(),
    summary: {
      score,
      devices: total,
      macos: count((device) => device.platform === "macos"),
      windows: count((device) => device.platform === "windows"),
      healthy_pct: pct(healthy.length, total),
      encrypted_pct: pct(encryptionKnown.filter((device) => device.encrypted).length, encryptionKnown.length),
      compliant_pct: pct(complianceKnown.filter((device) => device.compliance === "compliant").length, complianceKnown.length),
      os_current_pct: pct(osKnown.filter((device) => device.os_status === "current").length, osKnown.length),
      checked_in_7d_pct: pct(checkedIn7.length, total),
      apps_current_pct: pct(inventoried.filter((device) => !device.apps_behind.length).length, inventoried.length),
      by_risk: Object.fromEntries(["critical", "high", "medium", "low", "healthy"].map((level) => [level, count((device) => device.risk_level === level)]))
    },
    coverage: {
      in_jamf: count((device) => device.sources.jamf),
      in_intune: count((device) => device.sources.intune),
      with_agent: count((device) => device.sources.agent),
      in_crowdstrike: count((device) => device.sources.crowdstrike),
      crowdstrike_reporting: count((device) => device.crowdstrike_reporting),
      jamf_and_intune: count((device) => device.sources.jamf && device.sources.intune),
      macs_missing_jamf: count((device) => device.platform === "macos" && !device.sources.jamf),
      pcs_missing_intune: count((device) => device.platform === "windows" && !device.sources.intune),
      without_agent: count((device) => !device.sources.agent),
      app_inventory: count((device) => device.apps_source)
    },
    baselines: { macos: { latest: baselines.macos.latest, minimum: baselines.macos.minimum }, windows: { latest: baselines.windows.latest, minimum_build: baselines.windows.minimum_build } },
    top_risks: topRisks,
    software: softwareRules.map((rule) => {
      const tally = { macos: { installed: 0, missing: 0, unknown: 0 }, windows: { installed: 0, missing: 0, unknown: 0 } };
      for (const device of devices) {
        const entry = device.software.find((item) => item.rule_id === rule.id);
        if (entry && tally[device.platform]) tally[device.platform][entry.status] += 1;
      }
      return { ...rule, tally };
    }),
    patches: trackedPatches.map((patch) => {
      const tally = { installed: 0, missing: 0, unknown: 0, reported: 0 };
      for (const device of devices) {
        const entry = device.patches.find((item) => item.kb === patch.kb);
        if (!entry) continue;
        tally[entry.status] += 1;
        if (entry.method === "reported") tally.reported += 1;
      }
      return { ...patch, tally };
    }),
    kb_reporting: { devices: count((device) => Array.isArray(device.reported_kbs)) },
    vulnerabilities: aggregateVulnerabilities(devices),
    os: osDistribution,
    apps: appSummary,
    devices
  };
}

export function aggregateVulnerabilities(devices) {
  const byCve = new Map();
  let reporting = 0;
  for (const device of devices) {
    if (!Array.isArray(device.vulnerabilities)) continue;
    reporting += 1;
    for (const vuln of device.vulnerabilities) {
      const entry = byCve.get(vuln.cve) ?? { cve: vuln.cve, severity: vuln.severity, score: vuln.score, exprt: vuln.exprt, exploit: vuln.exploit, kev: vuln.kev, description: vuln.description, url: vuln.url ?? null, products: new Set(), remediation: new Set(), kbs: new Set(), sources: new Set(), devices: 0, platforms: { macos: 0, windows: 0 }, first_seen: vuln.first_seen };
      for (const source of vuln.sources ?? [vuln.source ?? "crowdstrike"]) entry.sources.add(source);
      if (!entry.exploit && vuln.exploit) entry.exploit = vuln.exploit;
      if (!entry.description && vuln.description) entry.description = vuln.description;
      entry.devices += 1;
      entry.platforms[device.platform] = (entry.platforms[device.platform] ?? 0) + 1;
      if (vuln.product) entry.products.add(vuln.product);
      for (const item of vuln.remediation ?? []) entry.remediation.add(item);
      for (const kb of vuln.kbs ?? []) entry.kbs.add(kb);
      if (vuln.kev) entry.kev = true;
      if ((vuln.score ?? 0) > (entry.score ?? 0)) entry.score = vuln.score;
      if (SEVERITY_WEIGHT[vuln.severity] > SEVERITY_WEIGHT[entry.severity]) entry.severity = vuln.severity;
      if (vuln.first_seen && (!entry.first_seen || vuln.first_seen < entry.first_seen)) entry.first_seen = vuln.first_seen;
      byCve.set(vuln.cve, entry);
    }
  }
  const list = [...byCve.values()].map((entry) => ({ ...entry, products: [...entry.products].slice(0, 6), remediation: [...entry.remediation].slice(0, 3), kbs: [...entry.kbs], sources: [...entry.sources] }))
    .sort((left, right) => Number(right.kev || right.exploit === "Actively used") - Number(left.kev || left.exploit === "Actively used") || SEVERITY_WEIGHT[right.severity] - SEVERITY_WEIGHT[left.severity] || right.devices - left.devices || (right.score ?? 0) - (left.score ?? 0));
  return { devices_reporting: reporting, unique: list.length, total: list.reduce((sum, entry) => sum + entry.devices, 0), list };
}

// What the device list needs: full app, CVE and raw details are only sent when a
// single device is opened, which keeps the list small for large fleets.
export function deviceListItem(device) {
  const { apps: _apps, raw: _raw, vulnerabilities: _vulnerabilities, apps_behind: appsBehind, extension_attributes: _attributes, patches, ...rest } = device;
  return {
    ...rest,
    issues: (device.issues ?? []).map(({ id, key, title, severity }) => ({ id, key, title, severity })),
    app_count: device.apps?.length ?? 0,
    apps_behind_count: appsBehind?.length ?? 0,
    apps_behind_names: [...new Set((appsBehind ?? []).map((app) => app.name))],
    patches_missing: (patches ?? []).filter((patch) => patch.status === "missing").length
  };
}
