// Administrator-defined fleet rules: required / prohibited software, tracked
// Windows updates (KBs) and saved dashboards. Everything here is validated so the
// dashboard can't store malformed rules.

import { randomUUID } from "node:crypto";
import { QueryError, describeQuery, matchesClause, parseEntityClause, parseQuery, runQuery } from "./fleet-query.mjs";

const text = (value, max = 160) => String(value ?? "").trim().slice(0, max);
const list = (value, max = 12) => (Array.isArray(value) ? value : String(value ?? "").split(","))
  .map((item) => text(item, 120)).filter(Boolean).slice(0, max);
const SEVERITIES = ["critical", "high", "medium", "low"];

// ---- Required / prohibited software -------------------------------------------------

export const DEFAULT_SOFTWARE_RULES = [
  { id: "rule_crowdstrike", name: "CrowdStrike Falcon", mode: "required", severity: "critical", detect_source: "crowdstrike", macos: ["Falcon"], windows: ["CrowdStrike Windows Sensor", "CrowdStrike Falcon"] },
  { id: "rule_beyondtrust", name: "BeyondTrust EPM", mode: "required", severity: "high", macos: ["PrivilegeManagement", "Privilege Management", "BeyondTrust"], windows: ["BeyondTrust Privilege Management", "Privilege Management for Windows", "Avecto"] },
  { id: "rule_okta_verify", name: "Okta Verify", mode: "required", severity: "high", macos: ["Okta Verify"], windows: ["Okta Verify"] },
  { id: "rule_tenable", name: "Tenable Nessus Agent", mode: "prohibited", severity: "medium", macos: ["Nessus Agent", "Tenable"], windows: ["Nessus Agent", "Tenable"] },
  { id: "rule_cyberark", name: "CyberArk EPM", mode: "prohibited", severity: "medium", macos: ["CyberArk"], windows: ["CyberArk"] }
].map((rule) => sanitizeSoftwareRule(rule));

function escapeQuoted(value) { return String(value).replace(/["\u201c\u201d]/g, "").trim(); }

// Older rules stored plain name patterns; they become an equivalent condition
// ("name contains A" OR "bundle ID contains A" OR "name contains B" …).
export function patternsToCondition(patterns) {
  const list = (patterns ?? []).map(escapeQuoted).filter(Boolean);
  if (!list.length) return null;
  // Bundle IDs (com.vendor.app) are matched on the bundle ID, anything else on the app name.
  const term = (pattern) => (/^[a-z0-9-]+(\.[a-z0-9-]+){2,}$/i.test(pattern) && !/\s/.test(pattern) ? `f/ BundleId contains "${pattern}"` : `f/ Name contains "${pattern}"`);
  return list.length === 1 ? `e/ Software ${term(list[0])}` : `e/ Software ${list.map((pattern) => `( ${term(pattern)} )`).join(" OR ")}`;
}

function validCondition(source, entity, label) {
  const text = text_(source);
  if (!text) return null;
  try {
    if (entity === "Device") {
      const parsed = parseQuery(text);
      if (/SoftwareRule/i.test(text)) throw new QueryError("can't refer to software rules");
      return parsed && text;
    }
    parseEntityClause(text, entity);
    return text;
  } catch (error) {
    throw new QueryError(`${label}: ${error.message}`);
  }
}
function text_(value) { return String(value ?? "").trim().slice(0, 4000); }

export function sanitizeSoftwareRule(input) {
  const name = text(input?.name, 80);
  if (!name) return null;
  if (input?.kind === "os") {
    // OS rules: each platform has a device condition (e.g. OSBuild >= 26100); matching devices are compliant.
    const detect = {
      macos: input?.detect?.macos ? validCondition(input.detect.macos, "Device", "Mac requirement") : null,
      windows: input?.detect?.windows ? validCondition(input.detect.windows, "Device", "Windows requirement") : null
    };
    if (!detect.macos && !detect.windows) return null;
    return {
      id: /^rule_[\w-]{3,60}$/.test(input?.id ?? "") ? input.id : `rule_${randomUUID().slice(0, 12)}`,
      kind: "os", name, mode: "required",
      severity: SEVERITIES.includes(input?.severity) ? input.severity : "high",
      scope: input?.scope ? validCondition(input.scope, "Device", "Applies to") : null,
      detect, detect_source: null,
      platforms: { macos: Boolean(detect.macos), windows: Boolean(detect.windows) }
    };
  }
  const legacy = { macos: list(input?.macos), windows: list(input?.windows) };
  const detect = {
    macos: input?.detect?.macos !== undefined ? validCondition(input.detect.macos, "App", "Mac detection") : patternsToCondition(legacy.macos),
    windows: input?.detect?.windows !== undefined ? validCondition(input.detect.windows, "App", "Windows detection") : patternsToCondition(legacy.windows)
  };
  // Rules about CrowdStrike are satisfied by a reporting Falcon sensor (from the CrowdStrike API),
  // which is more reliable than app names.
  const detectSource = input?.detect_source === undefined ? (/crowdstrike|falcon/i.test(name) && (input?.mode ?? "required") === "required" ? "crowdstrike" : null) : input.detect_source === "crowdstrike" ? "crowdstrike" : null;
  if (!detect.macos && !detect.windows && !detectSource) return null;
  return {
    id: /^rule_[\w-]{3,60}$/.test(input?.id ?? "") ? input.id : `rule_${randomUUID().slice(0, 12)}`,
    kind: "software",
    name,
    mode: input?.mode === "prohibited" ? "prohibited" : "required",
    severity: SEVERITIES.includes(input?.severity) ? input.severity : input?.mode === "prohibited" ? "medium" : "high",
    scope: input?.scope ? validCondition(input.scope, "Device", "Applies to") : null,
    detect,
    detect_source: detectSource,
    platforms: { macos: Boolean(detect.macos || detectSource), windows: Boolean(detect.windows || detectSource) }
  };
}

// Plain-English text for the rules table, e.g. "software whose name contains “Okta Verify”".
export function describeRule(rule) {
  const detect = (condition) => {
    if (!condition) return null;
    if (rule.kind === "os") return (describeQuery(condition) ?? condition).replace(/^Devices, /, "").replace(/^(Windows|macOS) devices, /, "").replace(/\.$/, "");
    const text = describeQuery(`e/ Device r/ ( ${condition} )`);
    if (!text) return condition;
    return text.replace(/^Devices, with /, "").replace(/\.$/, "")
      .replace(/whose name contains (“[^”]+”) or whose bundle ID contains \1/g, "named like $1")
      .replace(/^software \(named like (“[^”]+”(?: or named like “[^”]+”)*)\)$/, (_, list) => `software named like ${list.replace(/ or named like /g, " or ")}`);
  };
  return {
    scope_text: rule.scope ? (describeQuery(rule.scope) ?? rule.scope).replace(/\.$/, "") : null,
    detect_text: { macos: detect(rule.detect?.macos), windows: detect(rule.detect?.windows) }
  };
}

const compiled = new Map();
function compileRule(rule) {
  const key = JSON.stringify([rule.kind, rule.scope, rule.detect, rule.detect_source, rule.macos, rule.windows]);
  if (compiled.has(key)) return compiled.get(key);
  const detect = rule.detect ?? { macos: patternsToCondition(rule.macos), windows: patternsToCondition(rule.windows) };
  const result = {
    scope: rule.scope ? parseQuery(rule.scope) : null,
    detect: rule.kind === "os"
      ? { macos: detect.macos ? parseQuery(detect.macos) : null, windows: detect.windows ? parseQuery(detect.windows) : null }
      : { macos: detect.macos ? parseEntityClause(detect.macos, "App") : null, windows: detect.windows ? parseEntityClause(detect.windows, "App") : null }
  };
  if (compiled.size > 500) compiled.clear();
  compiled.set(key, result);
  return result;
}

// Returns installed / missing / unknown (no data to decide) / not_applicable.
export function evaluateSoftwareRule(rule, device, now = Date.now()) {
  const { scope, detect } = compileRule(rule);
  if (scope && !runQuery(scope, [device], { now }).length) return { status: "not_applicable", match: null };
  const condition = detect[device.platform];
  if (rule.kind === "os") {
    if (!condition) return { status: "not_applicable", match: null };
    if (!device.os?.version) return { status: "unknown", match: null };
    const match = { name: device.os.name ?? (device.platform === "macos" ? "macOS" : "Windows"), version: device.os.version };
    return { status: runQuery(condition, [device], { now }).length ? "installed" : "missing", match };
  }
  const sensor = rule.detect_source === "crowdstrike";
  if (!condition && !sensor) return { status: "not_applicable", match: null };
  if (sensor && device.crowdstrike_reporting) return { status: "installed", match: { name: "Falcon sensor (reporting to CrowdStrike)", version: device.crowdstrike?.version ?? "" } };
  if (condition && device.apps_source) {
    const match = (device.apps ?? []).find((app) => matchesClause(app, condition, now));
    if (match) return { status: "installed", match: { name: match.name, version: match.version } };
    return { status: "missing", match: null };
  }
  if (sensor && device.crowdstrike_connected) return { status: "missing", match: null };
  return { status: "unknown", match: null };
}

// ---- Tracked Windows updates ------------------------------------------------------------

// builds: "26100.7171" means: on feature build 26100 the update is present from UBR 7171.
export function sanitizeTrackedPatch(input) {
  const kb = text(input?.kb, 20).toUpperCase().replace(/^(\d)/, "KB$1");
  if (!/^KB\d{6,8}$/.test(kb)) return null;
  const builds = list(input?.builds, 8)
    .map((build) => build.replace(/^10\.0\./, ""))
    .filter((build) => /^\d{5}\.\d{1,6}$/.test(build));
  return { kb, title: text(input?.title, 120), builds, severity: SEVERITIES.includes(input?.severity) ? input.severity : "high", released: /^\d{4}-\d{2}-\d{2}$/.test(input?.released ?? "") ? input.released : "" };
}

const windowsParts = (version) => {
  const [, , build, ubr] = String(version ?? "").split(".").map(Number);
  return { build: build || 0, ubr: ubr || 0 };
};

// Monthly Windows cumulative updates are cumulative: a device whose build revision (UBR)
// is at or above the revision a KB produces has that KB's fixes, even if a newer KB
// replaced it. Exact KB lists reported by the Intune Remediation script are used too.
export function evaluateTrackedPatch(patch, device) {
  if (device.platform !== "windows") return { status: "not_applicable", method: null };
  const reported = Array.isArray(device.reported_kbs) ? device.reported_kbs : null;
  if (reported?.includes(patch.kb)) return { status: "installed", method: "reported" };
  const { build, ubr } = windowsParts(device.os?.version);
  const target = patch.builds.map((entry) => entry.split(".").map(Number)).find(([featureBuild]) => featureBuild === build);
  if (target) return ubr >= target[1] ? { status: "installed", method: "build" } : { status: "missing", method: "build", required_build: `${target[0]}.${target[1]}` };
  if (!patch.builds.length) return reported ? { status: "missing", method: "reported" } : { status: "unknown", method: null };
  return { status: "not_applicable", method: null };
}

// ---- Dashboards ---------------------------------------------------------------------------

export const WIDGET_TYPES = ["donut", "breakdown", "trend", "number", "table"];
const TONES = ["good", "bad", "warn", "neutral"];

export function sanitizeDashboard(input) {
  const name = text(input?.name, 80);
  if (!name) return null;
  const widgets = (Array.isArray(input?.widgets) ? input.widgets : []).slice(0, 40).map((widget) => {
    const type = WIDGET_TYPES.includes(widget?.type) ? widget.type : "donut";
    const series = (Array.isArray(widget?.series) ? widget.series : []).slice(0, 8)
      .map((item) => ({ label: text(item?.label, 60), query: text(item?.query, 2000), tone: TONES.includes(item?.tone) ? item.tone : "neutral" }))
      .filter((item) => item.query);
    if (!series.length) return null;
    return {
      id: /^w_[\w-]{3,40}$/.test(widget?.id ?? "") ? widget.id : `w_${randomUUID().slice(0, 10)}`,
      title: text(widget?.title, 80) || series[0].label || "Untitled widget",
      type,
      group_by: type === "breakdown" ? text(widget?.group_by, 40) || "Platform" : undefined,
      size: widget?.size === "wide" ? "wide" : "normal",
      series: series.map((item, index) => ({ ...item, label: item.label || `Series ${index + 1}` }))
    };
  }).filter(Boolean);
  return { id: /^dash_[\w-]{3,40}$/.test(input?.id ?? "") ? input.id : `dash_${randomUUID().slice(0, 10)}`, name, widgets };
}

const quote = (value) => (/[\s,()]/.test(value) ? `"${value}"` : value);

export function coverageWidget(rule) {
  const base = (platform) => `e/ Device f/ Platform = ${platform} f/ LastSeenAt < 30d r/ ( e/ SoftwareRule f/ Name = ${quote(rule.name)}`;
  if (rule.mode === "prohibited") {
    return {
      title: `${rule.name} - Removal progress`,
      type: "trend",
      series: [{ label: `Devices with ${rule.name}`, tone: "bad", query: `e/ Device f/ LastSeenAt < 30d r/ ( e/ SoftwareRule f/ Name = ${quote(rule.name)} f/ Status = installed )` }]
    };
  }
  const has = (key) => (rule.platforms ? rule.platforms[key] : rule[key]?.length);
  const platforms = [["windows", "Windows"], ["macos", "macOS"]].filter(([key]) => has(key));
  return {
    title: rule.kind === "os" ? `${rule.name} Compliance` : `${rule.name} Deployment`,
    type: "donut",
    series: [
      ...platforms.map(([key, label]) => ({ label: `${label} - ${rule.kind === "os" ? "Compliant" : "Installed"}`, tone: "good", query: `${base(key)} f/ Status = installed )` })),
      ...platforms.map(([key, label]) => ({ label: `${label} - ${rule.kind === "os" ? "Not compliant" : "Missing"}`, tone: "bad", query: `${base(key)} f/ Status = missing )` })),
      ...platforms.map(([key, label]) => ({ label: `${label} - No data`, tone: "neutral", query: `${base(key)} f/ Status = unknown )` }))
    ]
  };
}

export function defaultDashboards(rules) {
  return [
    sanitizeDashboard({ id: "dash_security_agents", name: "IT - Security Agents Status", widgets: rules.map(coverageWidget) }),
    sanitizeDashboard({
      id: "dash_windows_patching",
      name: "Windows Patch Rollout",
      widgets: [
        { title: "Windows patch status (seen < 7d)", type: "donut", series: [
          { label: "Win 11 - All tracked updates", tone: "good", query: "e/ Device f/ Platform = windows f/ OSRelease = 11 f/ LastSeenAt < 7d not r/ ( e/ MissingPatch )" },
          { label: "Win 11 - Missing an update", tone: "bad", query: "e/ Device f/ Platform = windows f/ OSRelease = 11 f/ LastSeenAt < 7d r/ ( e/ MissingPatch )" },
          { label: "Win 10 - Out of support", tone: "warn", query: "e/ Device f/ Platform = windows f/ OSRelease = 10 f/ LastSeenAt < 7d" }
        ] },
        { title: "Missing tracked updates over time", type: "trend", series: [{ label: "Windows devices missing a tracked update", tone: "bad", query: "e/ Device f/ Platform = windows f/ LastSeenAt < 7d r/ ( e/ MissingPatch )" }] },
        { title: "Windows by release", type: "breakdown", group_by: "OSRelease", series: [{ label: "Windows seen < 7d", tone: "neutral", query: "e/ Device f/ Platform = windows f/ LastSeenAt < 7d" }] },
        { title: "Windows 10 still in use", type: "table", size: "wide", series: [{ label: "Windows 10 devices", tone: "bad", query: "e/ Device f/ Platform = windows f/ OSRelease = 10" }] }
      ]
    }),
    sanitizeDashboard({
      id: "dash_device_health",
      name: "Device Health",
      widgets: [
        { title: "Disk encryption", type: "donut", series: [
          { label: "Windows - Encrypted", tone: "good", query: "e/ Device f/ Platform = windows f/ Encrypted = true" },
          { label: "MacOS - Encrypted", tone: "good", query: "e/ Device f/ Platform = macos f/ Encrypted = true" },
          { label: "Windows - Not encrypted", tone: "bad", query: "e/ Device f/ Platform = windows f/ Encrypted = false" },
          { label: "MacOS - Not encrypted", tone: "bad", query: "e/ Device f/ Platform = macos f/ Encrypted = false" }
        ] },
        { title: "Devices not checking in (> 14 days)", type: "trend", series: [{ label: "Stale devices", tone: "bad", query: "e/ Device f/ LastSeenAt > 14d" }] },
        { title: "Devices by risk level", type: "breakdown", group_by: "RiskLevel", series: [{ label: "All devices", tone: "neutral", query: "e/ Device" }] }
      ]
    })
  ];
}
