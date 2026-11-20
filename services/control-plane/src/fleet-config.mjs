// Administrator-defined fleet rules: required / prohibited software, tracked
// Windows updates (KBs) and saved dashboards. Everything here is validated so the
// dashboard can't store malformed rules.

import { randomUUID } from "node:crypto";

const text = (value, max = 160) => String(value ?? "").trim().slice(0, max);
const list = (value, max = 12) => (Array.isArray(value) ? value : String(value ?? "").split(","))
  .map((item) => text(item, 120)).filter(Boolean).slice(0, max);
const SEVERITIES = ["critical", "high", "medium", "low"];

// ---- Required / prohibited software -------------------------------------------------

export const DEFAULT_SOFTWARE_RULES = [
  { id: "rule_crowdstrike", name: "CrowdStrike Falcon", mode: "required", severity: "critical", macos: ["Falcon"], windows: ["CrowdStrike Windows Sensor", "CrowdStrike Falcon"] },
  { id: "rule_beyondtrust", name: "BeyondTrust EPM", mode: "required", severity: "high", macos: ["PrivilegeManagement", "Privilege Management", "BeyondTrust"], windows: ["BeyondTrust Privilege Management", "Privilege Management for Windows", "Avecto"] },
  { id: "rule_okta_verify", name: "Okta Verify", mode: "required", severity: "high", macos: ["Okta Verify"], windows: ["Okta Verify"] },
  { id: "rule_tenable", name: "Tenable Nessus Agent", mode: "prohibited", severity: "medium", macos: ["Nessus Agent", "Tenable"], windows: ["Nessus Agent", "Tenable"] },
  { id: "rule_cyberark", name: "CyberArk EPM", mode: "prohibited", severity: "medium", macos: ["CyberArk"], windows: ["CyberArk"] }
];

export function sanitizeSoftwareRule(input) {
  const name = text(input?.name, 80);
  const macos = list(input?.macos);
  const windows = list(input?.windows);
  if (!name || (!macos.length && !windows.length)) return null;
  return {
    id: /^rule_[\w-]{3,60}$/.test(input?.id ?? "") ? input.id : `rule_${randomUUID().slice(0, 12)}`,
    name,
    mode: input?.mode === "prohibited" ? "prohibited" : "required",
    severity: SEVERITIES.includes(input?.severity) ? input.severity : input?.mode === "prohibited" ? "medium" : "high",
    macos,
    windows
  };
}

// Returns installed / missing / unknown (no app inventory) / not_applicable.
export function evaluateSoftwareRule(rule, device) {
  const patterns = (rule[device.platform] ?? []).map((pattern) => pattern.toLowerCase());
  if (!patterns.length) return { status: "not_applicable", match: null };
  if (!device.apps_source) return { status: "unknown", match: null };
  const match = (device.apps ?? []).find((app) => patterns.some((pattern) => String(app.name ?? "").toLowerCase().includes(pattern) || String(app.bundle_id ?? "").toLowerCase().includes(pattern)));
  return { status: match ? "installed" : "missing", match: match ? { name: match.name, version: match.version } : null };
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
  const platforms = [["windows", "Windows", rule.windows?.length], ["macos", "MacOS", rule.macos?.length]].filter(([, , has]) => has);
  return {
    title: `${rule.name} Deployment`,
    type: "donut",
    series: [
      ...platforms.map(([key, label]) => ({ label: `${label} - Installed`, tone: "good", query: `${base(key)} f/ Status = installed )` })),
      ...platforms.map(([key, label]) => ({ label: `${label} - Missing`, tone: "bad", query: `${base(key)} f/ Status = missing )` }))
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
