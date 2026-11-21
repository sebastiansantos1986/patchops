// Orchestrates read-only syncs from Intune and Jamf, merges in PatchOps agent
// inventory, caches the result and records a once-a-day score history.

import { IntuneConnector, intuneConfig } from "./integrations/intune.mjs";
import { JamfConnector, jamfConfig } from "./integrations/jamf.mjs";
import { CrowdStrikeConnector, crowdstrikeConfig } from "./integrations/crowdstrike.mjs";
import { SAMPLE_TRACKED_PATCHES, sampleFleet } from "./integrations/sample-fleet.mjs";
import { DEFAULT_SOFTWARE_RULES, coverageWidget, defaultDashboards, describeRule, evaluateSoftwareRule, sanitizeDashboard, sanitizeSoftwareRule, sanitizeTrackedPatch } from "./fleet-config.mjs";
import { QueryError, describeQuery, groupValue, parseQuery, queryReference, referencedGroups, runQuery } from "./fleet-query.mjs";

// Demo data: every sample user is in one country group, and some are in Engineering.
const SAMPLE_GROUPS = ["GRP-Intune-Users-France-Finland", "GRP-Intune-Users-Germany", "GRP-Intune-Users-United-States", "GRP-Intune-Users-Spain"];
function SAMPLE_USER_GROUPS(email) {
  let hash = 0;
  for (const char of email) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return [SAMPLE_GROUPS[hash % SAMPLE_GROUPS.length], ...(hash % 5 === 0 ? ["GRP-Engineering"] : [])];
}
import { computePosture, deviceListItem } from "./posture-engine.mjs";
import { redact } from "./integrations/inspect.mjs";
import { CveFeeds } from "./integrations/cve-feeds.mjs";

export const CROWDSTRIKE_SYNC_WIDGET = {
  title: "Devices Not Syncing CrowdStrike",
  type: "donut",
  series: [
    { label: "Windows with CrowdStrike", tone: "good", query: "e/ Device f/ Platform = windows f/ LastSeenAt < 7d f/ CrowdStrikeReporting = true" },
    { label: "MacOS with CrowdStrike", tone: "good", query: "e/ Device f/ Platform = macos f/ LastSeenAt < 7d f/ CrowdStrikeReporting = true" },
    { label: "Windows without CrowdStrike", tone: "bad", query: "e/ Device f/ Platform = windows f/ LastSeenAt < 7d f/ CrowdStrikeReporting = false" },
    { label: "MacOS without CrowdStrike", tone: "bad", query: "e/ Device f/ Platform = macos f/ LastSeenAt < 7d f/ CrowdStrikeReporting = false" }
  ]
};
export const CROWDSTRIKE_TREND_WIDGET = {
  title: "Active devices without a reporting Falcon sensor",
  type: "trend",
  series: [{ label: "Devices without CrowdStrike", tone: "bad", query: "e/ Device f/ LastSeenAt < 7d f/ CrowdStrikeReporting = false" }]
};

function sampleCapabilities(key, posture) {
  const raw = posture.devices.map((device) => device.raw?.[key]).filter(Boolean);
  if (!raw.length) return {};
  const fields = new Map();
  for (const record of raw) for (const [field, value] of Object.entries(record)) if (value !== null && value !== "" && value !== undefined) fields.set(field, { count: (fields.get(field)?.count ?? 0) + 1, example: fields.get(field)?.example ?? (typeof value === "object" ? null : String(value).slice(0, 80)) });
  return { sample: { label: "Sample records", scope: "", state: "sample", count: raw.length, error: null, synced_at: posture.generated_at, fields: [...fields.entries()].map(([field, info]) => ({ field, filled: info.count, pct: Math.round((info.count / raw.length) * 1000) / 10, example: info.example })), samples: raw.slice(0, 2) } };
}

export const CVE_WIDGETS = [
  { title: "Devices with critical CVEs", type: "donut", series: [
    { label: "Windows - Actively exploited", tone: "bad", query: "e/ Device f/ Platform = windows f/ ExploitedCVEs > 0" },
    { label: "MacOS - Actively exploited", tone: "bad", query: "e/ Device f/ Platform = macos f/ ExploitedCVEs > 0" },
    { label: "Windows - Critical CVEs", tone: "warn", query: "e/ Device f/ Platform = windows f/ ExploitedCVEs = 0 f/ CriticalCVEs > 0" },
    { label: "MacOS - Critical CVEs", tone: "warn", query: "e/ Device f/ Platform = macos f/ ExploitedCVEs = 0 f/ CriticalCVEs > 0" },
    { label: "No critical CVEs", tone: "good", query: "e/ Device f/ OpenCVEs exists f/ CriticalCVEs = 0" }
  ] },
  { title: "Devices with actively exploited CVEs", type: "trend", series: [{ label: "Devices exposed", tone: "bad", query: "e/ Device f/ ExploitedCVEs > 0" }] },
  { title: "Devices by highest CVSS", type: "breakdown", group_by: "RiskLevel", series: [{ label: "Devices with open CVEs", tone: "neutral", query: "e/ Device f/ OpenCVEs > 0" }] }
];

// Server-local calendar day, so the trend matches the administrator's own date.
const localDay = (time) => {
  const date = new Date(time);
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
};
const SOURCE_LABELS = { intune: "Microsoft Intune", jamf: "Jamf Pro", crowdstrike: "CrowdStrike Falcon", agent: "PatchOps agent" };

export function postureSettings(env = process.env) {
  const mode = String(env.POSTURE_DATA_MODE ?? "auto").toLowerCase();
  return {
    mode: ["auto", "live", "sample"].includes(mode) ? mode : "auto",
    syncMinutes: Math.max(5, Number(env.POSTURE_SYNC_MINUTES) || 30),
    staleDays: Math.max(1, Number(env.POSTURE_STALE_DAYS) || 14),
    osSettings: {
      minMacos: env.POSTURE_MIN_MACOS?.trim() || null,
      latestMacos: env.POSTURE_LATEST_MACOS?.trim() || null,
      minWindowsBuild: env.POSTURE_MIN_WINDOWS_BUILD?.trim() || null,
      latestWindowsBuild: env.POSTURE_LATEST_WINDOWS_BUILD?.trim() || null
    }
  };
}

export function agentRecords(devices) {
  return devices.map((device) => ({
    source: "agent",
    source_id: device.id,
    hostname: device.hostname ?? "",
    serial_number: device.serial_number ?? "",
    platform: String(device.platform ?? "").toLowerCase(),
    model: device.model ?? "",
    manufacturer: String(device.platform).toLowerCase() === "macos" ? "Apple" : device.manufacturer ?? String(device.model ?? "").split(" ")[0] ?? "",
    architecture: device.architecture ?? "",
    ...(Array.isArray(device.installed_kbs) ? { reported_kbs: device.installed_kbs, reported_kbs_at: device.installed_kbs_at ?? device.last_seen_at ?? null } : {}),
    os: { name: device.os?.name ?? "", version: device.os?.version ?? "", build: device.os?.build ?? "" },
    user: { name: device.assigned_user ?? "", email: "" },
    last_check_in: device.last_seen_at ?? null,
    managed: true,
    compliance: "unknown",
    encrypted: typeof device.disk_encrypted === "boolean" ? device.disk_encrypted : null,
    security: {},
    ownership: "",
    apps: Array.isArray(device.software) ? device.software.map((app) => ({ name: app.name ?? "", version: app.version ?? "", publisher: app.publisher ?? "", bundle_id: app.bundle_identifier ?? "" })) : null
  }));
}

export class PostureService {
  constructor(store, { env = process.env, connectors, now = () => Date.now(), feeds = null, diskCache = null, waitForFirstSync = true, log = null } = {}) {
    this.store = store;
    // The real server never makes a page wait for a sync: it serves what it has and the
    // dashboard polls for progress. Tests keep the simpler "wait for the first sync".
    this.waitForFirstSync = waitForFirstSync;
    this.log = log ?? (() => {});
    // Optional on-disk snapshot (the real server passes one): restarts show data at once
    // and syncs only fetch what changed.
    this.diskCache = diskCache;
    // Public Apple / Microsoft / CISA feeds. Off unless a CveFeeds instance is passed in
    // (the real server does this), so tests and embedded use never reach the internet.
    this.feeds = feeds ?? new CveFeeds({ enabled: false, msrcMonths: 12, refreshHours: 24 });
    this.settings = postureSettings(env);
    const intune = intuneConfig(env);
    const jamf = jamfConfig(env);
    const crowdstrike = crowdstrikeConfig(env);
    this.connectors = connectors ?? {
      ...(intune.configured ? { intune: new IntuneConnector(intune) } : {}),
      ...(jamf.configured ? { jamf: new JamfConnector(jamf) } : {}),
      ...(crowdstrike.configured ? { crowdstrike: new CrowdStrikeConnector(crowdstrike) } : {})
    };
    this.now = now;
    this.useSample = this.settings.mode === "sample" || (this.settings.mode === "auto" && !Object.keys(this.connectors).length);
    this.cache = { intune: null, jamf: null, crowdstrike: null };
    this.status = {
      crowdstrike: { configured: Boolean(this.connectors.crowdstrike), state: this.connectors.crowdstrike ? "pending" : "not_configured", device_count: 0, synced_at: null, error: null },
      intune: { configured: Boolean(this.connectors.intune), state: this.connectors.intune ? "pending" : "not_configured", device_count: 0, synced_at: null, error: null },
      jamf: { configured: Boolean(this.connectors.jamf), state: this.connectors.jamf ? "pending" : "not_configured", device_count: 0, synced_at: null, error: null }
    };
    this.syncing = null;
    this.history = [];
  }

  // Loads the last saved snapshot once, before the first page is served.
  async init() {
    if (this.initialized) return this.initialized;
    this.initialized = (async () => {
      if (!this.diskCache?.enabled) return;
      const feeds = await this.diskCache.read("cve-feeds");
      if (feeds && this.feeds.settings.enabled) this.feeds.importState(feeds);
      this.feeds.onRefreshed = () => this.diskCache.write("cve-feeds", this.feeds.exportState());
      if (this.useSample) return;
      const saved = await this.diskCache.read("connectors");
      for (const [source, connector] of Object.entries(this.connectors)) {
        const entry = saved?.[source];
        if (!entry) continue;
        this.cache[source] = entry.records ?? null;
        Object.assign(this.status[source], entry.status ?? {}, { state: entry.records ? "ok" : this.status[source].state, from_cache: true });
        connector.importState?.(entry.state);
        for (const [name, capability] of Object.entries(entry.capabilities ?? {})) connector.capabilities?.[name]?.restore(capability);
      }
    })();
    return this.initialized;
  }

  persistConnectors() {
    if (!this.diskCache?.enabled || this.useSample) return;
    const snapshot = {};
    for (const [source, connector] of Object.entries(this.connectors)) {
      if (!this.cache[source]) continue;
      const { from_cache: _fromCache, ...status } = this.status[source];
      snapshot[source] = {
        records: this.cache[source],
        status,
        state: connector.exportState?.() ?? null,
        capabilities: connector.capabilities ? Object.fromEntries(Object.entries(connector.capabilities).map(([name, capability]) => [name, capability.toJSON()])) : {}
      };
    }
    return this.diskCache.write("connectors", snapshot);
  }

  async sync({ force = false, full = false } = {}) {
    await this.init();
    if (this.useSample) return;
    if (this.syncing) return this.syncing;
    const due = (source) => {
      if (force) return true;
      const { synced_at: syncedAt, attempted_at: attemptedAt, state } = this.status[source];
      if (state === "error" || state === "stale") return !attemptedAt || this.now() - Date.parse(attemptedAt) > 5 * 60_000; // back off after failures
      return !syncedAt || this.now() - Date.parse(syncedAt) > this.settings.syncMinutes * 60_000;
    };
    const work = Object.entries(this.connectors).filter(([source]) => due(source)).map(async ([source, connector]) => {
      const label = SOURCE_LABELS[source] ?? source;
      const started = Date.now();
      let lastLogged = 0;
      Object.assign(this.status[source], { state: "syncing", progress: "Starting…", sync_started_at: new Date(this.now()).toISOString() });
      this.log(`[sync] ${label}: started${full ? " (full resync)" : ""}`);
      connector.onProgress = (text) => {
        this.status[source].progress = text;
        if (Date.now() - lastLogged > 15_000) { lastLogged = Date.now(); this.log(`[sync] ${label}: ${text}`); }
      };
      try {
        const records = await connector.collect({ full });
        this.cache[source] = records;
        Object.assign(this.status[source], { state: "ok", device_count: records.length, synced_at: new Date(this.now()).toISOString(), error: null, from_cache: false, progress: null });
        this.log(`[sync] ${label}: done, ${records.length.toLocaleString("en-US")} devices in ${Math.round((Date.now() - started) / 1000)}s${connector.progressParts ? ` (${Object.values(connector.progressParts).filter(Boolean).join(" · ")})` : ""}`);
        this.computed = null;
        if (source === "intune") await this.refreshGroups();
        await this.persistConnectors(); // save each source as soon as it finishes
      } catch (error) {
        // Keep serving the last good data, but surface the failure to the dashboard.
        Object.assign(this.status[source], { state: this.cache[source] ? "stale" : "error", error: error.message, attempted_at: new Date(this.now()).toISOString(), progress: null });
        this.log(`[sync] ${label}: failed: ${error.message}`);
      }
    });
    if (!work.length) return;
    this.syncing = Promise.all(work).finally(() => { this.syncing = null; this.computed = null; });
    return this.syncing;
  }

  async records(devices = null) {
    const agentDevices = agentRecords(devices ?? await this.store.listDevices());
    if (this.useSample) return [...sampleFleet({ now: this.now() }), ...agentDevices];
    return [...(this.cache.intune ?? []), ...(this.cache.jamf ?? []), ...(this.cache.crowdstrike ?? []), ...agentDevices];
  }

  async compute({ fresh = false } = {}) {
    await this.init();
    // Wait for a sync only when there is nothing at all to show yet; otherwise serve the
    // saved/last data and refresh in the background.
    const firstSync = this.waitForFirstSync && !this.useSample && !Object.values(this.cache).some(Boolean) && Object.keys(this.connectors).some((source) => this.status[source].state !== "error");
    if (firstSync) await this.sync();
    else this.sync().catch(() => {}); // refresh in the background when due
    if (this.feeds.due()) {
      this.log("[feeds] checking Apple, Microsoft and CISA vulnerability data…");
      const started = Date.now();
      this.feeds.refresh().then(() => {
        this.computed = null;
        this.log(`[feeds] done in ${Math.round((Date.now() - started) / 1000)}s: ${Object.values(this.feeds.capabilities).map((capability) => `${capability.label.split(" (")[0]}: ${capability.state === "ok" ? capability.sync_mode ?? "ok" : capability.error}`).join(" | ")}`);
      }).catch(() => {});
    }
    // Recalculating a large fleet takes a second or two, so the result is reused until
    // something actually changes: a sync finishes, rules or dashboards are saved, the
    // feeds refresh (those clear this.computed), an agent checks in or the catalog
    // changes (the fingerprint below). Time-based checks ("seen in 7 days") are
    // refreshed every 5 minutes.
    const agentDevices = await this.store.listDevices();
    const catalog = await this.store.listCatalogEntries();
    const fingerprint = `${agentDevices.length}|${agentDevices.reduce((latest, device) => (device.last_seen_at > latest ? device.last_seen_at : latest), "")}|${catalog.map((entry) => `${entry.identity}=${entry.approved_version}`).join(",")}`;
    if (!fresh && this.computed && this.computed.fingerprint === fingerprint && this.now() - this.computed.at < 5 * 60_000) return this.computed.posture;
    const records = await this.records(agentDevices);
    const connected = { intune: this.useSample || Boolean(this.cache.intune), jamf: this.useSample || Boolean(this.cache.jamf), crowdstrike: this.useSample || Boolean(this.cache.crowdstrike) };
    const config = await this.fleetConfig();
    const osSettings = { ...(this.feeds.ready ? this.feeds.baselines() : {}), ...Object.fromEntries(Object.entries(this.settings.osSettings).filter(([, value]) => value)) };
    const userGroups = this.useSample ? SAMPLE_USER_GROUPS : this.connectors.intune?.groups?.members ?? {};
    const posture = computePosture(records, { userGroups, catalog, now: this.now(), staleDays: this.settings.staleDays, osSettings, connected, softwareRules: config.software_rules, trackedPatches: config.tracked_patches, cveFeeds: this.feeds.ready ? this.feeds : null });
    await this.recordHistory(posture);
    await this.recordQueryHistory(posture, config);
    this.computed = { at: this.now(), posture, fingerprint };
    return posture;
  }

  async recordHistory(posture) {
    if (!posture.summary.devices) return;
    const day = localDay(Date.parse(posture.generated_at));
    const point = { date: day, score: posture.summary.score, devices: posture.summary.devices, critical: posture.summary.by_risk.critical, high: posture.summary.by_risk.high };
    const history = this.useSample ? this.history : (await this.store.getPostureHistory?.()) ?? this.history;
    const existing = history.find((entry) => entry.date === day);
    if (existing && ["score", "devices", "critical", "high"].every((field) => existing[field] === point[field])) {
      this.history = history;
      return;
    }
    const next = [...history.filter((entry) => entry.date !== day), point].sort((left, right) => left.date.localeCompare(right.date)).slice(-180);
    this.history = next;
    if (!this.useSample) await this.store.savePostureHistory?.(next);
  }

  sampleHistory(current) {
    // Illustrative 30-day trend for the sample fleet only.
    const points = [];
    for (let offset = 29; offset >= 0; offset -= 1) {
      const date = localDay(this.now() - offset * 86_400_000);
      const drift = Math.round(offset * 0.35 + Math.sin(offset / 2.2) * 1.6);
      points.push({ date, score: Math.max(0, Math.min(100, current.score - drift)), devices: current.devices, critical: current.by_risk.critical + Math.round(offset / 8), high: current.by_risk.high + Math.round(offset / 6) });
    }
    return points;
  }

  sourceStatus(posture) {
    const sources = Object.fromEntries(["intune", "jamf", "crowdstrike"].map((source) => [source, {
      label: SOURCE_LABELS[source],
      ...(this.useSample ? { configured: false, state: "sample", device_count: posture.coverage[`in_${source}`], synced_at: posture.generated_at, error: null } : this.status[source])
    }]));
    sources.agent = { label: SOURCE_LABELS.agent, configured: true, state: "ok", device_count: posture.coverage.with_agent, synced_at: posture.generated_at, error: null };
    return sources;
  }

  async overview() {
    const posture = await this.compute();
    return {
      mode: this.useSample ? "sample" : "live",
      generated_at: posture.generated_at,
      syncing: Boolean(this.syncing),
      feeds_progress: this.feeds.refreshing ? this.feeds.progress ?? "Loading vulnerability feeds…" : null,
      settings: { stale_days: this.settings.staleDays, sync_minutes: this.settings.syncMinutes },
      sources: this.sourceStatus(posture),
      summary: posture.summary,
      coverage: posture.coverage,
      baselines: posture.baselines,
      top_risks: posture.top_risks,
      os: posture.os,
      apps: posture.apps.slice(0, 200),
      trend: this.useSample ? this.sampleHistory(posture.summary) : this.history,
      devices: posture.devices.map(deviceListItem)
    };
  }

  // ---- Fleet rules, saved dashboards and queries ----

  async fleetConfig() {
    if (this.config) return this.config;
    // Rules saved by older versions only had name patterns; sanitizing upgrades them to conditions
    // (and makes CrowdStrike rules use the Falcon sensor instead of app names).
    const savedRules = await this.store.getConfig?.("software_rules");
    const softwareRules = savedRules ? savedRules.map((rule) => { try { return sanitizeSoftwareRule(rule); } catch { return null; } }).filter(Boolean) : DEFAULT_SOFTWARE_RULES;
    const savedPatches = await this.store.getConfig?.("tracked_patches");
    const dashboards = (await this.store.getConfig?.("dashboards")) ?? defaultDashboards(softwareRules);
    this.config = {
      software_rules: softwareRules,
      tracked_patches: savedPatches ?? (this.useSample ? SAMPLE_TRACKED_PATCHES : []),
      tracked_patches_are_sample: !savedPatches && this.useSample,
      dashboards
    };
    return this.config;
  }

  async saveConfigValue(key, value) {
    await this.store.saveConfig(key, value);
    this.config = null;
    this.computed = null;
  }

  async saveSoftwareRules(input) {
    const rules = (Array.isArray(input) ? input : []).slice(0, 50).map(sanitizeSoftwareRule).filter(Boolean);
    const names = new Set();
    for (const rule of rules) {
      if (names.has(rule.name.toLowerCase())) throw new QueryError(`Two rules are named "${rule.name}"`);
      names.add(rule.name.toLowerCase());
    }
    await this.saveConfigValue("software_rules", rules);
    return rules;
  }

  async saveTrackedPatches(input) {
    const patches = (Array.isArray(input) ? input : []).slice(0, 100).map(sanitizeTrackedPatch).filter(Boolean);
    const unique = [...new Map(patches.map((patch) => [patch.kb, patch])).values()];
    await this.saveConfigValue("tracked_patches", unique);
    return unique;
  }

  async saveDashboard(input) {
    const dashboard = sanitizeDashboard(input);
    if (!dashboard) throw new QueryError("A dashboard needs a name");
    for (const widget of dashboard.widgets) for (const series of widget.series) {
      try { parseQuery(series.query); } catch (error) { throw new QueryError(`Widget "${widget.title}", series "${series.label}": ${error.message}`); }
    }
    const { dashboards } = await this.fleetConfig();
    const next = dashboards.some((item) => item.id === dashboard.id) ? dashboards.map((item) => (item.id === dashboard.id ? dashboard : item)) : [...dashboards, dashboard];
    await this.saveConfigValue("dashboards", next.slice(0, 50));
    return dashboard;
  }

  async deleteDashboard(id) {
    const { dashboards } = await this.fleetConfig();
    if (!dashboards.some((item) => item.id === id)) return false;
    await this.saveConfigValue("dashboards", dashboards.filter((item) => item.id !== id));
    return true;
  }

  async configSummary() {
    const posture = await this.compute();
    const config = await this.fleetConfig();
    return {
      mode: this.useSample ? "sample" : "live",
      software_rules: posture.software.map((rule) => ({ ...rule, ...describeRule(rule) })),
      app_names: this.appNames(posture),
      tracked_patches: posture.patches,
      tracked_patches_are_sample: config.tracked_patches_are_sample,
      kb_reporting: { configured: this.useSample || Boolean(this.connectors.intune?.config?.kbScriptId), devices: posture.kb_reporting.devices, error: this.connectors.intune?.kbError ?? null },
      dashboards: config.dashboards.map(({ id, name, widgets }) => ({ id, name, widget_count: widgets.length })),
      reference: queryReference(),
      suggested_widgets: [
        ...config.software_rules.map((rule) => ({ rule: rule.name, widget: coverageWidget(rule) })),
        ...(this.useSample || this.connectors.crowdstrike ? [{ rule: null, widget: CROWDSTRIKE_SYNC_WIDGET }, { rule: null, widget: CROWDSTRIKE_TREND_WIDGET }, ...CVE_WIDGETS.map((widget) => ({ rule: null, widget }))] : [])
      ]
    };
  }

  // Fetch Entra ID members for every group that a saved or ad-hoc query names.
  async wantedGroups(extra = []) {
    const config = await this.fleetConfig();
    const sources = [...config.dashboards.flatMap((dashboard) => dashboard.widgets.flatMap((widget) => widget.series.map((series) => series.query))), ...config.software_rules.map((rule) => rule.scope), ...(this.adhocGroupQueries ?? []), ...extra];
    return referencedGroups(sources);
  }

  async refreshGroups(extra = []) {
    const intune = this.connectors.intune;
    if (!intune?.fetchGroups) return null;
    if (this.groupRefresh) return this.groupRefresh;
    this.groupRefresh = (async () => {
      const wanted = await this.wantedGroups(extra);
      await intune.fetchGroups(wanted);
      this.computed = null;
      if (wanted.length) this.log(`[sync] Entra groups: ${intune.groups.group_names?.length ?? 0} groups, ${Object.keys(intune.groups.members ?? {}).length.toLocaleString("en-US")} members${intune.capabilities.groups.state === "ok" ? "" : ` (${intune.capabilities.groups.state}: ${intune.capabilities.groups.error ?? ""})`}`);
    })().finally(() => { this.groupRefresh = null; });
    return this.groupRefresh;
  }

  groupWarning(source) {
    const wanted = referencedGroups([source]);
    if (!wanted.length || this.useSample) return null;
    const intune = this.connectors.intune;
    if (!intune) return "Group conditions need Microsoft Intune connected (group membership comes from Entra ID).";
    const state = intune.capabilities.groups.state;
    if (state === "no_permission") return "Group membership can't be read: grant the Intune app GroupMember.Read.All and User.Read.All (application permissions), then resync.";
    const known = new Set((intune.groups.wanted ?? []).map((item) => `${item.op}|${item.value.toLowerCase()}`));
    if (wanted.some((item) => !known.has(`${item.op}|${item.value.toLowerCase()}`))) {
      this.adhocGroupQueries = [...new Set([...(this.adhocGroupQueries ?? []), source])].slice(-20);
      this.refreshGroups([source]).catch(() => {});
      return "Loading group members from Entra ID for this query. Counts update in a minute.";
    }
    return null;
  }

  // Every app name seen in the fleet (most common first), for the builder's name picker.
  appNames(posture) {
    if (this.appNamesCache?.posture === posture) return this.appNamesCache.names;
    const counts = { windows: new Map(), macos: new Map() };
    for (const device of posture.devices) {
      const map = counts[device.platform];
      if (!map) continue;
      for (const name of new Set((device.apps ?? []).map((app) => app.name).filter(Boolean))) map.set(name, (map.get(name) ?? 0) + 1);
    }
    const top = (map) => [...map].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 1500).map(([name, devices]) => ({ name, devices }));
    const names = { windows: top(counts.windows), macos: top(counts.macos) };
    this.appNamesCache = { posture, names };
    return names;
  }

  // Text -> tree for the visual builder. Errors come back as data so the editor can show them inline.
  parse(source) {
    try {
      const clauses = parseQuery(String(source ?? ""));
      return { ok: true, clauses, description: describeQuery(clauses) };
    } catch (error) {
      return { ok: false, error: error.message };
    }
  }

  // Dry-run a rule before saving: counts per platform and a few example devices of each outcome.
  async previewSoftwareRule(input) {
    const rule = sanitizeSoftwareRule(input);
    if (!rule) throw new QueryError("Give the rule a name and say how to detect it");
    const posture = await this.compute();
    const tally = { macos: { installed: 0, missing: 0, unknown: 0 }, windows: { installed: 0, missing: 0, unknown: 0 } };
    const examples = { installed: [], missing: [], unknown: [] };
    for (const device of posture.devices) {
      const outcome = evaluateSoftwareRule(rule, device, this.now());
      if (!tally[device.platform] || outcome.status === "not_applicable") continue;
      tally[device.platform][outcome.status] += 1;
      if (examples[outcome.status].length < 5) examples[outcome.status].push({ id: device.id, hostname: device.hostname, platform: device.platform, match: outcome.match });
    }
    return { rule, tally, examples };
  }

  async query(source, { groupBy = null, limit = 100 } = {}) {
    const posture = await this.compute();
    const parsed = parseQuery(source);
    const matches = runQuery(parsed, posture.devices, { now: this.now() });
    const result = { count: matches.length, total: posture.devices.length, devices: matches.slice(0, Math.min(Number(limit) || 100, 1000)).map(deviceListItem), description: describeQuery(parsed), warning: this.groupWarning(source) };
    if (groupBy) result.groups = this.groups(matches, groupBy);
    return result;
  }

  groups(devices, field) {
    const counts = new Map();
    for (const device of devices) {
      const key = groupValue(device, field);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()].map(([label, count]) => ({ label, count })).sort((left, right) => right.count - left.count);
  }

  queryKey(query) { return String(query).replace(/\s+/g, " ").trim(); }

  async recordQueryHistory(posture, config) {
    const queries = new Set(config.dashboards.flatMap((dashboard) => dashboard.widgets.flatMap((widget) => widget.series.map((series) => this.queryKey(series.query)))));
    if (!queries.size) return;
    const day = localDay(Date.parse(posture.generated_at));
    const counts = {};
    for (const query of queries) {
      try { counts[query] = runQuery(query, posture.devices, { now: this.now() }).length; } catch { /* invalid saved query: shown as an error on its widget */ }
    }
    this.todayCounts = counts;
    if (this.useSample) return;
    const history = (await this.store.getConfig?.("query_history")) ?? [];
    const today = history.find((entry) => entry.date === day);
    if (today && Object.entries(counts).every(([query, count]) => today.counts[query] === count)) return;
    const next = [...history.filter((entry) => entry.date !== day), { date: day, counts: { ...(today?.counts ?? {}), ...counts } }]
      .sort((left, right) => left.date.localeCompare(right.date)).slice(-180);
    await this.store.saveConfig("query_history", next);
  }

  async trend(query, current) {
    const key = this.queryKey(query);
    if (this.useSample) {
      // Illustrative 14-day history for the sample fleet: a gradual improvement towards today's value.
      let seed = [...key].reduce((sum, character) => (sum * 31 + character.charCodeAt(0)) >>> 0, 7);
      const noise = () => { seed = (seed * 1103515245 + 12345) >>> 0; return (seed / 4294967296) - 0.5; };
      return Array.from({ length: 14 }, (_, index) => {
        const daysAgo = 13 - index;
        const value = daysAgo === 0 ? current : Math.max(0, Math.round(current * (1 + daysAgo * 0.035) + noise() * Math.max(1, current * 0.08)));
        return { date: localDay(this.now() - daysAgo * 86_400_000), count: value };
      });
    }
    const history = (await this.store.getConfig?.("query_history")) ?? [];
    return history.filter((entry) => entry.counts[key] !== undefined).map((entry) => ({ date: entry.date, count: entry.counts[key] }));
  }

  // A query that names a software rule which doesn't exist silently matches nothing,
  // so call it out on the widget instead of showing zeros.
  unknownRuleWarning(widget, rules) {
    const names = new Set(rules.map((rule) => rule.name.toLowerCase()));
    const missing = new Set();
    for (const series of widget.series) {
      for (const match of series.query.matchAll(/SoftwareRule\s+f\/\s*(?:Name|Rule)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s)]+))/gi)) {
        const name = (match[1] ?? match[2] ?? match[3]).trim();
        if (!names.has(name.toLowerCase())) missing.add(name);
      }
    }
    return missing.size ? `No software rule named ${[...missing].map((name) => `"${name}"`).join(", ")}. Create it in Fleet Rules (same spelling) or fix the name in this widget's queries.` : null;
  }

  async dashboardData(id) {
    const config = await this.fleetConfig();
    const dashboard = config.dashboards.find((item) => item.id === id);
    if (!dashboard) return null;
    const posture = await this.compute();
    const widgets = [];
    for (const widget of dashboard.widgets) {
      try {
        const series = [];
        for (const item of widget.series) {
          const matches = runQuery(item.query, posture.devices, { now: this.now() });
          const entry = { ...item, count: matches.length, description: describeQuery(item.query) };
          const history = await this.trend(item.query, matches.length);
          if (widget.type === "trend") entry.trend = history;
          // Change over the last week, from the daily history (the oldest point within 7 days).
          const weekAgo = localDay(this.now() - 7 * 86_400_000);
          const base = history.find((point) => point.date >= weekAgo && point.date < localDay(this.now()));
          if (base) Object.assign(entry, { change: matches.length - base.count, change_since: base.date });
          if (widget.type === "table" && series.length === 0) entry.devices = matches.slice(0, 50).map(deviceListItem);
          if (widget.type === "breakdown" && series.length === 0) entry.groups = this.groups(matches, widget.group_by);
          series.push(entry);
        }
        widgets.push({ ...widget, series, warning: this.unknownRuleWarning(widget, config.software_rules) });
      } catch (error) {
        widgets.push({ ...widget, error: error.message });
      }
    }
    return { mode: this.useSample ? "sample" : "live", generated_at: posture.generated_at, dashboard: { id: dashboard.id, name: dashboard.name }, widgets };
  }

  async vulnerabilities() {
    const posture = await this.compute();
    const { list, ...summary } = posture.vulnerabilities;
    const capability = this.useSample ? { state: "sample" } : this.connectors.crowdstrike?.capabilities?.vulnerabilities?.toJSON() ?? { state: "not_configured" };
    const feeds = Object.fromEntries(Object.entries(this.feeds.capabilities).map(([key, value]) => [key, { state: value.state, error: value.error, synced_at: value.synced_at, label: value.label }]));
    return { mode: this.useSample ? "sample" : "live", generated_at: posture.generated_at, source: { state: capability.state, error: capability.error ?? null, scope: "Vulnerabilities: Read" }, feeds, feeds_loading: Boolean(this.feeds.refreshing), summary, cves: list.slice(0, 5000) };
  }

  // Everything each connector returned on its last sync: capabilities, permission gaps,
  // field fill-rates and a few raw (redacted) sample records.
  async sources() {
    const posture = await this.compute();
    const describe = (key, label) => {
      const connector = this.connectors[key];
      return {
        key, label,
        configured: Boolean(connector) || this.useSample,
        state: this.useSample ? "sample" : this.status[key]?.state ?? "not_configured",
        synced_at: this.useSample ? posture.generated_at : this.status[key]?.synced_at ?? null,
        error: this.useSample ? null : this.status[key]?.error ?? null,
        progress: this.useSample ? null : this.status[key]?.progress ?? null,
        capabilities: connector?.capabilities ? Object.fromEntries(Object.entries(connector.capabilities).map(([name, capability]) => [name, capability.toJSON()])) : this.useSample ? sampleCapabilities(key, posture) : {}
      };
    };
    return {
      mode: this.useSample ? "sample" : "live",
      generated_at: posture.generated_at,
      sources: [
        describe("crowdstrike", SOURCE_LABELS.crowdstrike), describe("jamf", SOURCE_LABELS.jamf), describe("intune", SOURCE_LABELS.intune),
        {
          key: "cve_feeds", label: "Public vulnerability feeds (Apple, Microsoft, CISA)", configured: this.feeds.settings.enabled,
          state: !this.feeds.settings.enabled ? "disabled" : this.feeds.refreshing ? "syncing" : this.feeds.ready ? "ok" : "pending",
          synced_at: this.feeds.refreshedAt ? new Date(this.feeds.refreshedAt).toISOString() : null, error: null,
          capabilities: Object.fromEntries(Object.entries(this.feeds.capabilities).map(([name, capability]) => [name, capability.toJSON()]))
        }
      ]
    };
  }

  async device(id) {
    const posture = await this.compute();
    const device = posture.devices.find((item) => item.id === id);
    return device ? { ...device, raw: redact(device.raw ?? {}) } : null;
  }

  async csv() {
    const posture = await this.compute();
    const columns = ["hostname", "serial_number", "platform", "os_version", "user", "email", "sources", "last_check_in", "encrypted", "intune_compliance", "risk_level", "risk_score", "issues"];
    const cell = (value) => {
      const text = String(value ?? "");
      const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text; // neutralise spreadsheet formulas
      return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
    };
    const rows = posture.devices.map((device) => [
      device.hostname, device.serial_number, device.platform, device.os.version, device.user.name, device.user.email,
      Object.keys(device.sources).join(" + "), device.last_check_in, device.encrypted ?? "unknown", device.compliance ?? "",
      device.risk_level, device.risk_score, device.issues.map((issue) => issue.title).join("; ")
    ].map(cell).join(","));
    return [columns.join(","), ...rows].join("\n");
  }
}
