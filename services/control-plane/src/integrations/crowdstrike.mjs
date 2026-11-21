// Read-only CrowdStrike Falcon connector (Hosts API).
//
// API client scopes:
//   Hosts: Read            required: device list, sensor health
//   Assets: Read           optional: installed applications (Falcon Discover / Exposure Management)
//   Vulnerabilities: Read  optional: open CVEs with remediation (Falcon Spotlight)
// Each optional capability is tried independently; a missing scope is reported, not fatal.
// Nothing here contains, deletes or changes hosts.

import { ConnectorError, fetchJSON } from "./http.mjs";
import { Capability } from "./inspect.mjs";
const fmt = (value) => Number(value).toLocaleString("en-US");


const CLOUDS = {
  "us-1": "https://api.crowdstrike.com",
  "us-2": "https://api.us-2.crowdstrike.com",
  "eu-1": "https://api.eu-1.crowdstrike.com",
  "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
  "us-gov-2": "https://api.us-gov-2.crowdstrike.mil"
};

const EXPLOIT_STATUS = { 0: "Unproven", 30: "Available", 60: "Easily accessible", 90: "Actively used" };
const SEVERITY = { critical: "critical", high: "high", medium: "medium", low: "low" };

export function crowdstrikeConfig(env = process.env) {
  const cloud = env.CROWDSTRIKE_CLOUD?.trim().toLowerCase();
  const baseUrl = (env.CROWDSTRIKE_BASE_URL?.trim() || CLOUDS[cloud] || CLOUDS["us-1"]).replace(/\/+$/, "");
  const config = {
    clientId: env.CROWDSTRIKE_CLIENT_ID?.trim(),
    clientSecret: env.CROWDSTRIKE_CLIENT_SECRET?.trim(),
    baseUrl,
    autodiscover: !env.CROWDSTRIKE_BASE_URL && !cloud,
    includeServers: /^(1|true|yes)$/i.test(env.CROWDSTRIKE_INCLUDE_SERVERS ?? ""),
    collectApps: !/^(0|false|no)$/i.test(env.CROWDSTRIKE_APPS ?? "true"),
    collectVulnerabilities: !/^(0|false|no)$/i.test(env.CROWDSTRIKE_VULNERABILITIES ?? "true"),
    maxVulnerabilities: Math.max(1000, Number(env.CROWDSTRIKE_MAX_VULNERABILITIES) || 250000),
    maxApps: Math.max(1000, Number(env.CROWDSTRIKE_MAX_APPS) || 500000),
    fullSyncHours: Math.max(1, Number(env.CROWDSTRIKE_FULL_SYNC_HOURS) || 24),
    // Full host records are large (200+ fields), so pages are kept moderate.
    pageSize: Math.max(100, Math.min(Number(env.CROWDSTRIKE_PAGE_SIZE) || 1000, 10000))
  };
  config.configured = Boolean(config.clientId && config.clientSecret);
  return config;
}

export function crowdstrikePlatform(platformName) {
  const value = String(platformName ?? "").toLowerCase();
  if (value === "windows") return "windows";
  if (value === "mac") return "macos";
  if (value === "linux") return "linux";
  return "other";
}

// Windows: prefer a full 10.0.build.revision string; macOS: major.minor when Falcon provides it.
// Versions that are only partial are flagged so a more precise source (Intune, Jamf) wins.
// Darwin 20 = macOS 11 … Darwin 24 = macOS 15; Apple then jumped to macOS 26 for Darwin 25.
export const darwinToMacMajor = (darwin) => (darwin >= 25 ? darwin + 1 : darwin - 9);

export function crowdstrikeOsVersion(host) {
  const platform = crowdstrikePlatform(host.platform_name);
  if (platform === "windows") {
    const kernel = String(host.kernel_version ?? "");
    if (/^10\.0\.\d{5}\.\d+$/.test(kernel)) return { version: kernel, approximate: false };
    const build = String(host.os_build ?? "");
    if (/^\d{5}\.\d+$/.test(build)) return { version: `10.0.${build}`, approximate: false };
    if (/^\d{5}$/.test(build)) return { version: `10.0.${build}`, approximate: true };
    return { version: "", approximate: true };
  }
  if (platform === "macos") {
    // Falcon's major/minor_version and kernel_version on Macs are Darwin numbers
    // (Darwin 25.x = macOS 26.x, Darwin 24.x = macOS 15.x), not macOS versions.
    const fromName = /\((\d+(?:\.\d+)*)\)/.exec(String(host.os_version ?? ""))?.[1];
    const darwin = [host.major_version, host.minor_version].every((part) => /^\d+$/.test(String(part ?? "").trim()))
      ? [Number(host.major_version), Number(host.minor_version)]
      : /^(\d+)\.(\d+)/.exec(String(host.kernel_version ?? ""))?.slice(1).map(Number) ?? null;
    if (darwin && darwin[0] >= 20) {
      const macMajor = darwinToMacMajor(darwin[0]);
      if (!fromName || Number(fromName.split(".")[0]) === macMajor) return { version: `${macMajor}.${darwin[1]}`, approximate: true };
    } else if (darwin && darwin[0] >= 11 && !fromName) {
      return { version: `${darwin[0]}.${darwin[1]}`, approximate: true }; // already a macOS version
    }
    return { version: fromName ?? "", approximate: true };
  }
  return { version: "", approximate: true };
}

// Falcon's asset inventory also lists code libraries (npm, PyPI…), developer packages and
// browser extensions. Only installed applications are kept.
export function crowdstrikeAppKind(app) {
  if (app.browser_extension || /extension/i.test(String(app.software_type ?? ""))) return "browser_extension";
  if (app.dev_package || /software package|librar|package/i.test(String(app.category ?? "")) || /package|librar/i.test(String(app.software_type ?? ""))) return "package";
  return "application";
}

export function normalizeCrowdStrikeApp(app) {
  return {
    aid: app.host?.aid ?? app.host?.id ?? app.host?.device_id ?? app.aid ?? null,
    hostname: app.host?.hostname ?? null,
    app: { name: String(app.name ?? "").replace(/\.app$/i, ""), version: app.version ?? "", publisher: app.vendor ?? "", bundle_id: "" },
    type: crowdstrikeAppKind(app)
  };
}

const kbs = (value) => [...new Set((JSON.stringify(value ?? "").match(/KB\d{6,8}/gi) ?? []).map((kb) => kb.toUpperCase()))];

export function normalizeCrowdStrikeVulnerability(vuln) {
  const cve = vuln.cve ?? {};
  const exploitCode = Number(cve.exploit_status);
  const app = vuln.apps?.[0] ?? vuln.app ?? {};
  const remediations = (vuln.remediation?.entities ?? []).map((entry) => entry.title || entry.action || entry.reference).filter(Boolean);
  return {
    source: "crowdstrike",
    aid: vuln.aid ?? vuln.host_info?.aid ?? null,
    hostname: vuln.host_info?.hostname ?? null,
    cve: String(cve.id ?? vuln.cve_id ?? vuln.vulnerability_id ?? "").toUpperCase(),
    severity: SEVERITY[String(cve.severity ?? vuln.severity ?? "").toLowerCase()] ?? "low",
    score: Number(cve.base_score ?? cve.cvss_base_score) || null,
    exprt: String(cve.exprt_rating ?? "").toLowerCase() || null,
    exploit: Number.isFinite(exploitCode) && cve.exploit_status !== undefined && cve.exploit_status !== null ? EXPLOIT_STATUS[exploitCode] ?? String(cve.exploit_status) : cve.exploit_status ?? null,
    kev: Boolean(cve.cisa_info?.is_cisa_kev ?? cve.is_cisa_kev ?? false),
    product: app.product_name_version || [app.product_name_normalized ?? app.product_name, app.version].filter(Boolean).join(" ") || "",
    status: String(vuln.status ?? "open").toLowerCase(),
    remediation: remediations.slice(0, 3),
    kbs: kbs(vuln.remediation),
    first_seen: vuln.created_timestamp ?? null,
    description: String(cve.description ?? "").slice(0, 400)
  };
}

export function normalizeCrowdStrikeHost(host) {
  const platform = crowdstrikePlatform(host.platform_name);
  const { version, approximate } = crowdstrikeOsVersion(host);
  const windowsBuild = Number(version.split(".")[2]);
  return {
    source: "crowdstrike",
    source_id: host.device_id ?? "",
    hostname: host.hostname ?? "",
    serial_number: host.serial_number ?? host.system_serial_number ?? "",
    platform,
    model: host.system_product_name ?? "",
    manufacturer: host.system_manufacturer ?? "",
    os: { name: platform === "windows" ? (windowsBuild ? (windowsBuild >= 22000 ? "Windows 11" : "Windows 10") : host.os_version ?? "Windows") : platform === "macos" ? "macOS" : host.os_version ?? "", version, build: platform === "macos" ? host.os_build ?? "" : "" },
    os_approximate: approximate,
    user: { name: host.last_login_user ?? "", email: "" },
    last_check_in: host.last_seen ?? null,
    enrolled_at: host.first_seen ?? null,
    managed: true,
    compliance: "unknown",
    encrypted: null,
    security: {},
    ownership: "",
    apps: null,
    raw: host,
    sensor: {
      version: host.agent_version ?? "",
      rfm: String(host.reduced_functionality_mode ?? "").toLowerCase() === "yes",
      status: host.status ?? "",
      contained: ["contained", "containment_pending"].includes(String(host.status ?? "").toLowerCase()),
      product_type: host.product_type_desc ?? "",
      tags: Array.isArray(host.tags) ? host.tags : []
    }
  };
}

export class CrowdStrikeConnector {
  constructor(config = crowdstrikeConfig(), { fetchImpl = globalThis.fetch } = {}) {
    this.config = { ...config };
    this.fetchImpl = fetchImpl;
    this.token = null;
    this.capabilities = {
      hosts: new Capability("Hosts", "Hosts: Read"),
      applications: new Capability("Installed applications", "Assets: Read"),
      vulnerabilities: new Capability("Vulnerabilities (Spotlight)", "Vulnerabilities: Read")
    };
    if (!this.config.collectApps) this.capabilities.applications.finish("disabled");
    if (!this.config.collectVulnerabilities) this.capabilities.vulnerabilities.finish("disabled");
  }

  async requestToken(baseUrl) {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.fetchImpl(`${baseUrl}/oauth2/token`, {
          method: "POST",
          headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ client_id: this.config.clientId, client_secret: this.config.clientSecret }),
          redirect: "manual",
          signal: AbortSignal.timeout(60_000)
        });
      } catch (error) {
        if (attempt >= 3) throw new ConnectorError(`CrowdStrike sign-in: no response from ${new URL(baseUrl).host} (${error.message})`, { source: "crowdstrike" });
        await new Promise((resolve) => setTimeout(resolve, 2000 * attempt));
      }
    }
  }

  async accessToken() {
    if (this.token && this.token.expiresAt > Date.now() + 60_000) return this.token.value;
    let response = await this.requestToken(this.config.baseUrl);
    // Falcon reports the tenant's cloud in X-Cs-Region; switch to it when the default was wrong.
    const region = response.headers.get("x-cs-region")?.toLowerCase();
    if (this.config.autodiscover && region && CLOUDS[region] && CLOUDS[region] !== this.config.baseUrl) {
      this.config.baseUrl = CLOUDS[region];
      response = await this.requestToken(this.config.baseUrl); // tokens are issued per cloud
    }
    if (response.status === 401 || response.status === 403) throw new ConnectorError("CrowdStrike sign-in: credentials were rejected — check the client ID and secret", { status: response.status, source: "crowdstrike" });
    if (!response.ok) throw new ConnectorError(`CrowdStrike sign-in: HTTP ${response.status}. If your tenant is not on US-1, set CROWDSTRIKE_CLOUD (us-2, eu-1, us-gov-1)`, { status: response.status, source: "crowdstrike" });
    const result = await response.json();
    if (!result?.access_token) throw new ConnectorError("CrowdStrike sign-in: no access token returned", { source: "crowdstrike" });
    this.token = { value: result.access_token, expiresAt: Date.now() + Number(result.expires_in ?? 1799) * 1000 };
    return this.token.value;
  }

  // Live progress for the dashboard and Terminal ("Hosts 2,000 of 4,512 · …").
  report(part, text) {
    this.progressParts = { ...(this.progressParts ?? {}), [part]: text };
    this.onProgress?.(Object.values(this.progressParts).filter(Boolean).join(" · "));
  }

  async listHosts() {
    const hosts = [];
    const filter = "platform_name:['Windows','Mac']";
    const seenCursors = new Set();
    let cursor = null;
    while (true) {
      // No "fields" list: the full host record is kept so the Data Sources page can show everything Falcon sends.
      const params = new URLSearchParams({ limit: String(this.config.pageSize), sort: "device_id.asc", filter });
      if (cursor) params.set("offset", cursor);
      const page = await fetchJSON(`${this.config.baseUrl}/devices/combined/devices/v1?${params}`, {
        headers: { authorization: `Bearer ${await this.accessToken()}` },
        source: "CrowdStrike",
        fetchImpl: this.fetchImpl
      });
      const resources = page?.resources ?? [];
      hosts.push(...resources);
      this.report("hosts", `Hosts ${fmt(hosts.length)}${page?.meta?.pagination?.total ? ` of ${fmt(page.meta.pagination.total)}` : ""}`);
      const pagination = page?.meta?.pagination ?? {};
      const next = pagination.next ?? (typeof pagination.offset === "string" ? pagination.offset : null);
      const total = Number(pagination.total ?? 0);
      if (!resources.length || !next || seenCursors.has(next) || (total && hosts.length >= total)) break;
      seenCursors.add(next);
      cursor = next;
    }
    return hosts;
  }

  // Cursor pagination shared by the Discover and Spotlight endpoints ("after" token).
  async *pages(path, params, { maxRecords }) {
    let after = null;
    let fetched = 0;
    const seen = new Set();
    while (true) {
      // Arrays become repeated parameters (facet=cve&facet=remediation), which Falcon requires.
      const query = new URLSearchParams();
      for (const [key, value] of Object.entries(params)) for (const item of [value].flat()) query.append(key, item);
      if (after) query.set("after", after);
      const page = await fetchJSON(`${this.config.baseUrl}${path}?${query}`, { headers: { authorization: `Bearer ${await this.accessToken()}` }, source: "CrowdStrike", fetchImpl: this.fetchImpl });
      const resources = page?.resources ?? [];
      fetched += resources.length;
      yield resources;
      const next = page?.meta?.pagination?.after ?? page?.meta?.pagination?.next ?? null;
      if (!resources.length || !next || seen.has(next) || fetched >= maxRecords) break;
      seen.add(next);
      after = next;
    }
  }

  capabilityError(capability, error) {
    if (error.status === 403) return capability.finish("no_permission", `The API client needs the "${capability.scope}" scope${capability.scope === "Assets: Read" ? " (and a Falcon Discover / Exposure Management license)" : capability.scope === "Vulnerabilities: Read" ? " (and a Falcon Spotlight license)" : ""}.`);
    return capability.finish("error", error.message);
  }

  // ---- Incremental state: apps and vulnerabilities are kept between syncs and only
  // records changed since the last sync are fetched. A full refresh runs daily so
  // removed apps and deleted records are caught too.
  exportState() {
    return { apps: [...(this.appIndex ?? new Map()).entries()], vulns: [...(this.vulnIndex ?? new Map()).entries()], sync: this.syncState ?? {} };
  }

  importState(state) {
    this.appIndex = new Map(state?.apps ?? []);
    this.vulnIndex = new Map(state?.vulns ?? []);
    this.syncState = state?.sync ?? {};
  }

  incrementalSince(kind, full) {
    const state = this.syncState ?? {};
    const lastFull = Date.parse(state[`${kind}_full_at`] ?? "");
    const last = Date.parse(state[`${kind}_at`] ?? "");
    if (full || !Number.isFinite(lastFull) || !Number.isFinite(last) || Date.now() - lastFull > this.config.fullSyncHours * 3_600_000) return null;
    return new Date(last - 15 * 60_000).toISOString().replace(/\.\d{3}Z$/, "Z"); // 15 min overlap for clock skew
  }

  markSynced(kind, startedAt, wasFull) {
    this.syncState = { ...(this.syncState ?? {}), [`${kind}_at`]: startedAt, ...(wasFull ? { [`${kind}_full_at`]: startedAt } : {}) };
  }

  // One tiny probe request decides the lightest query this tenant supports.
  async planApplicationsQuery() {
    const probe = async (params) => {
      const query = new URLSearchParams();
      for (const [key, value] of Object.entries(params)) for (const item of [value].flat()) query.append(key, item);
      return fetchJSON(`${this.config.baseUrl}/discover/combined/applications/v1?${query}`, { headers: { authorization: `Bearer ${await this.accessToken()}` }, source: "CrowdStrike", fetchImpl: this.fetchImpl });
    };
    let excludePackages = true;
    let sample;
    try {
      sample = await probe({ limit: "5", filter: "category:!'Software Packages'" });
    } catch (error) {
      if (error.status !== 400) throw error;
      excludePackages = false;
      sample = await probe({ limit: "5" });
    }
    const hasHostId = (sample?.resources ?? []).some((raw) => normalizeCrowdStrikeApp(raw).aid);
    return { excludePackages, facet: !hasHostId && (sample?.resources ?? []).length > 0 };
  }

  async collectApplications({ full = false } = {}) {
    const capability = this.capabilities.applications;
    if (!this.config.collectApps) return new Map();
    this.appIndex ??= new Map();
    const startedAt = new Date().toISOString();
    const since = this.incrementalSince("apps", full);
    let byHostName = new Map([...this.appIndex].map(([key, value]) => [`${value.aid}|${value.app.name}`, key]));
    let skipped = 0;
    // Download size: each record can carry a full copy of the computer's details
    // (facet=host_info). It is only requested if records don't already include the host id.
    let plan = this.syncState?.apps_plan ?? null;
    const run = async (filter) => {
      const combined = [filter, plan.excludePackages ? "category:!'Software Packages'" : null].filter(Boolean).join("+");
      const params = { limit: "1000", ...(plan.facet ? { facet: ["host_info"] } : {}), ...(combined ? { filter: combined } : {}) };
      let seen = 0;
      for await (const resources of this.pages("/discover/combined/applications/v1", params, { maxRecords: this.config.maxApps })) {
        seen += resources.length;
        this.report("apps", `Installed apps ${fmt(seen)} records${filter ? " changed" : ""}`);
        for (const raw of resources) {
          capability.observe(raw);
          const entry = normalizeCrowdStrikeApp(raw);
          if (!entry.aid || !entry.app.name || entry.type !== "application") { skipped += 1; continue; }
          const key = String(raw.id ?? `${entry.aid}|${entry.app.name}|${entry.app.version}`);
          // An upgraded app replaces its older record on the same host.
          const hostName = `${entry.aid}|${entry.app.name}`;
          const previousKey = byHostName.get(hostName);
          if (previousKey && previousKey !== key) this.appIndex.delete(previousKey);
          byHostName.set(hostName, key);
          this.appIndex.set(key, { aid: entry.aid, app: entry.app });
        }
      }
    };
    try {
      capability.begin();
      if (!plan) {
        plan = await this.planApplicationsQuery();
        this.syncState = { ...(this.syncState ?? {}), apps_plan: plan };
      }
      if (since) {
        try {
          await run(`last_updated_timestamp:>'${since}'`);
          capability.sync_mode = "incremental";
        } catch (error) {
          if (error.status !== 400) throw error;
          capability.begin();
          this.appIndex = new Map();
          byHostName = new Map();
          await run(null);
          capability.sync_mode = "full (incremental filter not supported)";
        }
      } else {
        this.appIndex = new Map();
        byHostName = new Map();
        await run(null);
        capability.sync_mode = "full";
      }
      this.markSynced("apps", startedAt, !capability.sync_mode.startsWith("incremental"));
      capability.count = this.appIndex.size;
      capability.sync_mode = `${capability.sync_mode}; ${skipped.toLocaleString("en-US")} libraries/extensions skipped${plan.excludePackages ? ", software packages filtered out by CrowdStrike" : ""}${plan.facet ? "" : ", compact records"}`;
      capability.finish("ok");
    } catch (error) {
      if (error.status === 400 && plan?.excludePackages) {
        // The package filter isn't accepted by this tenant: plan again without it.
        this.syncState = { ...(this.syncState ?? {}), apps_plan: { ...plan, excludePackages: false } };
        return this.collectApplications({ full: true });
      }
      this.capabilityError(capability, error);
    }
    const byHost = new Map();
    for (const { aid, app } of this.appIndex.values()) {
      if (!byHost.has(aid)) byHost.set(aid, []);
      byHost.get(aid).push(app);
    }
    return byHost;
  }

  async collectVulnerabilities({ full = false } = {}) {
    const capability = this.capabilities.vulnerabilities;
    if (!this.config.collectVulnerabilities) return new Map();
    this.vulnIndex ??= new Map();
    const startedAt = new Date().toISOString();
    const keyFor = (raw, entry) => String(raw.id ?? `${entry.aid}|${entry.cve}`);
    const run = async ({ filter, facet }, { incremental }) => {
      let seen = 0;
      for await (const resources of this.pages("/spotlight/combined/vulnerabilities/v1", { limit: "1000", filter, facet }, { maxRecords: this.config.maxVulnerabilities })) {
        seen += resources.length;
        this.report("vulns", `Vulnerabilities ${fmt(seen)} records${incremental ? " changed" : ""}`);
        for (const raw of resources) {
          capability.observe(raw);
          const entry = normalizeCrowdStrikeVulnerability(raw);
          if (!entry.aid || !entry.cve) continue;
          const key = keyFor(raw, entry);
          // In incremental mode closed / expired findings are removed.
          if (incremental && !["open", "reopen"].includes(entry.status)) this.vulnIndex.delete(key);
          else this.vulnIndex.set(key, entry);
        }
      }
    };
    const fullRun = async () => {
      // Falcon tenants differ slightly in which filters/facets they accept, so fall back
      // step by step on "400 Bad Request" and keep the most detailed query that works.
      const attempts = [
        // host_info is left out: records already carry the host id (aid) and it would
        // repeat the full computer details in every vulnerability record.
        { filter: "status:['open','reopen']", facet: ["cve", "remediation"] },
        { filter: "status:'open'", facet: ["cve", "remediation"] },
        { filter: "status:'open'", facet: ["cve"] }
      ];
      let lastError = null;
      for (const attempt of attempts) {
        capability.begin();
        this.vulnIndex = new Map();
        try {
          await run(attempt, { incremental: false });
          capability.query = attempt;
          this.syncState = { ...(this.syncState ?? {}), vuln_facets: attempt.facet };
          return;
        } catch (error) {
          if (error.status !== 400) throw error;
          lastError = error;
        }
      }
      throw lastError;
    };
    try {
      const since = this.incrementalSince("vulns", full);
      let mode = "full";
      if (since) {
        capability.begin();
        try {
          const facet = (this.syncState?.vuln_facets ?? ["cve", "remediation"]).filter((item) => item !== "host_info");
          await run({ filter: `updated_timestamp:>'${since}'`, facet }, { incremental: true });
          capability.query = { filter: `updated_timestamp:>'${since}'`, facet };
          mode = "incremental";
        } catch (error) {
          if (error.status !== 400) throw error;
          await fullRun();
          mode = "full (incremental filter not supported)";
        }
      } else {
        await fullRun();
      }
      capability.sync_mode = mode;
      this.markSynced("vulns", startedAt, mode !== "incremental");
      capability.count = this.vulnIndex.size;
      capability.finish("ok");
    } catch (error) {
      this.capabilityError(capability, error);
    }
    const byHost = new Map();
    for (const entry of this.vulnIndex.values()) {
      if (!byHost.has(entry.aid)) byHost.set(entry.aid, []);
      byHost.get(entry.aid).push(entry);
    }
    return byHost;
  }

  async collect({ full = false } = {}) {
    this.progressParts = {};
    const hosts = this.capabilities.hosts;
    hosts.begin();
    const records = [];
    for (const raw of await this.listHosts()) {
      hosts.observe(raw);
      const record = normalizeCrowdStrikeHost(raw);
      if (record.platform !== "windows" && record.platform !== "macos") continue;
      // Servers and domain controllers are out of scope unless explicitly included.
      if (!this.config.includeServers && /server|domain controller/i.test(record.sensor.product_type)) continue;
      records.push(record);
    }
    hosts.finish("ok");
    const [apps, vulnerabilities] = await Promise.all([this.collectApplications({ full }), this.collectVulnerabilities({ full })]);
    for (const record of records) {
      // No Discover rows for a host means "unknown", not "nothing installed".
      if (apps.has(record.source_id)) record.apps = apps.get(record.source_id);
      if (this.capabilities.vulnerabilities.state === "ok") record.vulnerabilities = vulnerabilities.get(record.source_id) ?? [];
    }
    return records;
  }
}
