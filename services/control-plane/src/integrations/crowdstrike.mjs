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
    pageSize: Math.max(100, Math.min(Number(env.CROWDSTRIKE_PAGE_SIZE) || 5000, 10000))
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
    const major = String(host.major_version ?? "").trim();
    const minor = String(host.minor_version ?? "").trim();
    if (/^\d+$/.test(major)) return { version: /^\d+$/.test(minor) ? `${major}.${minor}` : major, approximate: true };
    const fromName = /\((\d+(?:\.\d+)*)\)/.exec(String(host.os_version ?? ""));
    return { version: fromName?.[1] ?? "", approximate: true };
  }
  return { version: "", approximate: true };
}

export function normalizeCrowdStrikeApp(app) {
  return {
    aid: app.host?.aid ?? app.host?.id ?? app.host?.device_id ?? app.aid ?? null,
    hostname: app.host?.hostname ?? null,
    app: { name: String(app.name ?? "").replace(/\.app$/i, ""), version: app.version ?? "", publisher: app.vendor ?? "", bundle_id: "" },
    type: String(app.software_type ?? "application").toLowerCase()
  };
}

const kbs = (value) => [...new Set((JSON.stringify(value ?? "").match(/KB\d{6,8}/gi) ?? []).map((kb) => kb.toUpperCase()))];

export function normalizeCrowdStrikeVulnerability(vuln) {
  const cve = vuln.cve ?? {};
  const exploitCode = Number(cve.exploit_status);
  const app = vuln.apps?.[0] ?? vuln.app ?? {};
  const remediations = (vuln.remediation?.entities ?? []).map((entry) => entry.title || entry.action || entry.reference).filter(Boolean);
  return {
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
    serial_number: host.serial_number ?? "",
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
    const response = await this.fetchImpl(`${baseUrl}/oauth2/token`, {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: this.config.clientId, client_secret: this.config.clientSecret }),
      redirect: "manual",
      signal: AbortSignal.timeout(30_000)
    });
    return response;
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

  async collectApplications() {
    const capability = this.capabilities.applications;
    if (!this.config.collectApps) return new Map();
    capability.begin();
    const byHost = new Map();
    try {
      for await (const resources of this.pages("/discover/combined/applications/v1", { limit: "1000", facet: ["host_info"] }, { maxRecords: this.config.maxApps })) {
        for (const raw of resources) {
          capability.observe(raw);
          const entry = normalizeCrowdStrikeApp(raw);
          if (!entry.aid || !entry.app.name || entry.type.includes("extension")) continue;
          if (!byHost.has(entry.aid)) byHost.set(entry.aid, []);
          byHost.get(entry.aid).push(entry.app);
        }
      }
      capability.finish("ok");
    } catch (error) {
      this.capabilityError(capability, error);
    }
    return byHost;
  }

  async collectVulnerabilities() {
    const capability = this.capabilities.vulnerabilities;
    if (!this.config.collectVulnerabilities) return new Map();
    capability.begin();
    const byHost = new Map();
    const run = async ({ filter, facet }) => {
      for await (const resources of this.pages("/spotlight/combined/vulnerabilities/v1", { limit: "5000", filter, facet }, { maxRecords: this.config.maxVulnerabilities })) {
        for (const raw of resources) {
          capability.observe(raw);
          const entry = normalizeCrowdStrikeVulnerability(raw);
          if (!entry.aid || !entry.cve) continue;
          if (!byHost.has(entry.aid)) byHost.set(entry.aid, []);
          byHost.get(entry.aid).push(entry);
        }
      }
    };
    // Falcon tenants differ slightly in which filters/facets they accept, so fall back
    // step by step on "400 Bad Request" and keep the most detailed query that works.
    const attempts = [
      { filter: "status:['open','reopen']", facet: ["cve", "remediation", "host_info"] },
      { filter: "status:'open'", facet: ["cve", "remediation", "host_info"] },
      { filter: "status:'open'", facet: ["cve", "remediation"] },
      { filter: "status:'open'", facet: ["cve"] }
    ];
    try {
      let lastError = null;
      for (const attempt of attempts) {
        capability.begin();
        byHost.clear();
        try {
          await run(attempt);
          lastError = null;
          capability.query = attempt;
          break;
        } catch (error) {
          if (error.status !== 400) throw error;
          lastError = error;
        }
      }
      if (lastError) throw lastError;
      capability.finish("ok");
    } catch (error) {
      this.capabilityError(capability, error);
    }
    return byHost;
  }

  async collect() {
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
    const [apps, vulnerabilities] = await Promise.all([this.collectApplications(), this.collectVulnerabilities()]);
    for (const record of records) {
      // No Discover rows for a host means "unknown", not "nothing installed".
      if (apps.has(record.source_id)) record.apps = apps.get(record.source_id);
      if (this.capabilities.vulnerabilities.state === "ok") record.vulnerabilities = vulnerabilities.get(record.source_id) ?? [];
    }
    return records;
  }
}
