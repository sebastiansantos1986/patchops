// Read-only Microsoft Intune connector (Microsoft Graph v1.0, app-only auth).
//
// Required Entra ID application permissions (admin consent):
//   DeviceManagementManagedDevices.Read.All
// Optional, for exact installed-KB lists from the PatchOps Remediation script:
//   DeviceManagementConfiguration.Read.All   (+ INTUNE_KB_SCRIPT_ID)
// Nothing here writes to Intune.

import { ConnectorError, fetchJSON, mapLimit } from "./http.mjs";
import { Capability } from "./inspect.mjs";
const fmt = (value) => Number(value).toLocaleString("en-US");


const GRAPH = "https://graph.microsoft.com/v1.0";
const GRAPH_BETA = "https://graph.microsoft.com/beta";
const DEVICE_FIELDS = [
  "id", "deviceName", "serialNumber", "operatingSystem", "osVersion", "complianceState", "isEncrypted",
  "lastSyncDateTime", "enrolledDateTime", "userPrincipalName", "userDisplayName", "emailAddress", "model",
  "manufacturer", "managementAgent", "jailBroken", "managedDeviceOwnerType", "azureADDeviceId"
].join(",");

export function intuneConfig(env = process.env) {
  const config = {
    tenantId: env.INTUNE_TENANT_ID?.trim(),
    clientId: env.INTUNE_CLIENT_ID?.trim(),
    clientSecret: env.INTUNE_CLIENT_SECRET?.trim(),
    includeApps: !/^(0|false|no)$/i.test(env.INTUNE_INCLUDE_APPS ?? "true"),
    appConcurrency: Math.max(1, Math.min(Number(env.INTUNE_APP_CONCURRENCY) || 4, 10)),
    kbScriptId: /^[0-9a-f-]{36}$/i.test(env.INTUNE_KB_SCRIPT_ID?.trim() ?? "") ? env.INTUNE_KB_SCRIPT_ID.trim() : null
  };
  config.configured = Boolean(config.tenantId && config.clientId && config.clientSecret);
  return config;
}

export function normalizeIntunePlatform(operatingSystem) {
  const value = String(operatingSystem ?? "").toLowerCase();
  if (value.startsWith("windows")) return "windows";
  if (value === "macos" || value === "mac os x" || value === "osx") return "macos";
  if (value === "ios" || value === "ipados") return "ios";
  if (value.startsWith("android")) return "android";
  if (value.startsWith("linux")) return "linux";
  return "other";
}

export function windowsName(osVersion) {
  const build = Number(String(osVersion ?? "").split(".")[2]);
  if (!Number.isFinite(build)) return "Windows";
  return build >= 22000 ? "Windows 11" : "Windows 10";
}

const encryptedValue = (value) => (value === true ? true : value === false ? false : null);

export function normalizeIntuneDevice(device, apps = null) {
  const platform = normalizeIntunePlatform(device.operatingSystem);
  return {
    source: "intune",
    source_id: device.id,
    hostname: device.deviceName ?? "",
    serial_number: device.serialNumber ?? "",
    platform,
    model: device.model ?? "",
    manufacturer: device.manufacturer ?? "",
    os: { name: platform === "windows" ? windowsName(device.osVersion) : platform === "macos" ? "macOS" : device.operatingSystem ?? "", version: device.osVersion ?? "", build: "" },
    user: { name: device.userDisplayName ?? "", email: device.userPrincipalName || device.emailAddress || "" },
    last_check_in: device.lastSyncDateTime ?? null,
    enrolled_at: device.enrolledDateTime ?? null,
    managed: true,
    compliance: String(device.complianceState ?? "unknown").toLowerCase(),
    encrypted: encryptedValue(device.isEncrypted),
    security: { jailbroken: device.jailBroken === "True" ? true : device.jailBroken === "False" ? false : null },
    ownership: device.managedDeviceOwnerType ?? "",
    apps: apps ? apps.map((app) => ({ name: app.displayName ?? "", version: app.version ?? "", publisher: app.publisher ?? "", bundle_id: "" })).filter((app) => app.name) : null
  };
}

// Output written by scripts/intune/Detect-InstalledKBs.ps1: "PATCHOPS_KBS:KB5001,KB5002"
export function parseKbOutput(output) {
  const text = String(output ?? "");
  if (!text.includes("PATCHOPS_KBS:")) return null;
  return [...new Set((text.split("PATCHOPS_KBS:")[1].match(/KB\d{6,8}/gi) ?? []).map((kb) => kb.toUpperCase()))];
}

export class IntuneConnector {
  constructor(config = intuneConfig(), { fetchImpl } = {}) {
    this.config = config;
    this.fetchImpl = fetchImpl;
    this.token = null;
    this.capabilities = {
      devices: new Capability("Managed devices", "DeviceManagementManagedDevices.Read.All"),
      kb_reports: new Capability("Installed KB reports (Remediation)", "DeviceManagementConfiguration.Read.All"),
      groups: new Capability("Group membership (for queries on Group)", "GroupMember.Read.All, User.Read.All")
    };
    this.groups = { wanted: [], members: {}, fetched_at: null };
    this.capabilities.groups.finish("disabled");
    if (!this.config.kbScriptId) this.capabilities.kb_reports.finish("disabled");
  }

  async accessToken() {
    if (this.token && this.token.expiresAt > Date.now() + 60_000) return this.token.value;
    const { tenantId, clientId, clientSecret } = this.config;
    const body = new URLSearchParams({ client_id: clientId, client_secret: clientSecret, grant_type: "client_credentials", scope: "https://graph.microsoft.com/.default" });
    const result = await fetchJSON(`https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body, source: "Intune sign-in", fetchImpl: this.fetchImpl
    });
    if (!result?.access_token) throw new ConnectorError("Intune sign-in: no access token returned", { source: "intune" });
    this.token = { value: result.access_token, expiresAt: Date.now() + Number(result.expires_in ?? 3600) * 1000 };
    return this.token.value;
  }

  async graph(pathOrUrl, extraHeaders = {}) {
    const url = pathOrUrl.startsWith("https://") ? pathOrUrl : `${GRAPH}${pathOrUrl}`;
    if (!url.startsWith(`${GRAPH}/`) && !url.startsWith(`${GRAPH_BETA}/`)) throw new ConnectorError("Intune: refused to follow a non-Graph link", { source: "intune" });
    return fetchJSON(url, { headers: { authorization: `Bearer ${await this.accessToken()}`, ...extraHeaders }, source: "Intune", fetchImpl: this.fetchImpl });
  }

  async pages(first, headers = {}, limit = 100_000) {
    const items = [];
    let next = first;
    while (next && items.length < limit) {
      const page = await this.graph(next, headers);
      items.push(...(page.value ?? []));
      next = page["@odata.nextLink"] ?? null;
    }
    return items;
  }

  // Entra ID group membership, only for the groups that queries and rules mention
  // (e.g. f/ EntityName = "GRP-Intune-Users-France-Finland"). Nested groups count.
  // wanted: [{ op: "=" | "starts_with" | "contains", value }]
  async fetchGroups(wanted) {
    const capability = this.capabilities.groups;
    if (!wanted.length) { this.groups = { wanted: [], members: {}, fetched_at: null }; capability.finish("disabled"); return this.groups; }
    capability.begin();
    try {
      const odata = (value) => String(value).replace(/'/g, "''");
      const found = new Map();
      for (const { op, value } of wanted.slice(0, 25)) {
        const groups = op === "contains"
          ? await this.pages(`/groups?$search=${encodeURIComponent(`"displayName:${String(value).replace(/"/g, "")}"`)}&$select=id,displayName&$top=50`, { ConsistencyLevel: "eventual" }, 50)
          : await this.pages(`/groups?$filter=${encodeURIComponent(op === "starts_with" ? `startswith(displayName,'${odata(value)}')` : `displayName eq '${odata(value)}'`)}&$select=id,displayName&$top=50`, {}, 50);
        for (const group of groups) found.set(group.id, group.displayName);
      }
      const members = {};
      let done = 0;
      for (const [id, name] of [...found].slice(0, 50)) {
        this.report("groups", `Group members ${done} of ${found.size} groups`);
        const users = await this.pages(`/groups/${encodeURIComponent(id)}/transitiveMembers/microsoft.graph.user?$select=userPrincipalName,mail&$top=999`, { ConsistencyLevel: "eventual" });
        for (const user of users) for (const address of new Set([user.userPrincipalName, user.mail].filter(Boolean).map((item) => item.toLowerCase()))) (members[address] ??= []).push(name);
        done += 1;
      }
      this.report("groups", null);
      capability.count = found.size;
      capability.finish("ok");
      this.groups = { wanted, members, fetched_at: new Date().toISOString(), group_names: [...found.values()] };
    } catch (error) {
      capability.finish(error.status === 403 ? "no_permission" : "error", error.message);
      this.groupsError = error.message;
    }
    return this.groups;
  }

  // Live progress for the dashboard and Terminal ("Hosts 2,000 of 4,512 · …").
  report(part, text) {
    this.progressParts = { ...(this.progressParts ?? {}), [part]: text };
    this.onProgress?.(Object.values(this.progressParts).filter(Boolean).join(" · "));
  }

  async listManagedDevices() {
    const devices = [];
    let next = `/deviceManagement/managedDevices?$select=${DEVICE_FIELDS}&$top=500`;
    while (next) {
      const page = await this.graph(next);
      devices.push(...(page.value ?? []));
      this.report("devices", `Devices ${fmt(devices.length)}${page["@odata.nextLink"] ? "…" : ""}`);
      next = page["@odata.nextLink"] ?? null;
    }
    return devices;
  }

  async detectedApps(deviceId) {
    try {
      const result = await this.graph(`/deviceManagement/managedDevices/${encodeURIComponent(deviceId)}?$select=id&$expand=detectedApps`);
      return result.detectedApps ?? [];
    } catch {
      return null; // App inventory is best-effort; device posture still counts.
    }
  }

  // Remediation (device health script) results are only exposed on the Graph beta endpoint.
  async kbReports() {
    if (!this.config.kbScriptId) return new Map();
    const reports = new Map();
    let next = `${GRAPH_BETA}/deviceManagement/deviceHealthScripts/${this.config.kbScriptId}/deviceRunStates?$expand=managedDevice($select=id)&$top=500`;
    while (next) {
      const page = await this.graph(next);
      for (const state of page.value ?? []) {
        const kbs = parseKbOutput(state.preRemediationDetectionScriptOutput);
        const deviceId = state.managedDevice?.id;
        if (kbs && deviceId) reports.set(deviceId, { kbs, at: state.lastStateUpdateDateTime ?? null });
      }
      next = page["@odata.nextLink"] ?? null;
    }
    return reports;
  }

  // Discovered-app lists are the slow part (one Graph call per device). They only change
  // when a device syncs, so they are reused while lastSyncDateTime is unchanged.
  exportState() {
    return { apps: Object.fromEntries(this.appCache ?? new Map()), groups: this.groups };
  }

  importState(state) {
    this.appCache = new Map(Object.entries(state?.apps ?? {}));
    if (state?.groups?.members) this.groups = state.groups;
  }

  async collect({ full = false } = {}) {
    this.progressParts = {};
    this.appCache ??= new Map();
    let kbReports = new Map();
    if (this.config.kbScriptId) {
      this.capabilities.kb_reports.begin();
      try {
        kbReports = await this.kbReports();
        this.capabilities.kb_reports.count = kbReports.size;
        this.capabilities.kb_reports.finish("ok");
      } catch (error) {
        this.kbError = error.message; // device posture still syncs without exact KB data
        this.capabilities.kb_reports.finish(error.status === 403 ? "no_permission" : "error", error.message);
      }
    }
    this.capabilities.devices.begin();
    const raw = (await this.listManagedDevices().catch((error) => { this.capabilities.devices.finish("error", error.message); throw error; })).filter((device) => ["windows", "macos"].includes(normalizeIntunePlatform(device.operatingSystem)));
    let fetched = 0;
    const toFetch = raw.filter((device) => { const cached = this.appCache.get(device.id); return full || !cached || cached.last_sync !== device.lastSyncDateTime; }).length;
    if (this.config.includeApps) this.report("apps", toFetch ? `Installed apps 0 of ${fmt(toFetch)} PCs` : "Installed apps unchanged");
    const apps = this.config.includeApps ? await mapLimit(raw, this.config.appConcurrency, async (device) => {
      const cached = this.appCache.get(device.id);
      if (!full && cached && cached.last_sync === device.lastSyncDateTime && Array.isArray(cached.apps)) return cached.apps;
      fetched += 1;
      if (fetched % 10 === 0 || fetched === toFetch) this.report("apps", `Installed apps ${fmt(fetched)} of ${fmt(toFetch)} PCs`);
      const result = await this.detectedApps(device.id);
      if (Array.isArray(result)) this.appCache.set(device.id, { last_sync: device.lastSyncDateTime, apps: result });
      return result ?? cached?.apps ?? null;
    }) : raw.map(() => null);
    const present = new Set(raw.map((device) => device.id));
    for (const id of this.appCache.keys()) if (!present.has(id)) this.appCache.delete(id);
    this.capabilities.devices.sync_mode = full || !this.config.includeApps ? "full" : `apps refreshed for ${fetched} of ${raw.length} devices`;
    const records = raw.map((device, index) => {
      this.capabilities.devices.observe(device);
      const record = { ...normalizeIntuneDevice(device, apps[index]), raw: device };
      const report = kbReports.get(device.id);
      if (report) Object.assign(record, { reported_kbs: report.kbs, reported_kbs_at: report.at });
      return record;
    });
    this.capabilities.devices.finish("ok");
    return records;
  }
}
