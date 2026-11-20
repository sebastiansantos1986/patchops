// Read-only Microsoft Intune connector (Microsoft Graph v1.0, app-only auth).
//
// Required Entra ID application permissions (admin consent):
//   DeviceManagementManagedDevices.Read.All
// Optional, for exact installed-KB lists from the PatchOps Remediation script:
//   DeviceManagementConfiguration.Read.All   (+ INTUNE_KB_SCRIPT_ID)
// Nothing here writes to Intune.

import { ConnectorError, fetchJSON, mapLimit } from "./http.mjs";
import { Capability } from "./inspect.mjs";

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
      kb_reports: new Capability("Installed KB reports (Remediation)", "DeviceManagementConfiguration.Read.All")
    };
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

  async graph(pathOrUrl) {
    const url = pathOrUrl.startsWith("https://") ? pathOrUrl : `${GRAPH}${pathOrUrl}`;
    if (!url.startsWith(`${GRAPH}/`) && !url.startsWith(`${GRAPH_BETA}/`)) throw new ConnectorError("Intune: refused to follow a non-Graph link", { source: "intune" });
    return fetchJSON(url, { headers: { authorization: `Bearer ${await this.accessToken()}` }, source: "Intune", fetchImpl: this.fetchImpl });
  }

  async listManagedDevices() {
    const devices = [];
    let next = `/deviceManagement/managedDevices?$select=${DEVICE_FIELDS}&$top=500`;
    while (next) {
      const page = await this.graph(next);
      devices.push(...(page.value ?? []));
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

  async collect() {
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
    const apps = this.config.includeApps ? await mapLimit(raw, this.config.appConcurrency, (device) => this.detectedApps(device.id)) : raw.map(() => null);
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
