// Read-only Jamf Pro connector (Jamf Pro API, computers-inventory).
//
// Preferred auth: an API Role + API Client (OAuth client credentials) with
//   Read Computers  (and optionally Read Computer Inventory Collection)
// A standard Jamf user (JAMF_USERNAME / JAMF_PASSWORD) also works as a fallback.
// Nothing here writes to Jamf.

import { ConnectorError, fetchJSON } from "./http.mjs";
import { Capability } from "./inspect.mjs";
const fmt = (value) => Number(value).toLocaleString("en-US");


const SECTIONS = ["GENERAL", "HARDWARE", "OPERATING_SYSTEM", "DISK_ENCRYPTION", "SECURITY", "USER_AND_LOCATION", "APPLICATIONS", "EXTENSION_ATTRIBUTES"];

// Extension attributes can appear at the top level and inside sections; collect them all.
export function jamfExtensionAttributes(computer) {
  const found = [];
  const visit = (value, depth) => {
    if (!value || typeof value !== "object" || depth > 2) return;
    for (const [key, child] of Object.entries(value)) {
      if (key === "extensionAttributes" && Array.isArray(child)) {
        for (const attribute of child) if (attribute?.name) found.push({ name: String(attribute.name), value: (attribute.values ?? [attribute.value]).filter((item) => item !== null && item !== undefined && item !== "").join(", ") });
      } else if (!Array.isArray(child)) visit(child, depth + 1);
    }
  };
  visit(computer, 0);
  return [...new Map(found.map((attribute) => [attribute.name.toLowerCase(), attribute])).values()];
}

export const normalizeArchitecture = (value) => {
  const text = String(value ?? "").toLowerCase();
  if (/arm64|aarch64|apple/.test(text)) return "arm64";
  if (/x86_64|x64|amd64|i386|intel/.test(text)) return "x86_64";
  return "";
};

export function jamfConfig(env = process.env) {
  const config = {
    url: env.JAMF_URL?.trim().replace(/\/+$/, ""),
    clientId: env.JAMF_CLIENT_ID?.trim(),
    clientSecret: env.JAMF_CLIENT_SECRET?.trim(),
    username: env.JAMF_USERNAME?.trim(),
    password: env.JAMF_PASSWORD,
    pageSize: Math.max(50, Math.min(Number(env.JAMF_PAGE_SIZE) || 200, 1000))
  };
  config.configured = Boolean(config.url && ((config.clientId && config.clientSecret) || (config.username && config.password)));
  return config;
}

const flag = (value, enabledValues = ["ENABLED"]) => {
  if (value === true || value === false) return value;
  const text = String(value ?? "").toUpperCase();
  if (!text || text === "NOT_COLLECTED" || text === "UNKNOWN") return null;
  if (text === "DISABLED") return false;
  return enabledValues.includes(text) || text.startsWith("APP_STORE");
};

export function jamfEncryption(computer) {
  const status = String(computer.operatingSystem?.fileVault2Status ?? "").toUpperCase();
  if (status === "ALL_ENCRYPTED" || status === "BOOT_ENCRYPTED") return true;
  if (status === "NOT_ENCRYPTED" || status === "SOME_ENCRYPTED") return false;
  const partition = String(computer.diskEncryption?.bootPartitionEncryptionDetails?.partitionFileVault2State ?? "").toUpperCase();
  if (partition === "ENCRYPTED") return true;
  if (["UNENCRYPTED", "NOT_ENCRYPTED", "DECRYPTED", "DECRYPTING"].includes(partition)) return false;
  return null;
}

export function normalizeJamfComputer(computer) {
  const general = computer.general ?? {};
  const hardware = computer.hardware ?? {};
  const os = computer.operatingSystem ?? {};
  const security = computer.security ?? {};
  const person = computer.userAndLocation ?? {};
  return {
    source: "jamf",
    source_id: String(computer.id ?? ""),
    hostname: general.name ?? "",
    serial_number: hardware.serialNumber ?? "",
    platform: "macos",
    model: hardware.model ?? hardware.modelIdentifier ?? "",
    manufacturer: "Apple",
    os: { name: "macOS", version: os.version ?? "", build: os.build ?? "" },
    user: { name: person.realname || person.username || "", email: person.email ?? "" },
    last_check_in: general.lastContactTime ?? general.reportDate ?? null,
    enrolled_at: general.lastEnrolledDate ?? null,
    managed: general.remoteManagement?.managed !== false,
    compliance: "unknown",
    encrypted: jamfEncryption(computer),
    security: {
      sip: flag(security.sipStatus),
      gatekeeper: flag(security.gatekeeperStatus),
      firewall: typeof security.firewallEnabled === "boolean" ? security.firewallEnabled : null
    },
    ownership: "",
    architecture: normalizeArchitecture(hardware.processorArchitecture ?? hardware.processorType),
    extension_attributes: jamfExtensionAttributes(computer),
    apps: Array.isArray(computer.applications)
      ? computer.applications.map((app) => ({ name: String(app.name ?? "").replace(/\.app$/i, ""), version: app.version ?? "", publisher: "", bundle_id: app.bundleId ?? "" })).filter((app) => app.name)
      : null
  };
}

export class JamfConnector {
  constructor(config = jamfConfig(), { fetchImpl } = {}) {
    this.config = config;
    this.fetchImpl = fetchImpl;
    this.token = null;
    this.capabilities = { computers: new Capability("Computer inventory", "Read Computers") };
  }

  async accessToken() {
    if (this.token && this.token.expiresAt > Date.now() + 60_000) return this.token.value;
    const { url, clientId, clientSecret, username, password } = this.config;
    let token;
    let lifetimeSeconds = 1200;
    if (clientId && clientSecret) {
      const result = await fetchJSON(`${url}/api/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, grant_type: "client_credentials" }),
        source: "Jamf sign-in",
        fetchImpl: this.fetchImpl
      });
      token = result?.access_token;
      lifetimeSeconds = Number(result?.expires_in ?? lifetimeSeconds);
    } else {
      const result = await fetchJSON(`${url}/api/v1/auth/token`, {
        method: "POST",
        headers: { authorization: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}` },
        source: "Jamf sign-in",
        fetchImpl: this.fetchImpl
      });
      token = result?.token;
      if (result?.expires) lifetimeSeconds = Math.max(60, (Date.parse(result.expires) - Date.now()) / 1000);
    }
    if (!token) throw new ConnectorError("Jamf sign-in: no access token returned", { source: "jamf" });
    this.token = { value: token, expiresAt: Date.now() + lifetimeSeconds * 1000 };
    return token;
  }


  // Live progress for the dashboard and Terminal ("Hosts 2,000 of 4,512 · …").
  report(part, text) {
    this.progressParts = { ...(this.progressParts ?? {}), [part]: text };
    this.onProgress?.(Object.values(this.progressParts).filter(Boolean).join(" · "));
  }

  async listComputers() {
    const computers = [];
    const sections = SECTIONS.map((section) => `section=${section}`).join("&");
    for (let page = 0; ; page += 1) {
      const result = await fetchJSON(`${this.config.url}/api/v1/computers-inventory?${sections}&page=${page}&page-size=${this.config.pageSize}&sort=id%3Aasc`, {
        headers: { authorization: `Bearer ${await this.accessToken()}` },
        source: "Jamf",
        fetchImpl: this.fetchImpl
      });
      const results = result?.results ?? [];
      computers.push(...results);
      this.report("computers", `Computers ${fmt(computers.length)} of ${fmt(result?.totalCount ?? computers.length)}`);
      if (!results.length || computers.length >= Number(result?.totalCount ?? 0)) break;
    }
    return computers;
  }

  async collect() {
    this.progressParts = {};
    const capability = this.capabilities.computers;
    capability.begin();
    try {
      const records = (await this.listComputers()).map((computer) => {
        capability.observe(computer);
        const { applications: _applications, ...raw } = computer;
        return { ...normalizeJamfComputer(computer), raw };
      });
      capability.finish("ok");
      return records;
    } catch (error) {
      capability.finish("error", error.message);
      throw error;
    }
  }
}
