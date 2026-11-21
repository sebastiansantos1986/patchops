// Relay: a local PatchOps (which holds the Intune / Jamf / CrowdStrike credentials) uploads the
// device records it synced to a hosted PatchOps, so the hosted copy shows the full fleet without
// ever having the credentials. The relay token can only upload records; it can't read anything.
import { createHash, timingSafeEqual } from "node:crypto";
import { gunzipSync, gzipSync } from "node:zlib";

export const RELAY_SOURCES = ["intune", "jamf", "crowdstrike"];
const MAX_COMPRESSED = 40 * 1024 * 1024;
const MAX_JSON = 250 * 1024 * 1024;
const MAX_RECORDS = 100_000;
const yes = (value) => /^(1|true|yes|on)$/i.test(String(value ?? "").trim());

// Sender settings (local PatchOps): where to upload and what to include.
export function relayConfig(env = process.env) {
  const url = String(env.PATCHOPS_RELAY_URL ?? "").trim().replace(/\/+$/, "");
  const token = String(env.PATCHOPS_RELAY_TOKEN ?? "").trim();
  return {
    url: url && !/\/api$/.test(url) ? `${url}/api` : url,
    token,
    enabled: Boolean(url && token),
    includeVulnerabilities: yes(env.PATCHOPS_RELAY_VULNERABILITIES),
    includeUsers: yes(env.PATCHOPS_RELAY_USERS)
  };
}

// Receiver side (hosted PatchOps): constant-time check of "Authorization: Relay <token>".
export function relayAuthorized(header, expected) {
  if (!expected || expected.length < 24) return false;
  const match = /^Relay\s+(.+)$/i.exec(String(header ?? "").trim());
  if (!match) return false;
  const digest = (value) => createHash("sha256").update(value).digest();
  return timingSafeEqual(digest(match[1].trim()), digest(expected));
}

// What leaves the local machine: no raw API payloads (IP/MAC addresses, internal IDs), and no
// user names or vulnerabilities unless they were switched on.
export function relayRecord(record, { includeVulnerabilities = false, includeUsers = false } = {}) {
  const { raw: _raw, ...rest } = record;
  if (!includeVulnerabilities) delete rest.vulnerabilities;
  if (!includeUsers) rest.user = { name: "", email: "" };
  return rest;
}

export function buildRelaySnapshot(source, { records, status = {}, capabilities = {}, userGroups = null }, options = {}, sender = "") {
  return {
    version: 1,
    source,
    sender: String(sender).slice(0, 80),
    sent_at: new Date().toISOString(),
    synced_at: status.synced_at ?? null,
    options: { vulnerabilities: Boolean(options.includeVulnerabilities), users: Boolean(options.includeUsers) },
    // Only the summary of each data type: no sample records or example values.
    capabilities: Object.fromEntries(Object.entries(capabilities ?? {}).map(([name, capability]) => [name, {
      label: capability.label, scope: capability.scope, state: capability.state, count: capability.count ?? 0, error: capability.error ?? null,
      fields: (capability.fields ?? []).map(({ field, filled, pct }) => ({ field, filled, pct })), samples: []
    }])),
    ...(source === "intune" && options.includeUsers && userGroups ? { user_groups: userGroups } : {}),
    records: records.map((record) => relayRecord(record, options))
  };
}

export async function sendRelaySnapshot(config, snapshot, { fetchImpl = globalThis.fetch, timeoutMs = 150_000 } = {}) {
  const body = gzipSync(JSON.stringify(snapshot), { level: 6 });
  const response = await fetchImpl(`${config.url}/relay/snapshot`, {
    method: "POST",
    headers: { authorization: `Relay ${config.token}`, "content-type": "application/json", "content-encoding": "gzip" },
    body,
    signal: AbortSignal.timeout(timeoutMs)
  });
  const text = await response.text();
  if (!response.ok) {
    let message = text.slice(0, 200);
    try { message = JSON.parse(text).error ?? message; } catch { /* plain text */ }
    const error = new Error(`hosted PatchOps answered ${response.status}: ${message}`);
    error.status = response.status;
    throw error;
  }
  return { bytes: body.length, ...JSON.parse(text || "{}") };
}

// Reads and checks an uploaded snapshot (gzip or plain JSON, size-limited).
export async function readRelaySnapshot(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_COMPRESSED) throw Object.assign(new Error("snapshot is too large"), { status: 413 });
    chunks.push(chunk);
  }
  let buffer = Buffer.concat(chunks);
  if (/gzip/i.test(request.headers["content-encoding"] ?? "")) buffer = gunzipSync(buffer, { maxOutputLength: MAX_JSON });
  const input = JSON.parse(buffer.toString("utf8"));
  if (input?.version !== 1 || !RELAY_SOURCES.includes(input.source)) throw Object.assign(new Error("unknown snapshot format or source"), { status: 400 });
  if (!Array.isArray(input.records) || input.records.length > MAX_RECORDS) throw Object.assign(new Error("records must be a list"), { status: 400 });
  const records = input.records.filter((record) => record && typeof record === "object" && !Array.isArray(record)).map((record) => {
    const { raw: _raw, ...rest } = record;
    return { ...rest, source: input.source }; // a snapshot can only describe its own source
  });
  return {
    source: input.source,
    sender: String(input.sender ?? "").slice(0, 80),
    sent_at: typeof input.sent_at === "string" ? input.sent_at.slice(0, 40) : null,
    synced_at: typeof input.synced_at === "string" ? input.synced_at.slice(0, 40) : null,
    options: { vulnerabilities: Boolean(input.options?.vulnerabilities), users: Boolean(input.options?.users) },
    capabilities: input.capabilities && typeof input.capabilities === "object" ? input.capabilities : {},
    user_groups: input.source === "intune" && input.user_groups && typeof input.user_groups === "object" ? input.user_groups : null,
    records
  };
}
