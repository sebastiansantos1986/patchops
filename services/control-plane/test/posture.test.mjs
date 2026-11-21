import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { loadEnvFile } from "../src/env-file.mjs";
import { IntuneConnector, intuneConfig, normalizeIntuneDevice } from "../src/integrations/intune.mjs";
import { JamfConnector, jamfConfig, normalizeJamfComputer } from "../src/integrations/jamf.mjs";
import { appKey, computePosture, deviceKey, macReleaseIndex, mergeRecords } from "../src/posture-engine.mjs";
import { PostureService } from "../src/posture-service.mjs";
import { Store } from "../src/store.mjs";

const NOW = Date.parse("2026-11-19T18:00:00Z");
const daysAgo = (days) => new Date(NOW - days * 86_400_000).toISOString();
const record = (overrides) => ({
  source: "intune", source_id: "x", hostname: "HOST", serial_number: "SERIAL12345", platform: "windows", model: "", manufacturer: "",
  os: { name: "Windows 11", version: "10.0.26100.7171", build: "" }, user: { name: "", email: "" }, last_check_in: daysAgo(1),
  managed: true, compliance: "compliant", encrypted: true, security: {}, ownership: "", apps: null, ...overrides
});

test("devices are correlated across sources by serial number", () => {
  const merged = mergeRecords([
    record({ source: "jamf", platform: "macos", serial_number: "c02abc123xyz", hostname: "MAC-1", os: { name: "macOS", version: "26.1" }, compliance: "unknown", security: { sip: true } }),
    record({ source: "intune", platform: "macos", serial_number: "C02ABC123XYZ", hostname: "mac-1", os: { name: "macOS", version: "26.1" }, compliance: "noncompliant" }),
    record({ source: "agent", platform: "macos", serial_number: "C02-ABC123XYZ", hostname: "mac-1", apps: [{ name: "Slack", version: "4.47.59" }] })
  ]);
  assert.equal(merged.length, 1);
  assert.deepEqual(Object.keys(merged[0].sources).sort(), ["agent", "intune", "jamf"]);
  assert.equal(merged[0].compliance, "noncompliant");
  assert.equal(merged[0].apps_source, "agent");
});

test("placeholder serial numbers fall back to hostname matching", () => {
  assert.equal(deviceKey({ serial_number: "To be filled by O.E.M.", hostname: "WIN-01.corp.example.com" }), "host:win-01");
  assert.equal(deviceKey({ serial_number: "0", hostname: "" , source: "intune", source_id: "abc" }), "src:intune:abc");
});

test("macOS release ordering handles the jump from 15 to 26", () => {
  assert.equal(macReleaseIndex(26) - macReleaseIndex(15), 1);
  const posture = computePosture([
    record({ source: "jamf", serial_number: "MACA00001", platform: "macos", os: { name: "macOS", version: "26.1" }, compliance: "unknown" }),
    record({ source: "jamf", serial_number: "MACA00002", platform: "macos", os: { name: "macOS", version: "14.8.2" }, compliance: "unknown" }),
    record({ source: "jamf", serial_number: "MACA00003", platform: "macos", os: { name: "macOS", version: "13.7.8" }, compliance: "unknown" })
  ], { now: NOW, connected: { jamf: true } });
  const status = Object.fromEntries(posture.devices.map((device) => [device.os.version, device.os_status]));
  assert.equal(status["26.1"], "current");
  assert.equal(status["14.8.2"], "older_release");
  assert.equal(status["13.7.8"], "unsupported");
});

test("risk checks flag encryption, Windows 10, compliance, stale devices and lagging apps", () => {
  const posture = computePosture([
    record({ serial_number: "WINA00001", hostname: "GOOD", apps: [{ name: "Google Chrome", version: "142.0.7444.135" }] }),
    record({ serial_number: "WINA00002", hostname: "BAD", encrypted: false, compliance: "noncompliant", last_check_in: daysAgo(40), os: { name: "Windows 10", version: "10.0.19045.6456" }, apps: [{ name: "Google Chrome", version: "138.0.7204.184" }] })
  ], { now: NOW, connected: { intune: true } });
  const bad = posture.devices.find((device) => device.hostname === "BAD");
  const good = posture.devices.find((device) => device.hostname === "GOOD");
  assert.deepEqual(bad.issues.map((issue) => issue.id).sort(), ["apps_outdated", "noncompliant", "not_encrypted", "os_unsupported", "stale"]);
  assert.equal(bad.apps_behind[0].severity, "high");
  assert.equal(bad.risk_score, 100);
  assert.equal(good.risk_level, "healthy");
  assert.equal(posture.summary.encrypted_pct, 50);
  assert.equal(posture.summary.healthy_pct, 50);
});

test("approved PatchOps baselines override fleet-newest app targets", () => {
  const catalog = [{ identity: "windows:google chrome", platform: "windows", name: "Google Chrome", approved_version: "143.0.0.0", severity: "critical" }];
  const posture = computePosture([record({ serial_number: "WINA00009", apps: [{ name: "Google Chrome", version: "142.0.7444.135" }] })], { now: NOW, catalog });
  assert.equal(posture.devices[0].apps_behind[0].target_source, "approved_baseline");
  assert.equal(posture.devices[0].apps_behind[0].severity, "critical");
  assert.equal(appKey("7-Zip 25.01 (x64)"), "7-zip");
});

test("missing MDM enrollment is reported only once that MDM is connected", () => {
  const orphan = record({ source: "agent", serial_number: "WINA00042" });
  assert.ok(!computePosture([orphan], { now: NOW }).devices[0].issues.some((issue) => issue.id === "missing_mdm"));
  assert.ok(computePosture([orphan], { now: NOW, connected: { intune: true } }).devices[0].issues.some((issue) => issue.id === "missing_mdm"));
});

test("Intune and Jamf payloads normalize into the shared device shape", () => {
  const intune = normalizeIntuneDevice({ id: "1", deviceName: "WIN-1", serialNumber: "ABC12345", operatingSystem: "Windows", osVersion: "10.0.22631.6199", complianceState: "noncompliant", isEncrypted: false, lastSyncDateTime: daysAgo(2), userPrincipalName: "a@example.com", jailBroken: "Unknown" }, [{ displayName: "Zoom", version: "6.6.6" }]);
  assert.equal(intune.platform, "windows");
  assert.equal(intune.os.name, "Windows 11");
  assert.equal(intune.encrypted, false);
  assert.equal(intune.apps[0].name, "Zoom");
  const jamf = normalizeJamfComputer({ id: 7, general: { name: "MAC-7", lastContactTime: daysAgo(1), remoteManagement: { managed: true } }, hardware: { serialNumber: "C02XYZ" }, operatingSystem: { version: "26.1", fileVault2Status: "NOT_ENCRYPTED" }, security: { sipStatus: "ENABLED", gatekeeperStatus: "DISABLED", firewallEnabled: true }, applications: [{ name: "Slack.app", version: "4.47.59", bundleId: "com.tinyspeck.slackmacgap" }] });
  assert.equal(jamf.encrypted, false);
  assert.deepEqual(jamf.security, { sip: true, gatekeeper: false, firewall: true });
  assert.equal(jamf.apps[0].name, "Slack");
});

test("connectors page through Graph and Jamf with app-only tokens", async () => {
  const calls = [];
  const json = (body) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  const fetchImpl = async (url, init) => {
    calls.push([init.method ?? "GET", String(url)]);
    if (url.includes("login.microsoftonline.com")) return json({ access_token: "graph-token", expires_in: 3600 });
    if (url.includes("/oauth/token")) return json({ access_token: "jamf-token", expires_in: 1200 });
    if (url.includes("managedDevices?$select")) return json({ value: [{ id: "a", operatingSystem: "Windows", serialNumber: "S1AAAAA", osVersion: "10.0.26100.1" }], "@odata.nextLink": "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=2" });
    if (url.includes("$skiptoken=2")) return json({ value: [{ id: "b", operatingSystem: "iOS", serialNumber: "S2AAAAA" }] });
    if (url.includes("$expand=detectedApps")) return json({ id: "a", detectedApps: [{ displayName: "Zoom", version: "6.6.6" }] });
    if (url.includes("computers-inventory") && url.includes("page=0")) return json({ totalCount: 2, results: [{ id: 1, hardware: { serialNumber: "M1AAAAA" } }] });
    if (url.includes("computers-inventory") && url.includes("page=1")) return json({ totalCount: 2, results: [{ id: 2, hardware: { serialNumber: "M2AAAAA" } }] });
    throw new Error(`unexpected ${url}`);
  };
  const intune = await new IntuneConnector(intuneConfig({ INTUNE_TENANT_ID: "t", INTUNE_CLIENT_ID: "c", INTUNE_CLIENT_SECRET: "s" }), { fetchImpl }).collect();
  assert.equal(intune.length, 1, "mobile devices are excluded");
  assert.equal(intune[0].apps[0].name, "Zoom");
  const jamf = await new JamfConnector(jamfConfig({ JAMF_URL: "https://acme.jamfcloud.com/", JAMF_CLIENT_ID: "c", JAMF_CLIENT_SECRET: "s" }), { fetchImpl }).collect();
  assert.deepEqual(jamf.map((item) => item.serial_number), ["M1AAAAA", "M2AAAAA"]);
  assert.equal(calls.filter(([, url]) => url.includes("/oauth/token")).length, 1, "Jamf token is reused across pages");
  assert.ok(calls.every(([method, url]) => method === "GET" || url.includes("token")), "connectors only read data");
});

test("sample mode is used until a connector is configured, and sync failures surface without losing data", async () => {
  const sample = await new PostureService(new Store(), { env: {}, now: () => NOW }).overview();
  assert.equal(sample.mode, "sample");
  assert.ok(sample.summary.devices > 50);
  assert.equal(sample.trend.length, 30);

  let fail = false;
  const connector = { collect: async () => { if (fail) throw new Error("Jamf: credentials were rejected"); return [record({ source: "jamf", platform: "macos", serial_number: "MACB00001", os: { name: "macOS", version: "26.1" } })]; } };
  let clock = NOW;
  const service = new PostureService(new Store(), { env: {}, connectors: { jamf: connector }, now: () => clock });
  const live = await service.overview();
  assert.equal(live.mode, "live");
  assert.equal(live.sources.jamf.state, "ok");
  assert.equal(live.sources.intune.state, "not_configured");
  fail = true;
  clock += 60 * 60_000;
  await service.sync({ force: true });
  const afterFailure = await service.overview();
  assert.equal(afterFailure.sources.jamf.state, "stale");
  assert.match(afterFailure.sources.jamf.error, /rejected/);
  assert.equal(afterFailure.summary.devices, 1);
});

test("CSV export neutralises spreadsheet formulas", async () => {
  const service = new PostureService(new Store(), { env: {}, connectors: { intune: { collect: async () => [record({ hostname: "=HYPERLINK(\"x\")", serial_number: "WINC00001" })] } }, now: () => NOW });
  const csv = await service.csv();
  assert.match(csv, /"'=HYPERLINK\(""x""\)"/);
});

test(".env loader reads values without overriding the real environment", () => {
  const directory = mkdtempSync(join(tmpdir(), "patchops-env-"));
  const file = join(directory, ".env");
  writeFileSync(file, "# comment\nJAMF_URL=https://acme.jamfcloud.com\nINTUNE_CLIENT_SECRET=\"abc#123\"\nEXISTING=from-file\n");
  const env = { EXISTING: "from-shell" };
  assert.equal(loadEnvFile(file, env), 2);
  assert.equal(env.JAMF_URL, "https://acme.jamfcloud.com");
  assert.equal(env.INTUNE_CLIENT_SECRET, "abc#123");
  assert.equal(env.EXISTING, "from-shell");
});

test("posture API requires a session and reviewers cannot trigger a sync", async () => {
  const { createApp } = await import("../src/server.mjs");
  const store = new Store();
  store.createConsoleUser({ username: "viewer", role: "reviewer", status: "active", password_hash: (await import("../src/auth.mjs")).hashPassword("viewer-password-123") });
  const server = createApp(store, { enrollmentToken: "e", dashboardUsername: "owner", dashboardPassword: "owner-password", sessionSecret: "s", env: {} });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}/api`;
  const login = async (username, password) => (await (await fetch(`${base}/auth/login`, { method: "POST", body: JSON.stringify({ username, password }) })).json()).token;
  try {
    assert.equal((await fetch(`${base}/posture`)).status, 401);
    const owner = await login("owner", "owner-password");
    const overview = await (await fetch(`${base}/posture`, { headers: { authorization: `Bearer ${owner}` } })).json();
    assert.equal(overview.mode, "sample");
    assert.equal(overview.devices[0].apps, undefined, "device list omits full app inventories");
    const detail = await fetch(`${base}/posture/devices/${encodeURIComponent(overview.devices[0].id)}`, { headers: { authorization: `Bearer ${owner}` } });
    assert.ok(Array.isArray((await detail.json()).apps));
    const csv = await fetch(`${base}/posture/export.csv`, { headers: { authorization: `Bearer ${owner}` } });
    assert.match(csv.headers.get("content-type"), /text\/csv/);
    const reviewer = await login("viewer", "viewer-password-123");
    assert.equal((await fetch(`${base}/posture`, { headers: { authorization: `Bearer ${reviewer}` } })).status, 200);
    assert.equal((await fetch(`${base}/posture/sync`, { method: "POST", headers: { authorization: `Bearer ${reviewer}` } })).status, 403);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
