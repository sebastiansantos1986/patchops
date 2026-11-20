import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluateSoftwareRule, evaluateTrackedPatch, sanitizeDashboard, sanitizeTrackedPatch } from "../src/fleet-config.mjs";
import { parseQuery, runQuery } from "../src/fleet-query.mjs";
import { parseKbOutput } from "../src/integrations/intune.mjs";
import { computePosture } from "../src/posture-engine.mjs";
import { PostureService } from "../src/posture-service.mjs";
import { Store } from "../src/store.mjs";

const NOW = Date.parse("2026-11-19T18:00:00Z");
const daysAgo = (days) => new Date(NOW - days * 86_400_000).toISOString();
const win = (serial, version, extra = {}) => ({ source: "intune", source_id: serial, hostname: serial, serial_number: serial, platform: "windows", os: { name: "Windows", version }, user: { name: "", email: "" }, last_check_in: daysAgo(1), managed: true, compliance: "compliant", encrypted: true, security: {}, apps: [], ...extra });
const mac = (serial, version, apps, extra = {}) => ({ source: "jamf", source_id: serial, hostname: serial, serial_number: serial, platform: "macos", os: { name: "macOS", version }, user: { name: "", email: "" }, last_check_in: daysAgo(1), managed: true, compliance: "unknown", encrypted: true, security: {}, apps, ...extra });

test("cumulative KBs are inferred from the Windows build revision", () => {
  const patch = sanitizeTrackedPatch({ kb: "5099701", builds: "10.0.26100.7171, 26200.7171" });
  assert.equal(patch.kb, "KB5099701");
  assert.deepEqual(patch.builds, ["26100.7171", "26200.7171"]);
  assert.equal(evaluateTrackedPatch(patch, { platform: "windows", os: { version: "10.0.26100.7171" } }).status, "installed");
  assert.equal(evaluateTrackedPatch(patch, { platform: "windows", os: { version: "10.0.26100.7300" } }).status, "installed", "a later cumulative update includes it");
  const missing = evaluateTrackedPatch(patch, { platform: "windows", os: { version: "10.0.26100.6899" } });
  assert.equal(missing.status, "missing");
  assert.equal(missing.required_build, "26100.7171");
  assert.equal(evaluateTrackedPatch(patch, { platform: "windows", os: { version: "10.0.22631.6199" } }).status, "not_applicable");
  assert.equal(evaluateTrackedPatch(patch, { platform: "windows", os: { version: "10.0.26100.6899" }, reported_kbs: ["KB5099701"] }).status, "installed", "exact report wins");
  const dotnet = sanitizeTrackedPatch({ kb: "KB5098950" });
  assert.equal(evaluateTrackedPatch(dotnet, { platform: "windows", os: { version: "10.0.26100.1" } }).status, "unknown");
  assert.equal(evaluateTrackedPatch(dotnet, { platform: "windows", os: { version: "10.0.26100.1" }, reported_kbs: [] }).status, "missing");
});

test("Remediation script output is parsed into KB lists", () => {
  assert.deepEqual(parseKbOutput("PATCHOPS_KBS:KB5099701,kb5098950,KB5099701"), ["KB5099701", "KB5098950"]);
  assert.equal(parseKbOutput("something else"), null);
});

test("software rules report installed, missing and unknown inventory", () => {
  const rule = { name: "Okta Verify", macos: ["Okta Verify"], windows: ["Okta Verify"] };
  assert.equal(evaluateSoftwareRule(rule, { platform: "macos", apps_source: "jamf", apps: [{ name: "Okta Verify" }] }).status, "installed");
  assert.equal(evaluateSoftwareRule(rule, { platform: "macos", apps_source: "jamf", apps: [] }).status, "missing");
  assert.equal(evaluateSoftwareRule(rule, { platform: "macos", apps_source: null, apps: [] }).status, "unknown");
  assert.equal(evaluateSoftwareRule({ name: "x", macos: ["x"], windows: [] }, { platform: "windows", apps_source: "agent", apps: [] }).status, "not_applicable");
});

test("Cyclops-style queries, including CrowdStrike field aliases and relations", () => {
  const rules = [{ id: "rule_okta", name: "Okta Verify", mode: "required", severity: "high", macos: ["Okta Verify"], windows: ["Okta Verify"] }];
  const patches = [sanitizeTrackedPatch({ kb: "KB5099701", builds: ["26100.7171"] })];
  const posture = computePosture([
    win("WIN11OK001", "10.0.26100.7171", { apps: [{ name: "Okta Verify", version: "6.6" }] }),
    win("WIN11OLD01", "10.0.26100.6899", { last_check_in: daysAgo(10) }),
    win("WIN10OLD01", "10.0.19045.6456"),
    mac("MACOK00001", "26.1", [{ name: "Okta Verify", version: "9" }]),
    mac("MACNO00001", "15.7.2", [{ name: "Slack", version: "4" }])
  ], { now: NOW, softwareRules: rules, trackedPatches: patches });
  const run = (query) => runQuery(query, posture.devices, { now: NOW }).map((device) => device.hostname).sort();

  assert.deepEqual(run("e/ Device f/ CrowdstrikeFalconOSDistribution = 11 f/ FalconSpotlightOSType = windows f/  LastSeenAt  < 7d"), ["WIN11OK001"]);
  assert.deepEqual(run("e/ Device f/ CrowdstrikeFalconOSDistribution = 11 f/ FalconSpotlightOSType = windows r/ ( e/ SecurityPatch f/ UniquePatchId contains_any (KB5099701,KB5132059)) f/  LastSeenAt  < 7d"), ["WIN11OK001"]);
  assert.deepEqual(run("e/ Device f/ Platform = windows r/ ( e/ MissingPatch )"), ["WIN11OLD01"]);
  assert.deepEqual(run('e/ Device not r/ ( e/ SoftwareRule f/ Name = "Okta Verify" f/ Status = installed )'), ["MACNO00001", "WIN10OLD01", "WIN11OLD01"]);
  assert.deepEqual(run("e/ Device f/ Platform = mac f/ OSVersion < 26"), ["MACNO00001"]);
  assert.deepEqual(run("e/ Device f/ LastSeenAt > 7d or e/ Device f/ OSRelease = 10"), ["WIN10OLD01", "WIN11OLD01"]);
  assert.deepEqual(run("e/ Device f/ Hostname in (WIN11OK001, MACOK00001)"), ["MACOK00001", "WIN11OK001"]);
  assert.deepEqual(run("e/ Device r/ ( e/ App f/ Name contains slack )"), ["MACNO00001"]);
  assert.deepEqual(run("e/ Device f/ Encrypted = yes f/ RiskScore >= 0 f/ Email not_exists"), ["MACNO00001", "MACOK00001", "WIN10OLD01", "WIN11OK001", "WIN11OLD01"]);
});

test("query errors point at the problem", () => {
  assert.throws(() => parseQuery("e/ Device f/ Nope = 1"), /Unknown field "Nope".*character 14/);
  assert.throws(() => parseQuery("e/ Laptop"), /Unknown entity/);
  assert.throws(() => parseQuery("e/ Device f/ Platform windows"), /Expected an operator/);
  assert.throws(() => parseQuery("e/ Device r/ ( e/ App f/ Name = x"), /Expected "\)"/);
  assert.throws(() => parseQuery("e/ App f/ Name = x"), /must start with "e\/ Device"/);
  assert.throws(() => parseQuery("e/ Device r/ ( e/ Device )"), /no related Device/);
});

test("dashboards are validated and invalid widgets are dropped", () => {
  const dashboard = sanitizeDashboard({ name: "  Mine ", widgets: [{ title: "A", type: "weird", series: [{ label: "x", query: "e/ Device" }] }, { title: "empty", series: [] }] });
  assert.equal(dashboard.name, "Mine");
  assert.equal(dashboard.widgets.length, 1);
  assert.equal(dashboard.widgets[0].type, "donut");
  assert.equal(sanitizeDashboard({ name: "" }), null);
});

test("service: default dashboards, saved rules and invalid queries", async () => {
  const service = new PostureService(new Store(), { env: {}, now: () => NOW });
  const config = await service.configSummary();
  assert.ok(config.dashboards.some((dashboard) => dashboard.name === "IT - Security Agents Status"));
  assert.ok(config.tracked_patches_are_sample);
  const agents = await service.dashboardData("dash_security_agents");
  const falcon = agents.widgets.find((widget) => widget.title.startsWith("CrowdStrike"));
  assert.equal(falcon.type, "donut");
  assert.ok(falcon.series.every((series) => Number.isInteger(series.count)));
  const removal = agents.widgets.find((widget) => widget.type === "trend");
  assert.equal(removal.series[0].trend.length, 14);
  assert.equal(removal.series[0].trend.at(-1).count, removal.series[0].count);

  await assert.rejects(service.saveDashboard({ name: "Bad", widgets: [{ title: "x", series: [{ label: "y", query: "e/ Device f/ Nope = 1" }] }] }), /Unknown field/);
  const saved = await service.saveDashboard({ name: "Exec", widgets: [{ title: "Macs", type: "number", series: [{ label: "Macs", query: "e/ Device f/ Platform = macos" }] }] });
  const data = await service.dashboardData(saved.id);
  assert.equal(data.widgets[0].series[0].count, (await service.query("e/ Device f/ Platform = macos")).count);

  await service.saveTrackedPatches([{ kb: "KB5099701", builds: ["26100.7171"] }, { kb: "not-a-kb" }]);
  assert.equal((await service.configSummary()).tracked_patches.length, 1);
  await service.saveSoftwareRules([{ name: "Zoom", macos: ["zoom.us"], windows: ["Zoom"] }]);
  assert.deepEqual((await service.configSummary()).software_rules.map((rule) => rule.name), ["Zoom"]);
  assert.ok(await service.deleteDashboard(saved.id));
});

test("fleet API enforces roles", async () => {
  const { createApp } = await import("../src/server.mjs");
  const { hashPassword } = await import("../src/auth.mjs");
  const store = new Store();
  store.createConsoleUser({ username: "viewer", role: "reviewer", status: "active", password_hash: hashPassword("viewer-password-123") });
  const server = createApp(store, { enrollmentToken: "e", dashboardUsername: "owner", dashboardPassword: "owner-password", sessionSecret: "s", env: {} });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}/api`;
  const login = async (username, password) => (await (await fetch(`${base}/auth/login`, { method: "POST", body: JSON.stringify({ username, password }) })).json()).token;
  const call = (path, token, init = {}) => fetch(`${base}${path}`, { ...init, headers: { authorization: `Bearer ${token}` } });
  try {
    assert.equal((await fetch(`${base}/fleet/config`)).status, 401);
    const owner = await login("owner", "owner-password");
    const reviewer = await login("viewer", "viewer-password-123");
    const query = await call("/fleet/query", reviewer, { method: "POST", body: JSON.stringify({ query: "e/ Device f/ Platform = windows", group_by: "OSRelease" }) });
    assert.equal(query.status, 200);
    assert.ok((await query.json()).groups.length);
    const bad = await call("/fleet/query", owner, { method: "POST", body: JSON.stringify({ query: "e/ Device f/" }) });
    assert.equal(bad.status, 400);
    assert.match((await bad.json()).message, /field name/);
    assert.equal((await call("/fleet/dashboards", reviewer, { method: "POST", body: JSON.stringify({ dashboard: { name: "x", widgets: [] } }) })).status, 403);
    assert.equal((await call("/fleet/dashboards", owner, { method: "POST", body: JSON.stringify({ dashboard: { name: "x", widgets: [] } }) })).status, 200);
    assert.equal((await call("/fleet/dashboards/dash_security_agents", reviewer)).status, 200);
    assert.equal((await call("/fleet/dashboards/dash_security_agents", reviewer, { method: "DELETE" })).status, 403);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("built-in Apple apps are not compared across Macs, Safari still is", async () => {
  const { computePosture: compute } = await import("../src/posture-engine.mjs");
  const posture = compute([
    mac("MACAPPLE01", "26.1", [{ name: "Contacts", version: "14.0", bundle_id: "com.apple.AddressBook" }, { name: "Safari", version: "18.0", bundle_id: "com.apple.Safari" }, { name: "Forcepoint DLP Endpoint", version: "30.8.136", bundle_id: "com.forcepoint.dlp" }]),
    mac("MACAPPLE02", "26.1", [{ name: "Contacts", version: "2539.13", bundle_id: "com.apple.AddressBook" }, { name: "Safari", version: "19.1", bundle_id: "com.apple.Safari" }, { name: "Forcepoint DLP Endpoint", version: "30.9.208", bundle_id: "com.forcepoint.dlp" }])
  ], { now: NOW });
  const behind = posture.devices.find((device) => device.hostname === "MACAPPLE01").apps_behind.map((app) => app.name).sort();
  assert.deepEqual(behind, ["Forcepoint DLP Endpoint", "Safari"]);
});

test("widgets warn when a query names a software rule that does not exist", async () => {
  const service = new PostureService(new Store(), { env: {}, now: () => NOW });
  const saved = await service.saveDashboard({ name: "Rules", widgets: [{ title: "Forcepoint", type: "donut", series: [{ label: "a", query: 'e/ Device r/ ( e/ SoftwareRule f/ Name = "Forcepoint DLP Endpoint" f/ Status = installed )' }, { label: "b", query: 'e/ Device r/ ( e/ SoftwareRule f/ Name = "Okta Verify" f/ Status = missing )' }] }] });
  let data = await service.dashboardData(saved.id);
  assert.match(data.widgets[0].warning, /No software rule named "Forcepoint DLP Endpoint"/);
  const rules = (await service.fleetConfig()).software_rules;
  await service.saveSoftwareRules([...rules, { name: "Forcepoint DLP Endpoint", macos: ["Forcepoint DLP Endpoint"], windows: ["Forcepoint DLP Endpoint"] }]);
  data = await service.dashboardData(saved.id);
  assert.equal(data.widgets[0].warning, null);
});

test("CrowdStrike connector discovers the cloud, pages hosts and skips servers", async () => {
  const { CrowdStrikeConnector, crowdstrikeConfig, crowdstrikeOsVersion } = await import("../src/integrations/crowdstrike.mjs");
  const calls = [];
  const json = (body, headers = {}) => new Response(JSON.stringify(body), { status: 201, headers: { "content-type": "application/json", ...headers } });
  const fetchImpl = async (url, init = {}) => {
    calls.push([init.method ?? "GET", String(url)]);
    if (url === "https://api.crowdstrike.com/oauth2/token") return json({ access_token: "wrong-cloud", expires_in: 1799 }, { "x-cs-region": "us-2" });
    if (url === "https://api.us-2.crowdstrike.com/oauth2/token") return json({ access_token: "us2-token", expires_in: 1799 }, { "x-cs-region": "us-2" });
    assert.equal(init.headers.authorization, "Bearer us2-token");
    const offset = new URL(url).searchParams.get("offset");
    if (!offset) return new Response(JSON.stringify({ meta: { pagination: { total: 3, next: "cursor-2" } }, resources: [
      { device_id: "a", hostname: "WIN-1", serial_number: "S1", platform_name: "Windows", kernel_version: "10.0.26100.7171", product_type_desc: "Workstation", last_seen: daysAgo(1), agent_version: "7.30", reduced_functionality_mode: "no", status: "normal" },
      { device_id: "b", hostname: "SRV-1", serial_number: "S2", platform_name: "Windows", os_build: "20348", product_type_desc: "Server", last_seen: daysAgo(1) }
    ] }), { status: 200 });
    if (offset === "cursor-2") return new Response(JSON.stringify({ meta: { pagination: { total: 3 } }, resources: [
      { device_id: "c", hostname: "MAC-1", serial_number: "C02X", platform_name: "Mac", major_version: "15", minor_version: "6", product_type_desc: "Workstation", last_seen: daysAgo(9), reduced_functionality_mode: "yes", status: "contained" }
    ] }), { status: 200 });
    throw new Error(`unexpected ${url}`);
  };
  const hosts = await new CrowdStrikeConnector(crowdstrikeConfig({ CROWDSTRIKE_CLIENT_ID: "id", CROWDSTRIKE_CLIENT_SECRET: "secret" }), { fetchImpl }).collect();
  assert.deepEqual(hosts.map((host) => host.hostname), ["WIN-1", "MAC-1"]);
  assert.equal(hosts[0].os.version, "10.0.26100.7171");
  assert.equal(hosts[1].sensor.rfm, true);
  assert.equal(hosts[1].sensor.contained, true);
  assert.ok(calls.every(([method, url]) => method === "GET" || url.endsWith("/oauth2/token")), "read-only");
  assert.deepEqual(crowdstrikeOsVersion({ platform_name: "Windows", os_build: "22631" }), { version: "10.0.22631", approximate: true });
});

test("CrowdStrike coverage issues and query fields", async () => {
  const falcon = (serial, platform, seenDays, sensor = {}) => ({ source: "crowdstrike", source_id: `cs-${serial}`, hostname: serial, serial_number: serial, platform, os: { name: "", version: platform === "macos" ? "26" : "10.0.26100" }, os_approximate: true, user: { name: "", email: "" }, last_check_in: daysAgo(seenDays), managed: true, compliance: "unknown", encrypted: null, security: {}, apps: null, sensor: { version: "7.30", rfm: false, status: "normal", contained: false, ...sensor } });
  const posture = computePosture([
    mac("MACCS00001", "26.1", []), falcon("MACCS00001", "macos", 1),
    mac("MACCS00002", "26.1", []), falcon("MACCS00002", "macos", 12),
    mac("MACCS00003", "26.1", []),
    win("WINCS00001", "10.0.26100.7171"), falcon("WINCS00001", "windows", 0, { rfm: true })
  ], { now: NOW, connected: { crowdstrike: true, jamf: true } });
  const byHost = Object.fromEntries(posture.devices.map((device) => [device.hostname, device]));
  assert.equal(byHost.MACCS00001.os.version, "26.1", "precise Jamf version wins over Falcon's partial one");
  assert.ok(byHost.MACCS00002.issues.some((issue) => issue.id === "crowdstrike_not_reporting"));
  assert.ok(byHost.MACCS00003.issues.some((issue) => issue.id === "crowdstrike_missing"));
  assert.ok(byHost.WINCS00001.issues.some((issue) => issue.id === "crowdstrike_rfm"));
  const run = (query) => runQuery(query, posture.devices, { now: NOW }).map((device) => device.hostname).sort();
  assert.deepEqual(run("e/ Device f/ LastSeenAt < 7d f/ CrowdStrikeReporting = false"), ["MACCS00002", "MACCS00003"]);
  assert.deepEqual(run("e/ Device f/ CrowdStrikeRFM = true"), ["WINCS00001"]);
  assert.deepEqual(run("e/ Device f/ FalconLastSeen > 7d"), ["MACCS00002"]);
});

test("CrowdStrike apps and CVEs are optional and a missing scope is reported, not fatal", async () => {
  const { CrowdStrikeConnector, crowdstrikeConfig } = await import("../src/integrations/crowdstrike.mjs");
  const respond = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const make = (spotlightStatus) => async (url) => {
    const path = new URL(url).pathname;
    if (path === "/oauth2/token") return respond({ access_token: "t", expires_in: 1799 }, 201);
    if (path === "/devices/combined/devices/v1") return respond({ meta: { pagination: { total: 1 } }, resources: [{ device_id: "aid-1", hostname: "WIN-9", serial_number: "S9", platform_name: "Windows", kernel_version: "10.0.26100.7171", product_type_desc: "Workstation", last_seen: daysAgo(0), client_secret_thing: "x" }] });
    if (path === "/discover/combined/applications/v1") return respond({ meta: { pagination: {} }, resources: [
      { name: "Forcepoint DLP Endpoint", version: "30.8.136", vendor: "Forcepoint", software_type: "application", host: { aid: "aid-1" } },
      { name: "Some Extension", version: "1", software_type: "browser_extension", host: { aid: "aid-1" } }
    ] });
    if (path === "/spotlight/combined/vulnerabilities/v1") {
      if (spotlightStatus !== 200) return respond({ errors: [{ code: spotlightStatus, message: "access denied, authorization failed" }] }, spotlightStatus);
      return respond({ meta: { pagination: { after: null } }, resources: [
        { aid: "aid-1", status: "open", cve: { id: "CVE-2025-1111", severity: "CRITICAL", base_score: 9.8, exprt_rating: "HIGH", exploit_status: 90 }, apps: [{ product_name_version: "Windows 11" }], remediation: { entities: [{ title: "Install KB5099701 for Windows 11" }] } }
      ] });
    }
    throw new Error(`unexpected ${url}`);
  };
  const ok = new CrowdStrikeConnector(crowdstrikeConfig({ CROWDSTRIKE_CLIENT_ID: "a", CROWDSTRIKE_CLIENT_SECRET: "b", CROWDSTRIKE_CLOUD: "us-1" }), { fetchImpl: make(200) });
  const [host] = await ok.collect();
  assert.deepEqual(host.apps.map((app) => app.name), ["Forcepoint DLP Endpoint"], "browser extensions skipped");
  assert.equal(host.vulnerabilities[0].severity, "critical");
  assert.equal(host.vulnerabilities[0].exploit, "Actively used");
  assert.deepEqual(host.vulnerabilities[0].kbs, ["KB5099701"]);
  assert.equal(ok.capabilities.hosts.toJSON().samples[0].client_secret_thing, "[redacted]");
  assert.ok(ok.capabilities.hosts.toJSON().fields.some((field) => field.field === "kernel_version" && field.pct === 100));

  const denied = new CrowdStrikeConnector(crowdstrikeConfig({ CROWDSTRIKE_CLIENT_ID: "a", CROWDSTRIKE_CLIENT_SECRET: "b", CROWDSTRIKE_CLOUD: "us-1" }), { fetchImpl: make(403) });
  const [deniedHost] = await denied.collect();
  assert.equal(deniedHost.vulnerabilities, undefined, "no CVE data rather than 'zero CVEs'");
  assert.equal(denied.capabilities.vulnerabilities.state, "no_permission");
  assert.match(denied.capabilities.vulnerabilities.error, /Vulnerabilities: Read/);

  const posture = computePosture([{ ...host }], { now: NOW });
  const run = (query) => runQuery(query, posture.devices, { now: NOW }).length;
  assert.equal(run("e/ Device r/ ( e/ Vulnerability f/ CVE = CVE-2025-1111 f/ Score >= 9 )"), 1);
  assert.equal(run("e/ Device r/ ( e/ MissingPatch f/ UniquePatchId = KB5099701 f/ Method = spotlight )"), 1);
  assert.equal(run("e/ Device f/ ExploitedCVEs > 0"), 1);
  assert.equal(posture.devices[0].issues[0].severity, "critical");
  assert.equal(posture.vulnerabilities.list[0].devices, 1);
});

test("Spotlight sends facets as repeated parameters and falls back on 400s with Falcon's message", async () => {
  const { CrowdStrikeConnector, crowdstrikeConfig } = await import("../src/integrations/crowdstrike.mjs");
  const seen = [];
  const respond = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const fetchImpl = async (url) => {
    const parsed = new URL(url);
    if (parsed.pathname === "/oauth2/token") return respond({ access_token: "t", expires_in: 1799 }, 201);
    if (parsed.pathname === "/devices/combined/devices/v1") return respond({ meta: { pagination: { total: 1 } }, resources: [{ device_id: "aid-1", hostname: "W", serial_number: "S1", platform_name: "Windows", kernel_version: "10.0.26100.1", product_type_desc: "Workstation", last_seen: daysAgo(0) }] });
    if (parsed.pathname === "/discover/combined/applications/v1") return respond({ meta: { pagination: {} }, resources: [] });
    seen.push({ facets: parsed.searchParams.getAll("facet"), filter: parsed.searchParams.get("filter") });
    if (parsed.searchParams.get("filter") !== "status:'open'" || parsed.searchParams.getAll("facet").includes("host_info")) return respond({ errors: [{ code: 400, message: "Invalid filter or facet" }] }, 400);
    return respond({ meta: { pagination: {} }, resources: [{ aid: "aid-1", cve: { id: "CVE-2025-2222", severity: "HIGH" } }] });
  };
  const connector = new CrowdStrikeConnector(crowdstrikeConfig({ CROWDSTRIKE_CLIENT_ID: "a", CROWDSTRIKE_CLIENT_SECRET: "b", CROWDSTRIKE_CLOUD: "us-1" }), { fetchImpl });
  const [host] = await connector.collect();
  assert.deepEqual(seen[0].facets, ["cve", "remediation", "host_info"]);
  assert.equal(host.vulnerabilities[0].cve, "CVE-2025-2222");
  assert.deepEqual(connector.capabilities.vulnerabilities.query, { filter: "status:'open'", facet: ["cve", "remediation"] });

  const failing = new CrowdStrikeConnector(crowdstrikeConfig({ CROWDSTRIKE_CLIENT_ID: "a", CROWDSTRIKE_CLIENT_SECRET: "b", CROWDSTRIKE_CLOUD: "us-1" }), { fetchImpl: async (url) => new URL(url).pathname.startsWith("/spotlight") ? respond({ errors: [{ code: 400, message: "filter is required" }] }, 400) : fetchImpl(url) });
  await failing.collect();
  assert.match(failing.capabilities.vulnerabilities.error, /filter is required/);
});
