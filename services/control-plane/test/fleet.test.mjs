import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluateSoftwareRule, evaluateTrackedPatch, sanitizeDashboard, sanitizeTrackedPatch } from "../src/fleet-config.mjs";
import { parseQuery, runQuery } from "../src/fleet-query.mjs";
import { IntuneConnector, intuneConfig, parseKbOutput } from "../src/integrations/intune.mjs";
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
  assert.deepEqual(seen[0].facets, ["cve", "remediation"], "repeated parameters, without the heavy host_info facet");
  assert.equal(host.vulnerabilities[0].cve, "CVE-2025-2222");
  assert.deepEqual(connector.capabilities.vulnerabilities.query, { filter: "status:'open'", facet: ["cve", "remediation"] });

  const failing = new CrowdStrikeConnector(crowdstrikeConfig({ CROWDSTRIKE_CLIENT_ID: "a", CROWDSTRIKE_CLIENT_SECRET: "b", CROWDSTRIKE_CLOUD: "us-1" }), { fetchImpl: async (url) => new URL(url).pathname.startsWith("/spotlight") ? respond({ errors: [{ code: 400, message: "filter is required" }] }, 400) : fetchImpl(url) });
  await failing.collect();
  assert.match(failing.capabilities.vulnerabilities.error, /filter is required/);
});

test("Apple (SOFA), Microsoft (MSRC) and CISA KEV feeds produce OS CVEs and real baselines", async () => {
  const { readFileSync } = await import("node:fs");
  const { CveFeeds, FEED_URLS, macCvesFor, parseSofa } = await import("../src/integrations/cve-feeds.mjs");
  const sofaFeed = JSON.parse(readFileSync(new URL("./fixtures/sofa-macos-sample.json", import.meta.url), "utf8"));
  const sofa = parseSofa(sofaFeed);
  assert.equal(sofa[26].latest, "26.7.3");
  const onTahoe = macCvesFor("26.7.1", sofa).map((entry) => entry.cve);
  assert.ok(onTahoe.includes("CVE-2026-111497"), "fixed in 26.7.3, so a 26.7.1 Mac is missing it");
  assert.equal(macCvesFor("26.7.3", sofa).length, 0);
  assert.equal(macCvesFor("12.7.6", sofa), null, "majors not in the feed are unknown, not clean");

  const cvrf = {
    ProductTree: { FullProductName: [{ ProductID: "11", Value: "Windows 11 Version 25H2 for x64-based Systems" }, { ProductID: "99", Value: "Windows Server 2025" }] },
    Vulnerability: [
      { CVE: "CVE-2026-50001", Title: { Value: "Windows Kernel Elevation of Privilege" }, Threats: [{ Type: 3, ProductID: ["11"], Description: { Value: "Important" } }, { Type: 1, Description: { Value: "Publicly Disclosed:No;Exploited:Yes;" } }], CVSSScoreSets: [{ BaseScore: 7.8, ProductID: ["11"] }], Remediations: [{ Type: 2, Description: { Value: "5070001" }, FixedBuild: "10.0.26200.9974", ProductID: ["11"] }, { Type: 2, Description: { Value: "5070009" }, FixedBuild: "10.0.26100.9974", ProductID: ["99"] }] },
      { CVE: "CVE-2026-50002", Title: { Value: "Old fix" }, Threats: [{ Type: 3, ProductID: ["11"], Description: { Value: "Critical" } }], Remediations: [{ Type: 2, Description: { Value: "5060001" }, FixedBuild: "10.0.26200.9457", ProductID: ["11"] }] }
    ]
  };
  const json = (body) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  const fetchImpl = async (url) => {
    if (url === FEED_URLS.sofa[0]) return json(sofaFeed);
    if (url === FEED_URLS.msrcUpdates) return json({ value: [{ ID: "2026-Nov", InitialReleaseDate: "2026-11-10T08:00:00Z", CvrfUrl: "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Nov" }, { ID: "2019-Jan", InitialReleaseDate: "2019-01-08T08:00:00Z", CvrfUrl: "https://example.invalid/old" }] });
    if (url.endsWith("/2026-Nov")) return json(cvrf);
    if (url === FEED_URLS.kev) return json({ vulnerabilities: [{ cveID: "CVE-2026-111497", vendorProject: "Google", product: "Brotli", dateAdded: "2026-10-27" }] });
    throw new Error(`unexpected ${url}`);
  };
  const feeds = new CveFeeds({ enabled: true, msrcMonths: 12, refreshHours: 24 }, { fetchImpl, now: () => NOW });
  await feeds.refresh();
  assert.ok(Object.values(feeds.capabilities).every((capability) => capability.state === "ok"));
  assert.deepEqual(feeds.baselines().winLatestUbrByBuild, { 26200: 9974 }, "server products ignored");

  const posture = computePosture([
    mac("MACFEED001", "26.7.1", []),
    mac("MACFEED002", "27.2.1", []),
    win("WINFEED001", "10.0.26200.9711"),
    win("WINFEED002", "10.0.26200.9974")
  ], { now: NOW, cveFeeds: feeds, osSettings: feeds.baselines() });
  const byHost = Object.fromEntries(posture.devices.map((device) => [device.hostname, device]));
  const macVuln = byHost.MACFEED001.vulnerabilities.find((vuln) => vuln.cve === "CVE-2026-111497");
  assert.equal(macVuln.kev, true);
  assert.equal(macVuln.severity, "critical");
  assert.deepEqual(macVuln.sources, ["apple"]);
  assert.equal(byHost.MACFEED001.os_status, "update_available", "26.7.3 is Apple's latest Tahoe even if no Mac runs it");
  assert.equal(byHost.MACFEED002.vulnerabilities.length, 0);
  const winVulns = byHost.WINFEED001.vulnerabilities.map((vuln) => vuln.cve);
  assert.deepEqual(winVulns, ["CVE-2026-50001"], "only fixes newer than the device's revision");
  assert.equal(byHost.WINFEED001.vulnerabilities[0].kbs[0], "KB5070001");
  assert.ok(byHost.WINFEED001.issues.some((issue) => issue.id === "cves" && issue.severity === "critical"), "exploited per Microsoft");
  const run = (query) => runQuery(query, posture.devices, { now: NOW }).map((device) => device.hostname).sort();
  assert.deepEqual(run("e/ Device r/ ( e/ Vulnerability f/ Source contains microsoft )"), ["WINFEED001"]);
  assert.deepEqual(run("e/ Device r/ ( e/ Vulnerability f/ CVE = CVE-2026-111497 )"), ["MACFEED001"]);
});

test("feed outages are reported per source and never break posture", async () => {
  const { CveFeeds } = await import("../src/integrations/cve-feeds.mjs");
  const feeds = new CveFeeds({ enabled: true, msrcMonths: 3, refreshHours: 24 }, { fetchImpl: async () => new Response("nope", { status: 503 }), now: () => NOW });
  await feeds.refresh();
  assert.equal(feeds.capabilities.apple.state, "error");
  assert.match(feeds.capabilities.microsoft.error, /503/);
  assert.equal(feeds.ready, false);
});

test("CrowdStrike Darwin versions on Macs are translated to macOS versions", async () => {
  const { crowdstrikeOsVersion } = await import("../src/integrations/crowdstrike.mjs");
  assert.equal(crowdstrikeOsVersion({ platform_name: "Mac", major_version: "25", minor_version: "6" }).version, "26.6");
  assert.equal(crowdstrikeOsVersion({ platform_name: "Mac", major_version: "24", minor_version: "6" }).version, "15.6");
  assert.equal(crowdstrikeOsVersion({ platform_name: "Mac", kernel_version: "22.6.0" }).version, "13.6");
  assert.equal(crowdstrikeOsVersion({ platform_name: "Mac", major_version: "15", minor_version: "6" }).version, "15.6");
  const posture = computePosture([mac("MACZERO001", "26.5.0", [])], { now: NOW });
  assert.equal(posture.devices[0].os.version, "26.5");
});

test("disk cache: private files, atomic writes, restart serves saved data without re-downloading", async () => {
  const { mkdtempSync, statSync, readdirSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { DiskCache } = await import("../src/disk-cache.mjs");
  const dir = join(mkdtempSync(join(tmpdir(), "patchops-cache-")), "cache");
  const cache = new DiskCache({ enabled: true, dir });
  let calls = 0;
  const connector = { collect: async () => { calls += 1; return [mac("MACCACHE01", "26.1", [])]; }, exportState: () => ({ cursor: "x" }), importState(state) { this.imported = state; } };
  const first = new PostureService(new Store(), { env: {}, connectors: { jamf: connector }, diskCache: cache, now: () => NOW });
  await first.overview();
  await cache.writes.get("connectors");
  assert.equal(calls, 1);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.equal(statSync(join(dir, "connectors.json.gz")).mode & 0o777, 0o600);
  assert.ok(!readdirSync(dir).some((name) => name.endsWith(".tmp")));

  const restarted = new PostureService(new Store(), { env: {}, connectors: { jamf: connector }, diskCache: cache, now: () => NOW + 60_000 });
  const overview = await restarted.overview();
  assert.equal(calls, 1, "restart within the sync interval does not re-download");
  assert.equal(overview.summary.devices, 1);
  assert.equal(overview.sources.jamf.from_cache, true);
  assert.deepEqual(connector.imported, { cursor: "x" });
});

test("Intune re-reads discovered apps only for devices that synced since last time", async () => {
  const appCalls = [];
  let lastSync = daysAgo(1);
  const json = (body) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  const fetchImpl = async (url) => {
    if (url.includes("login.microsoftonline.com")) return json({ access_token: "t", expires_in: 3600 });
    if (url.includes("managedDevices?$select")) return json({ value: [{ id: "a", operatingSystem: "Windows", serialNumber: "SA00001", osVersion: "10.0.26100.1", lastSyncDateTime: daysAgo(1) }, { id: "b", operatingSystem: "Windows", serialNumber: "SB00001", osVersion: "10.0.26100.1", lastSyncDateTime: lastSync }] });
    if (url.includes("$expand=detectedApps")) { appCalls.push(url.includes("/a?") ? "a" : "b"); return json({ detectedApps: [{ displayName: "Zoom", version: "6" }] }); }
    throw new Error(`unexpected ${url}`);
  };
  const connector = new IntuneConnector(intuneConfig({ INTUNE_TENANT_ID: "t", INTUNE_CLIENT_ID: "c", INTUNE_CLIENT_SECRET: "s" }), { fetchImpl });
  await connector.collect();
  assert.deepEqual(appCalls.sort(), ["a", "b"]);
  const saved = JSON.parse(JSON.stringify(connector.exportState()));
  const again = new IntuneConnector(intuneConfig({ INTUNE_TENANT_ID: "t", INTUNE_CLIENT_ID: "c", INTUNE_CLIENT_SECRET: "s" }), { fetchImpl });
  again.importState(saved);
  appCalls.length = 0;
  lastSync = new Date(NOW).toISOString();
  const records = await again.collect();
  assert.deepEqual(appCalls, ["b"], "only the device that synced again");
  assert.equal(records.find((item) => item.source_id === "a").apps[0].name, "Zoom", "cached apps reused");
  appCalls.length = 0;
  await again.collect({ full: true });
  assert.equal(appCalls.length, 2, "a full resync re-reads everything");
});

test("CrowdStrike CVEs sync incrementally: changed findings only, closed ones removed, 400 falls back to full", async () => {
  const { CrowdStrikeConnector, crowdstrikeConfig } = await import("../src/integrations/crowdstrike.mjs");
  const filters = [];
  let incrementalSupported = true;
  const respond = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const fetchImpl = async (url) => {
    const parsed = new URL(url);
    if (parsed.pathname === "/oauth2/token") return respond({ access_token: "t", expires_in: 1799 }, 201);
    if (parsed.pathname === "/devices/combined/devices/v1") return respond({ meta: { pagination: { total: 1 } }, resources: [{ device_id: "aid-1", hostname: "W", serial_number: "S1", platform_name: "Windows", kernel_version: "10.0.26100.1", product_type_desc: "Workstation", last_seen: daysAgo(0) }] });
    if (parsed.pathname === "/discover/combined/applications/v1") return respond({ meta: { pagination: {} }, resources: [] });
    const filter = parsed.searchParams.get("filter");
    filters.push(filter);
    if (filter.startsWith("updated_timestamp")) {
      if (!incrementalSupported) return respond({ errors: [{ message: "invalid filter" }] }, 400);
      return respond({ meta: { pagination: {} }, resources: [{ id: "v1", aid: "aid-1", status: "closed", cve: { id: "CVE-2026-1" } }, { id: "v3", aid: "aid-1", status: "open", cve: { id: "CVE-2026-3", severity: "HIGH" } }] });
    }
    return respond({ meta: { pagination: {} }, resources: [{ id: "v1", aid: "aid-1", status: "open", cve: { id: "CVE-2026-1", severity: "CRITICAL" } }, { id: "v2", aid: "aid-1", status: "open", cve: { id: "CVE-2026-2", severity: "LOW" } }] });
  };
  const config = crowdstrikeConfig({ CROWDSTRIKE_CLIENT_ID: "a", CROWDSTRIKE_CLIENT_SECRET: "b", CROWDSTRIKE_CLOUD: "us-1" });
  const connector = new CrowdStrikeConnector(config, { fetchImpl });
  let [host] = await connector.collect();
  assert.deepEqual(host.vulnerabilities.map((vuln) => vuln.cve).sort(), ["CVE-2026-1", "CVE-2026-2"]);
  assert.equal(connector.capabilities.vulnerabilities.sync_mode, "full");

  const restored = new CrowdStrikeConnector(config, { fetchImpl });
  restored.importState(JSON.parse(JSON.stringify(connector.exportState())));
  [host] = await restored.collect();
  assert.deepEqual(host.vulnerabilities.map((vuln) => vuln.cve).sort(), ["CVE-2026-2", "CVE-2026-3"], "closed removed, new added, unchanged kept");
  assert.equal(restored.capabilities.vulnerabilities.sync_mode, "incremental");
  assert.match(filters.at(-1), /^updated_timestamp:>'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z'$/);

  incrementalSupported = false;
  [host] = await restored.collect();
  assert.equal(restored.capabilities.vulnerabilities.sync_mode, "full (incremental filter not supported)");
  assert.deepEqual(host.vulnerabilities.map((vuln) => vuln.cve).sort(), ["CVE-2026-1", "CVE-2026-2"]);
});

test("public feeds: unchanged files are not downloaded again and Microsoft months are reused", async () => {
  const { CveFeeds, FEED_URLS } = await import("../src/integrations/cve-feeds.mjs");
  const requests = [];
  const sofaFeed = { OSVersions: [{ OSVersion: "Tahoe 26", Latest: { ProductVersion: "26.7.3" }, SecurityReleases: [{ ProductVersion: "26.7.3", CVEs: { "CVE-2026-9": false }, ActivelyExploitedCVEs: [] }] }] };
  const fetchImpl = async (url, init) => {
    requests.push([url, init.headers["if-none-match"] ?? null]);
    const json = (body, headers = {}) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json", ...headers } });
    if (url === FEED_URLS.sofa[0]) return init.headers["if-none-match"] === "\"sofa-1\"" ? new Response(null, { status: 304 }) : json(sofaFeed, { etag: "\"sofa-1\"" });
    if (url === FEED_URLS.kev) return init.headers["if-none-match"] === "\"kev-1\"" ? new Response(null, { status: 304 }) : json({ vulnerabilities: [{ cveID: "CVE-2026-9" }] }, { etag: "\"kev-1\"" });
    if (url === FEED_URLS.msrcUpdates) return json({ value: [{ ID: "2026-Nov", InitialReleaseDate: "2026-11-10T08:00:00Z", CurrentReleaseDate: "2026-11-10T08:00:00Z", CvrfUrl: "https://msrc.example/2026-Nov" }] });
    if (url === "https://msrc.example/2026-Nov") return json({ ProductTree: { FullProductName: [{ ProductID: "1", Value: "Windows 11 Version 25H2 for x64-based Systems" }] }, Vulnerability: [{ CVE: "CVE-2026-50001", Remediations: [{ Type: 2, Description: { Value: "5070001" }, FixedBuild: "10.0.26200.9974", ProductID: ["1"] }] }] });
    throw new Error(`unexpected ${url}`);
  };
  const settings = { enabled: true, msrcMonths: 12, refreshHours: 24 };
  const first = new CveFeeds(settings, { fetchImpl, now: () => NOW });
  await first.refresh();
  const second = new CveFeeds(settings, { fetchImpl, now: () => NOW + 86_400_000 * 2 });
  second.importState(JSON.parse(JSON.stringify(first.exportState())));
  assert.equal(second.windowsCves, undefined);
  requests.length = 0;
  await second.refresh();
  assert.ok(!requests.some(([url]) => url === "https://msrc.example/2026-Nov"), "unchanged month not downloaded");
  assert.equal(second.capabilities.apple.sync_mode, "unchanged (not downloaded)");
  assert.equal(second.capabilities.kev.sync_mode, "unchanged (not downloaded)");
  assert.equal(second.osCves({ platform: "windows", os: { name: "Windows 11", version: "10.0.26200.9711" } })[0].cve, "CVE-2026-50001");
  assert.equal(second.osCves({ platform: "macos", os: { version: "26.7.1" } })[0].kev, true);
});

test("the dashboard never waits for a sync: progress is shown and each source appears as it finishes", async () => {
  let releaseSlow;
  const fast = { collect: async () => { fast.onProgress?.("Computers 1 of 1"); return [mac("MACFAST001", "26.1", [])]; } };
  const slow = { collect: () => new Promise((resolve) => { slow.onProgress?.("Installed apps 3 of 900 PCs"); releaseSlow = () => resolve([win("WINSLOW001", "10.0.26100.1")]); }) };
  const logs = [];
  const service = new PostureService(new Store(), { env: {}, connectors: { jamf: fast, intune: slow }, waitForFirstSync: false, log: (line) => logs.push(line), now: () => NOW });
  const first = await service.overview();
  assert.equal(first.syncing, true);
  await new Promise((resolve) => setImmediate(resolve));
  const during = await service.overview({});
  service.computed = null;
  const progress = (await service.overview()).sources.intune.progress;
  assert.equal(progress, "Installed apps 3 of 900 PCs");
  assert.ok((await service.overview()).devices.some((device) => device.hostname === "MACFAST001"), "finished source is visible while the other still runs");
  releaseSlow();
  await service.syncing;
  service.computed = null;
  const done = await service.overview();
  assert.equal(done.syncing, false);
  assert.equal(done.summary.devices, 2);
  assert.ok(logs.some((line) => /Microsoft Intune: done, 1 devices/.test(line)));
  assert.ok(during);
});

test("CrowdStrike apps: libraries and extensions skipped, compact records used when they carry the host id", async () => {
  const { CrowdStrikeConnector, crowdstrikeConfig } = await import("../src/integrations/crowdstrike.mjs");
  const discoverCalls = [];
  const respond = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const fetchImpl = async (url) => {
    const parsed = new URL(url);
    if (parsed.pathname === "/oauth2/token") return respond({ access_token: "t", expires_in: 1799 }, 201);
    if (parsed.pathname === "/devices/combined/devices/v1") return respond({ meta: { pagination: { total: 1 } }, resources: [{ device_id: "aid-1", hostname: "M", system_serial_number: "C02SERIAL1", platform_name: "Mac", kernel_version: "25.6.0", os_version: "Tahoe (26)", product_type_desc: "Workstation", last_seen: daysAgo(0) }] });
    if (parsed.pathname === "/spotlight/combined/vulnerabilities/v1") return respond({ meta: { pagination: {} }, resources: [] });
    discoverCalls.push({ facet: parsed.searchParams.getAll("facet"), filter: parsed.searchParams.get("filter") });
    if (parsed.searchParams.get("filter")?.includes("category")) return respond({ errors: [{ message: "invalid filter" }] }, 400);
    return respond({ meta: { pagination: {} }, resources: [
      { id: "1", name: "Forcepoint DLP Endpoint", version: "30.8.136", host: { id: "aid-1" } },
      { id: "2", name: "postcss-js", version: "4.0.1", category: "Software Packages", dev_package: { author: {} }, host: { id: "aid-1" } },
      { id: "3", name: "Grammarly", browser_extension: { id: "kbfn", enabled: true }, host: { id: "aid-1" } }
    ] });
  };
  const connector = new CrowdStrikeConnector(crowdstrikeConfig({ CROWDSTRIKE_CLIENT_ID: "a", CROWDSTRIKE_CLIENT_SECRET: "b", CROWDSTRIKE_CLOUD: "us-1" }), { fetchImpl });
  const [host] = await connector.collect();
  assert.equal(host.serial_number, "C02SERIAL1");
  assert.equal(host.os.version, "26.6");
  assert.deepEqual(host.apps.map((app) => app.name), ["Forcepoint DLP Endpoint"]);
  assert.ok(discoverCalls.slice(1).every((call) => call.facet.length === 0), "no heavy host_info facet when records carry the host id");
  assert.match(connector.capabilities.applications.sync_mode, /2 libraries\/extensions skipped/);
});

test("a page whose download is cut off by the time limit is retried, then reported clearly", async () => {
  const { fetchJSON } = await import("../src/integrations/http.mjs");
  let calls = 0;
  const slowThenOk = async () => {
    calls += 1;
    if (calls === 1) return { ok: true, status: 200, headers: new Headers(), json: async () => { throw Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" }); } };
    return new Response(JSON.stringify({ resources: [1] }), { status: 200 });
  };
  assert.deepEqual(await fetchJSON("https://example.test/a", { source: "CrowdStrike", fetchImpl: slowThenOk, retries: 2 }), { resources: [1] });
  assert.equal(calls, 2);
  const alwaysSlow = async () => ({ ok: true, status: 200, headers: new Headers(), json: async () => { throw Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" }); } });
  await assert.rejects(fetchJSON("https://example.test/b", { source: "CrowdStrike", fetchImpl: alwaysSlow, retries: 0, timeoutMs: 180_000 }), /CrowdStrike: download took longer than 180s/);
});

// ---- Cyclops-style queries ----
import { describeQuery } from "../src/fleet-query.mjs";
import { patternsToCondition, sanitizeSoftwareRule } from "../src/fleet-config.mjs";

const fleetDevice = (name, extra = {}) => ({
  hostname: name, platform: "windows", os: { version: "10.0.26100.7171" }, last_check_in: daysAgo(1), ownership: "company",
  sources: { intune: { last_check_in: daysAgo(1) }, crowdstrike: { last_check_in: daysAgo(1) } }, crowdstrike: { product_type: "Workstation" },
  apps: [], user: { name: "A", email: "a@x.com" }, user_groups: [], ...extra
});

test("Cyclops queries: nested relations, negation, OR groups and aliases", () => {
  const forcepoint = 'e/ Device f/ CrowdstrikeFalconHostType = Workstation f/ CrowdStrikeFalconLastSeenAt < 7d f/ OSType = windows r/ ( e/ Software f/ Name contains "Forcepoint Agent 30." ) !r/ ( e/ User r/ ( e/ Group f/ EntityName = "GRP-Intune-Users-France-Finland" ) )';
  const devices = [
    fleetDevice("keep", { apps: [{ name: "Forcepoint Agent 30.9.750" }] }),
    fleetDevice("excluded-group", { apps: [{ name: "Forcepoint Agent 30.9.750" }], user_groups: ["GRP-Intune-Users-France-Finland"] }),
    fleetDevice("old-agent", { apps: [{ name: "Forcepoint Agent 29.1" }] }),
    fleetDevice("server", { apps: [{ name: "Forcepoint Agent 30.9.750" }], crowdstrike: { product_type: "Server" } })
  ];
  assert.deepEqual(runQuery(forcepoint, devices, { now: NOW }).map((d) => d.hostname), ["keep"]);

  const orGroup = 'e/ device f/ DiscoveredBy = Intune f/ IntuneManagedDeviceOwnerType = company f/ LastSeenAt < 7d f/ OSType = windows (f/ DiscoveredBy = "CrowdStrike Falcon" OR f/ CrowdstrikeFalconLastSeenAt > 7d)';
  const noFalcon = fleetDevice("no-falcon", { sources: { intune: { last_check_in: daysAgo(1) } } });
  const staleFalcon = fleetDevice("stale-falcon", { sources: { intune: { last_check_in: daysAgo(1) }, crowdstrike: { last_check_in: daysAgo(20) } } });
  assert.deepEqual(runQuery(orGroup, [fleetDevice("ok"), noFalcon, staleFalcon], { now: NOW }).map((d) => d.hostname), ["ok", "stale-falcon"]);

  const epm = 'e/ Device f/  CrowdstrikeFalconHostType = Workstation  f/ LastSeenAt  < 7d  f/ OSType = windows r/ ( e/ Software ( f/ EntityName contains "Privilege Management") OR (f/ EntityName contains "PrivilegeManagement"))';
  assert.equal(runQuery(epm, [fleetDevice("a", { apps: [{ name: "PrivilegeManagement" }] }), fleetDevice("b")], { now: NOW }).length, 1);

  assert.match(describeQuery(forcepoint), /^Windows workstations, .*Forcepoint Agent 30\..*excluding devices whose user is in group/);
  assert.throws(() => parseQuery("e/ Device ( f/ Platform = windows"), /\)/);
});

test("rules v2: version conditions, scope, sensor detection and legacy migration", () => {
  const legacy = sanitizeSoftwareRule({ name: "Okta Verify", macos: ["Okta Verify"], windows: ["Okta Verify"] });
  assert.equal(legacy.detect.windows, patternsToCondition(["Okta Verify"]));
  assert.equal(legacy.detect_source, null);

  const falcon = sanitizeSoftwareRule({ name: "CrowdStrike Falcon", windows: ["CrowdStrike Windows Sensor"] });
  assert.equal(falcon.detect_source, "crowdstrike", "CrowdStrike rules use sensor reporting");
  assert.equal(evaluateSoftwareRule(falcon, { platform: "windows", apps_source: "intune", apps: [], crowdstrike_reporting: true }).status, "installed");
  assert.equal(evaluateSoftwareRule(falcon, { platform: "windows", apps_source: null, apps: [], crowdstrike_reporting: false, crowdstrike_connected: true }).status, "missing");

  const forcepoint = sanitizeSoftwareRule({
    name: "Forcepoint DLP", scope: "e/ Device f/ CrowdStrikeHostType = Workstation",
    detect: { windows: 'e/ Software f/ Name contains "Forcepoint" f/ Version >= 30.9', macos: 'e/ Software f/ Name = "Forcepoint DLP Endpoint"' }
  });
  const pc = (version, extra = {}) => ({ ...fleetDevice("pc"), apps_source: "intune", apps: [{ name: "Forcepoint Agent", version }], ...extra });
  assert.equal(evaluateSoftwareRule(forcepoint, pc("30.9.750"), NOW).status, "installed");
  assert.equal(evaluateSoftwareRule(forcepoint, pc("30.1.2"), NOW).status, "missing", "too old counts as missing");
  assert.equal(evaluateSoftwareRule(forcepoint, pc("30.9.750", { crowdstrike: { product_type: "Server" } }), NOW).status, "not_applicable");
  assert.throws(() => sanitizeSoftwareRule({ name: "Bad", detect: { windows: "e/ Software f/ Colour = red" } }), /Windows detection/);
});

test("group conditions fetch only the referenced Entra groups (nested members included)", async () => {
  const { referencedGroups } = await import("../src/fleet-query.mjs");
  const wanted = referencedGroups(['e/ Device !r/ ( e/ User r/ ( e/ Group f/ EntityName = "GRP-A" ) )', 'e/ Device r/ ( e/ User r/ ( e/ Group f/ Name contains "France" ) )', "e/ Device f/ Platform = windows"]);
  assert.deepEqual(wanted, [{ op: "=", value: "GRP-A" }, { op: "contains", value: "France" }].sort((a, b) => `${a.op}${a.value}`.localeCompare(`${b.op}${b.value}`)));
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url: decodeURIComponent(url), consistency: options.headers.ConsistencyLevel });
    const json = (body) => ({ ok: true, status: 200, headers: new Headers(), text: async () => JSON.stringify(body), json: async () => body });
    if (url.includes("oauth2")) return json({ access_token: "t", expires_in: 3600 });
    if (url.includes("transitiveMembers")) return json({ value: url.includes("g1") ? [{ userPrincipalName: "Ana@X.com", mail: "ana@x.com" }] : [{ userPrincipalName: "bo@x.com" }] });
    if (url.includes("$search")) return json({ value: [{ id: "g2", displayName: "GRP-France" }] });
    return json({ value: [{ id: "g1", displayName: "GRP-A" }] });
  };
  const connector = new IntuneConnector({ tenantId: "t", clientId: "c", clientSecret: "s", configured: true }, { fetchImpl });
  await connector.fetchGroups(wanted);
  assert.deepEqual(connector.groups.members, { "ana@x.com": ["GRP-A"], "bo@x.com": ["GRP-France"] });
  assert.ok(calls.some((call) => call.url.includes("displayName eq 'GRP-A'")));
  assert.ok(calls.filter((call) => call.url.includes("$search")).every((call) => call.consistency === "eventual"));
  assert.equal(connector.capabilities.groups.state, "ok");
});

test("OS rules: per-platform device conditions, unknown without an OS version", () => {
  const rule = sanitizeSoftwareRule({ kind: "os", name: "Supported OS", detect: { windows: "e/ Device f/ OSBuild >= 26100", macos: "e/ Device f/ OSVersion >= 15.7" } });
  assert.equal(rule.kind, "os");
  assert.equal(evaluateSoftwareRule(rule, { platform: "windows", os: { version: "10.0.26100.7171", build: 26100 } }).status, "installed");
  assert.equal(evaluateSoftwareRule(rule, { platform: "windows", os: { version: "10.0.19045.6456", build: 19045 } }).status, "missing");
  assert.equal(evaluateSoftwareRule(rule, { platform: "macos", os: { version: "14.8.2" } }).status, "missing");
  assert.equal(evaluateSoftwareRule(rule, { platform: "macos", os: { version: "26.1" } }).status, "installed");
  assert.equal(evaluateSoftwareRule(rule, { platform: "macos", os: {} }).status, "unknown");
  assert.throws(() => sanitizeSoftwareRule({ kind: "os", name: "x", detect: { windows: "e/ Device f/ Nope = 1" } }), /Windows requirement/);
});

test("agent check-ins only update the fields agents own", async () => {
  const { agentHeartbeat, agentInventory } = await import("../src/server.mjs");
  const heartbeat = agentHeartbeat({ device_id: "dev_1", id: "dev_2", agent_token_hash: "x", enrollment_status: "revoked", hostname: "PC1", disk_encrypted: true, installed_kbs: ["kb5068861", "rm -rf", "KB1"], seen_at: "2026-11-20T00:00:00Z" });
  assert.deepEqual(Object.keys(heartbeat).sort(), ["disk_encrypted", "hostname", "installed_kbs", "installed_kbs_at", "seen_at"]);
  assert.deepEqual(heartbeat.installed_kbs, ["KB5068861"]);
  const inventory = agentInventory({ os: { name: "Windows 11", version: "10.0.26100.7171", build: "26100", evil: 1 }, software: [{ name: "Forcepoint™ Endpoint", version: "30.9.750" }, { version: "1" }], captured_at: "now" });
  assert.deepEqual(inventory.os, { name: "Windows 11", version: "10.0.26100.7171", build: "26100" });
  assert.deepEqual(inventory.software, [{ name: "Forcepoint™ Endpoint", version: "30.9.750" }]);
});
