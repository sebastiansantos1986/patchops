import assert from "node:assert/strict";
import test from "node:test";
import { createApp } from "../src/server.mjs";
import { PostureService } from "../src/posture-service.mjs";
import { Store } from "../src/store.mjs";
import { relayAuthorized, relayRecord } from "../src/relay.mjs";

const TOKEN = "relay-test-token-0123456789abcdef";
const intuneRecord = (serial, extra = {}) => ({
  source: "intune", source_id: `id-${serial}`, hostname: `PC-${serial}`, serial_number: serial, platform: "windows",
  model: "HP EliteBook", os: { name: "Windows 11", version: "10.0.26100.7171", build: "" }, user: { name: "Wilfred Tan", email: "wilfred@corp.example" },
  last_check_in: new Date().toISOString(), managed: true, compliance: "compliant", encrypted: true, apps: [{ name: "Okta Verify Application", version: "7.1.0.0" }],
  vulnerabilities: [{ cve: "CVE-2026-0001", severity: "critical" }], raw: { ip: "10.1.2.3", mac: "aa:bb" }, ...extra
});

async function startReceiver(env = { PATCHOPS_RELAY_TOKEN: TOKEN }, connectors = {}) {
  const store = new Store();
  const posture = new PostureService(store, { env, connectors });
  const server = createApp(store, { posture }).listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  return { server, posture, url: `http://127.0.0.1:${server.address().port}/api` };
}

function sender(url, records, extraEnv = {}) {
  const connectors = { intune: { collect: async () => records, capabilities: {}, groups: { members: { "wilfred@corp.example": ["GRP-A"] } } } };
  return new PostureService(new Store(), { env: { PATCHOPS_RELAY_URL: url, PATCHOPS_RELAY_TOKEN: TOKEN, ...extraEnv }, connectors });
}

test("relay: local copy uploads synced records without credentials, raw data, users or CVEs", async () => {
  const receiver = await startReceiver();
  try {
    assert.equal(receiver.posture.useSample, false, "a relay receiver never shows the sample fleet");
    const local = sender(receiver.url, [intuneRecord("A1"), intuneRecord("B2")]);
    await local.sync();
    const status = await local.pushRelay("intune");
    assert.equal(status.state, "ok");
    assert.equal(status.devices, 2);

    const received = receiver.posture.relayed.intune.records;
    assert.equal(received.length, 2);
    assert.equal(received[0].raw, undefined);
    assert.equal(received[0].vulnerabilities, undefined);
    assert.deepEqual(received[0].user, { name: "", email: "" });
    assert.equal(receiver.posture.relayed.intune.user_groups, null);

    const overview = await receiver.posture.overview();
    assert.equal(overview.devices.length, 2);
    assert.equal(overview.sources.intune.state, "relayed");
    const sources = await receiver.posture.sources();
    assert.equal(sources.sources.find((item) => item.key === "intune").relay.direction, "received");
    assert.equal(JSON.parse((await import("node:zlib")).gunzipSync((await receiver.posture.store.getRelaySnapshot("intune")).data)).records.length, 2, "kept in the database");
  } finally { receiver.server.close(); }
});

test("relay: users and vulnerabilities only when switched on; bad tokens and direct sources are refused", async () => {
  const receiver = await startReceiver();
  try {
    const local = sender(receiver.url, [intuneRecord("C3")], { PATCHOPS_RELAY_USERS: "true", PATCHOPS_RELAY_VULNERABILITIES: "yes" });
    await local.sync();
    await local.pushRelay("intune");
    const [record] = receiver.posture.relayed.intune.records;
    assert.equal(record.user.email, "wilfred@corp.example");
    assert.equal(record.vulnerabilities.length, 1);
    assert.deepEqual(receiver.posture.relayed.intune.user_groups, { "wilfred@corp.example": ["GRP-A"] });

    const wrong = sender(receiver.url, [intuneRecord("D4")], { PATCHOPS_RELAY_TOKEN: "wrong-token-wrong-token-wrong" });
    await wrong.sync();
    const failed = await wrong.pushRelay("intune");
    assert.equal(failed.state, "error");
    assert.match(failed.error, /401/);
  } finally { receiver.server.close(); }

  const direct = await startReceiver({ PATCHOPS_RELAY_TOKEN: TOKEN }, { intune: { collect: async () => [], capabilities: {} } });
  try {
    const local = sender(direct.url, [intuneRecord("E5")]);
    await local.sync();
    assert.match((await local.pushRelay("intune")).error, /409/);
  } finally { direct.server.close(); }

  const off = await startReceiver({});
  try {
    const local = sender(off.url, [intuneRecord("F6")]);
    await local.sync();
    assert.match((await local.pushRelay("intune")).error, /404/);
  } finally { off.server.close(); }
});

test("relay helpers", () => {
  assert.equal(relayAuthorized(`Relay ${TOKEN}`, TOKEN), true);
  assert.equal(relayAuthorized(`Bearer ${TOKEN}`, TOKEN), false);
  assert.equal(relayAuthorized("Relay short", "short"), false, "tokens under 24 characters are never accepted");
  assert.deepEqual(Object.keys(relayRecord(intuneRecord("Z"))).includes("raw"), false);
});

test("relay data with NUL characters and broken Unicode can be stored in Postgres", async () => {
  const { toJsonb } = await import("../src/postgres-store.mjs");
  const stored = JSON.parse(toJsonb({ name: "Bad\u0000App", broken: "x\ud800y", ok: "Forcepoint™ Endpoint" }));
  assert.equal(stored.name, "BadApp");
  assert.equal(stored.broken, "x�y");
  assert.equal(stored.ok, "Forcepoint™ Endpoint");
  assert.doesNotMatch(toJsonb({ a: "\u0000" }), /\\u0000/);
});

test("relay skips uploads that wouldn't change anything", async () => {
  const receiver = await startReceiver();
  try {
    const local = sender(receiver.url, [intuneRecord("G7")]);
    await local.sync();
    const first = await local.pushRelay("intune");
    assert.equal(first.unchanged, undefined);
    const second = await local.pushRelay("intune");
    assert.equal(second.unchanged, true);
    local.cache.intune = [intuneRecord("G7"), intuneRecord("H8")];
    assert.equal((await local.pushRelay("intune")).unchanged, undefined, "changes are sent");
    assert.equal(receiver.posture.relayed.intune.records.length, 2);
  } finally { receiver.server.close(); }
});
