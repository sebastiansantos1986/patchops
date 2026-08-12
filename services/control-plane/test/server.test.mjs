import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createApp } from "../src/server.mjs";

let server;
let baseURL;

before(async () => {
  server = createApp(undefined, { enrollmentToken: "enroll-secret", dashboardUsername: "test-admin", dashboardPassword: "console-secret", sessionSecret: "session-secret" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseURL = `http://127.0.0.1:${server.address().port}/api`;
});

after(async () => {
  server.closeAllConnections();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

async function request(path, { method = "GET", authorization, body } = {}) {
  return fetch(`${baseURL}${path}`, {
    method,
    headers: { ...(authorization ? { authorization } : {}), ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
}

test("dashboard data requires a valid short-lived session", async () => {
  assert.equal((await request("/devices")).status, 401);
  assert.equal((await request("/auth/login", { method: "POST", body: { username: "test-admin", password: "wrong" } })).status, 401);
  assert.equal((await request("/auth/login", { method: "POST", body: { username: "wrong", password: "console-secret" } })).status, 401);
  const login = await request("/auth/login", { method: "POST", body: { username: "test-admin", password: "console-secret" } });
  assert.equal(login.status, 200);
  const { token } = await login.json();

  const settingsResponse = await request("/settings/notifications", { authorization: `Bearer ${token}` });
  assert.equal(settingsResponse.status, 200);
  assert.equal((await settingsResponse.json()).presentation, "custom");
  const savedSettings = await request("/settings/notifications", { method: "POST", authorization: `Bearer ${token}`, body: { app_name: "Acme Updates", accent_color: "#0A84FF", primary_label: "Update Now", popup_width: 640 } });
  assert.equal(savedSettings.status, 200);
  assert.equal((await savedSettings.json()).popup_width, 640);
  const savedAgentPolicy = await request("/settings/agent", { method: "POST", authorization: `Bearer ${token}`, body: { inventory_interval_seconds: 3600, notification_poll_seconds: 30 } });
  assert.equal(savedAgentPolicy.status, 200);
  assert.equal((await savedAgentPolicy.json()).inventory_interval_seconds, 3600);
  assert.equal((await request("/devices", { authorization: `Bearer ${token}` })).status, 200);
  assert.equal((await request("/campaigns", { method: "POST", authorization: `Bearer ${token}`, body: { name: "Pilot" } })).status, 201);
});

test("owners manage named console users and reviewers remain read-only", async () => {
  const ownerLogin = await request("/auth/login", { method: "POST", body: { username: "test-admin", password: "console-secret" } });
  const { token: ownerToken, user: owner } = await ownerLogin.json();
  assert.equal(owner.role, "owner");
  const created = await request("/admin/users", {
    method: "POST",
    authorization: `Bearer ${ownerToken}`,
    body: { username: "progress-reviewer", full_name: "Progress Reviewer", email: "reviewer@example.test", role: "reviewer", password: "review-only-password" }
  });
  assert.equal(created.status, 201);
  const reviewer = await created.json();
  assert.equal(reviewer.role, "reviewer");
  assert.equal(reviewer.password_hash, undefined);

  const reviewerLogin = await request("/auth/login", { method: "POST", body: { username: "progress-reviewer", password: "review-only-password" } });
  assert.equal(reviewerLogin.status, 200);
  const { token: reviewerToken } = await reviewerLogin.json();
  assert.equal((await request("/devices", { authorization: `Bearer ${reviewerToken}` })).status, 200);
  assert.equal((await request("/notifications", { method: "POST", authorization: `Bearer ${reviewerToken}`, body: { device_id: "none", title: "No", body: "No" } })).status, 403);
  assert.equal((await request("/admin/users", { authorization: `Bearer ${reviewerToken}` })).status, 403);

  assert.equal((await request(`/admin/users/${reviewer.id}`, { method: "PATCH", authorization: `Bearer ${ownerToken}`, body: { status: "disabled" } })).status, 200);
  assert.equal((await request("/auth/login", { method: "POST", body: { username: "progress-reviewer", password: "review-only-password" } })).status, 401);
});

test("enrollment exchanges a one-time secret for device-scoped credentials", async () => {
  const input = { hostname: "MAC-LAB", platform: "macos", serial_number: "LAB123" };
  assert.equal((await request("/agent/enroll", { method: "POST", authorization: "Enrollment wrong", body: input })).status, 401);
  const enrolled = await request("/agent/enroll", { method: "POST", authorization: "Enrollment enroll-secret", body: input });
  assert.equal(enrolled.status, 201);
  const identity = await enrolled.json();
  assert.equal((await request(`/agent/policy?device_id=${encodeURIComponent(identity.device_id)}`, { authorization: "Bearer wrong" })).status, 401);
  const policy = await request(`/agent/policy?device_id=${encodeURIComponent(identity.device_id)}`, { authorization: `Bearer ${identity.agent_token}` });
  assert.equal(policy.status, 200);
  assert.equal((await policy.json()).notification_poll_seconds, 30);
  const inventory = { device_id: identity.device_id, captured_at: new Date().toISOString(), os: { name: "macOS", version: "15" }, software: [] };
  assert.equal((await request("/agent/inventory", { method: "POST", authorization: "Bearer wrong", body: inventory })).status, 401);
  assert.equal((await request("/agent/inventory", { method: "POST", authorization: `Bearer ${identity.agent_token}`, body: inventory })).status, 200);
});

test("console creates an approved baseline and a simulation-only remediation draft", async () => {
  const enrolled = await request("/agent/enroll", { method: "POST", authorization: "Enrollment enroll-secret", body: { hostname: "PATCH-MAC", platform: "macos", serial_number: "PATCH-API-1" } });
  const identity = await enrolled.json();
  await request("/agent/inventory", { method: "POST", authorization: `Bearer ${identity.agent_token}`, body: { device_id: identity.device_id, captured_at: new Date().toISOString(), os: { name: "macOS", version: "15" }, software: [{ name: "Google Chrome", bundle_identifier: "com.google.Chrome", version: "127.0" }] } });
  const login = await request("/auth/login", { method: "POST", body: { username: "test-admin", password: "console-secret" } });
  const { token } = await login.json();
  const catalogResponse = await request("/catalog", { method: "POST", authorization: `Bearer ${token}`, body: { platform: "macos", name: "Google Chrome", identifier: "com.google.Chrome", approved_version: "128.0", severity: "critical" } });
  assert.equal(catalogResponse.status, 200);
  const catalog = await catalogResponse.json();
  const deviceResponse = await request(`/devices/${encodeURIComponent(identity.device_id)}`, { authorization: `Bearer ${token}` });
  assert.equal(deviceResponse.status, 200);
  assert.equal((await deviceResponse.json()).patch_summary.outdated, 1);
  const remediationResponse = await request("/remediations", { method: "POST", authorization: `Bearer ${token}`, body: { device_id: identity.device_id, catalog_id: catalog.id } });
  assert.equal(remediationResponse.status, 201);
  assert.equal((await remediationResponse.json()).execution_mode, "simulation");
});

test("dashboard notifications reach one authenticated device and record its action", async () => {
  const enrolled = await request("/agent/enroll", { method: "POST", authorization: "Enrollment enroll-secret", body: { hostname: "NOTIFY-MAC", platform: "macos", serial_number: "NOTIFY123" } });
  const identity = await enrolled.json();
  const login = await request("/auth/login", { method: "POST", body: { username: "test-admin", password: "console-secret" } });
  const { token } = await login.json();
  await request("/settings/notifications", { method: "POST", authorization: `Bearer ${token}`, body: { app_name: "Acme Updates", accent_color: "#0A84FF", primary_label: "Update Now", popup_width: 640 } });

  const queued = await request("/notifications", {
    method: "POST",
    authorization: `Bearer ${token}`,
    body: { device_id: identity.device_id, title: "VM notification test", subtitle: "PatchOps", body: "Choose an action; no software will be installed." }
  });
  assert.equal(queued.status, 201);
  const notification = await queued.json();
  assert.equal(notification.presentation, "custom");
  assert.equal(notification.appearance.app_name, "Acme Updates");
  assert.equal(notification.appearance.primary_label, "Update Now");

  assert.equal((await request(`/agent/notifications?device_id=${encodeURIComponent(identity.device_id)}`, { authorization: "Bearer wrong" })).status, 401);
  const pending = await request(`/agent/notifications?device_id=${encodeURIComponent(identity.device_id)}`, { authorization: `Bearer ${identity.agent_token}` });
  assert.deepEqual((await pending.json()).notifications.map(({ id }) => id), [notification.id]);

  assert.equal((await request("/agent/notifications/ack", { method: "POST", authorization: `Bearer ${identity.agent_token}`, body: { device_id: identity.device_id, notification_id: notification.id } })).status, 200);
  assert.equal((await request("/notifications/actions", { method: "POST", authorization: `Bearer ${identity.agent_token}`, body: { action_id: "notify-action-1", notification_id: notification.id, device_id: identity.device_id, platform: "macos", action: "defer" } })).status, 201);

  const history = await request("/notifications", { authorization: `Bearer ${token}` });
  const delivered = (await history.json()).notifications.find(({ id }) => id === notification.id);
  assert.equal(delivered.status, "acknowledged");
  assert.equal(delivered.action, "defer");
});
