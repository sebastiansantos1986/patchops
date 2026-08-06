import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createApp } from "../src/server.mjs";

let server;
let baseURL;

before(async () => {
  server = createApp(undefined, { enrollmentToken: "enroll-secret", dashboardPassword: "console-secret", sessionSecret: "session-secret" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseURL = `http://127.0.0.1:${server.address().port}/api`;
});

after(async () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));

async function request(path, { method = "GET", authorization, body } = {}) {
  return fetch(`${baseURL}${path}`, {
    method,
    headers: { ...(authorization ? { authorization } : {}), ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
}

test("dashboard data requires a valid short-lived session", async () => {
  assert.equal((await request("/devices")).status, 401);
  assert.equal((await request("/auth/login", { method: "POST", body: { password: "wrong" } })).status, 401);
  const login = await request("/auth/login", { method: "POST", body: { password: "console-secret" } });
  assert.equal(login.status, 200);
  const { token } = await login.json();
  assert.equal((await request("/devices", { authorization: `Bearer ${token}` })).status, 200);
  assert.equal((await request("/campaigns", { method: "POST", authorization: `Bearer ${token}`, body: { name: "Pilot" } })).status, 201);
});

test("enrollment exchanges a one-time secret for device-scoped credentials", async () => {
  const input = { hostname: "MAC-LAB", platform: "macos", serial_number: "LAB123" };
  assert.equal((await request("/agent/enroll", { method: "POST", authorization: "Enrollment wrong", body: input })).status, 401);
  const enrolled = await request("/agent/enroll", { method: "POST", authorization: "Enrollment enroll-secret", body: input });
  assert.equal(enrolled.status, 201);
  const identity = await enrolled.json();
  const inventory = { device_id: identity.device_id, captured_at: new Date().toISOString(), os: { name: "macOS", version: "15" }, software: [] };
  assert.equal((await request("/agent/inventory", { method: "POST", authorization: "Bearer wrong", body: inventory })).status, 401);
  assert.equal((await request("/agent/inventory", { method: "POST", authorization: `Bearer ${identity.agent_token}`, body: inventory })).status, 200);
});
