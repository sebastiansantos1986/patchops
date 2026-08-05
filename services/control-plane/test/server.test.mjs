import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createApp } from "../src/server.mjs";

let server;
let base;
before(async () => {
  server = createApp().listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  base = `http://127.0.0.1:${server.address().port}/api`;
});
after(() => server.close());

test("health and agent inventory loop", async () => {
  assert.equal((await (await fetch(`${base}/health`)).json()).status, "ok");
  const enrollment = await (await fetch(`${base}/agent/enroll`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ hostname: "MAC-01", platform: "macos", serial_number: "ABC" }) })).json();
  const inventory = await fetch(`${base}/agent/inventory`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ device_id: enrollment.device_id, software: [{ name: "Chrome", version: "1" }] }) });
  assert.equal(inventory.status, 200);
  const devices = await (await fetch(`${base}/devices`)).json();
  assert.equal(devices.devices[0].software[0].name, "Chrome");
});
