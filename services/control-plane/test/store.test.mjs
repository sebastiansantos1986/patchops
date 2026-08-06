import assert from "node:assert/strict";
import { test } from "node:test";
import { Store } from "../src/store.mjs";

test("agent enrollment and inventory loop", () => {
  const store = new Store();
  const enrollment = store.enroll({ hostname: "MAC-01", platform: "macos", serial_number: "ABC" });
  assert.match(enrollment.device_id, /^dev_/);
  store.updateDevice(enrollment.device_id, { software: [{ name: "Chrome", version: "1" }] });
  assert.equal(store.devices.get(enrollment.device_id).software[0].name, "Chrome");
});

test("campaigns start as drafts", () => {
  const campaign = new Store().createCampaign({ name: "Browser pilot" });
  assert.equal(campaign.status, "draft");
});
