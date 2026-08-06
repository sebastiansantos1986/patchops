import assert from "node:assert/strict";
import { test } from "node:test";
import { Store } from "../src/store.mjs";

test("agent enrollment and inventory loop", () => {
  const store = new Store();
  const enrollment = store.enroll({ hostname: "MAC-01", platform: "macos", serial_number: "ABC", enrollment_token: "secret" });
  assert.match(enrollment.device_id, /^dev_/);
  assert.equal(store.devices.get(enrollment.device_id).enrollment_token, undefined);
  store.updateDevice(enrollment.device_id, { software: [{ name: "Chrome", version: "1" }] });
  assert.equal(store.devices.get(enrollment.device_id).software[0].name, "Chrome");
});

test("campaigns start as drafts", () => {
  const campaign = new Store().createCampaign({ name: "Browser pilot" });
  assert.equal(campaign.status, "draft");
});

test("notification actions are allowlisted and idempotent", () => {
  const store = new Store();
  const input = { action_id: "action-1", action: "install_now", platform: "macos" };
  assert.equal(store.recordNotificationAction(input).duplicate, false);
  assert.equal(store.recordNotificationAction(input).duplicate, true);
  assert.equal(store.notificationActions.size, 1);
  assert.equal(store.recordNotificationAction({ action_id: "action-2", action: "run_anything" }), null);
});
