import assert from "node:assert/strict";
import { test } from "node:test";
import { Store } from "../src/store.mjs";

test("agent enrollment and inventory loop", () => {
  const store = new Store();
  const enrollment = store.enroll({ hostname: "MAC-01", platform: "macos", serial_number: "ABC", enrollment_token: "secret" });
  assert.match(enrollment.device_id, /^dev_/);
  assert.match(enrollment.agent_token, /^pat_/);
  assert.equal(store.devices.get(enrollment.device_id).enrollment_token, undefined);
  assert.equal(store.authenticateDevice(enrollment.device_id, enrollment.agent_token), true);
  assert.equal(store.authenticateDevice(enrollment.device_id, "wrong"), false);
  assert.equal(store.listDevices()[0].agent_token_hash, undefined);
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

test("custom notification settings are sanitized and embedded in queued popups", () => {
  const store = new Store();
  const enrollment = store.enroll({ hostname: "POPUP-MAC", platform: "macos", serial_number: "POPUP1" });
  const settings = store.saveNotificationSettings({ app_name: "Acme Updates", accent_color: "not-a-color", popup_width: 999, primary_label: "Update Now" });
  assert.equal(settings.accent_color, "#2563EB");
  assert.equal(settings.popup_width, 720);
  const notification = store.createNotification({ device_id: enrollment.device_id, title: "Update ready", body: "Please test this popup." });
  assert.equal(notification.presentation, "custom");
  assert.equal(notification.appearance.app_name, "Acme Updates");
  assert.equal(notification.appearance.primary_label, "Update Now");
});

test("console-managed agent policy is bounded", () => {
  const store = new Store();
  const policy = store.saveAgentSettings({ inventory_interval_seconds: 10, notification_poll_seconds: 999, allow_custom_popups: false });
  assert.equal(policy.inventory_interval_seconds, 60);
  assert.equal(policy.notification_poll_seconds, 300);
  assert.equal(policy.allow_custom_popups, false);
  assert.equal(store.getAgentSettings().allow_system_notifications, true);
});

test("console users are unique, editable, and never expose password hashes", () => {
  const store = new Store();
  const created = store.createConsoleUser({ username: "reviewer", full_name: "Review User", email: "review@example.test", role: "reviewer", status: "active", password_hash: "private-hash" });
  assert.equal(created.username, "reviewer");
  assert.equal(created.password_hash, undefined);
  assert.equal(store.createConsoleUser({ username: "REVIEWER", role: "reviewer", status: "active", password_hash: "other" }), null);
  assert.equal(store.findConsoleUser("Reviewer").password_hash, "private-hash");
  assert.equal(store.listConsoleUsers()[0].password_hash, undefined);
  assert.equal(store.updateConsoleUser(created.id, { status: "disabled" }).status, "disabled");
});

test("approved baselines create device patch posture and safe remediation drafts", () => {
  const store = new Store();
  const enrollment = store.enroll({ hostname: "PATCH-MAC", platform: "macos", serial_number: "PATCH1" });
  store.updateDevice(enrollment.device_id, { software: [{ name: "Chrome", bundle_identifier: "com.google.Chrome", version: "127.0" }] });
  const baseline = store.saveCatalogEntry({ platform: "macos", name: "Google Chrome", identifier: "com.google.Chrome", approved_version: "128.0", severity: "critical" });
  const device = store.getDevice(enrollment.device_id);
  assert.equal(device.patch_summary.outdated, 1);
  assert.equal(device.software[0].catalog_id, baseline.id);
  const remediation = store.createRemediation({ device_id: device.id, catalog_id: baseline.id });
  assert.equal(remediation.type, "install_approved_package");
  assert.equal(remediation.status, "draft");
  assert.equal(remediation.execution_mode, "simulation");
  assert.equal(store.getDevice(device.id).remediations.length, 1);
});
