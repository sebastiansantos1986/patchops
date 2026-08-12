import assert from "node:assert/strict";
import { test } from "node:test";
import { assessDevice, compareVersions, softwareIdentity } from "../src/patch-engine.mjs";

test("version comparison handles dotted and vendor-style versions", () => {
  assert.equal(compareVersions("128.0.6613", "128.0.6613"), 0);
  assert.equal(compareVersions("127.9", "128.0"), -1);
  assert.equal(compareVersions("15.2.10", "15.2.9"), 1);
  assert.equal(compareVersions("1.0b2", "1.0b10"), -1);
});

test("software identity uses stable platform identifiers", () => {
  assert.equal(softwareIdentity("macos", { name: "Chrome", bundle_identifier: "com.google.Chrome" }), "macos:com.google.chrome");
  assert.equal(softwareIdentity("windows", { name: "Chrome", product_code: "{PRODUCT}" }), "windows:{product}");
});

test("device assessment distinguishes unmanaged, outdated, and compliant software", () => {
  const device = { platform: "macos", software: [
    { name: "Chrome", bundle_identifier: "com.google.Chrome", version: "127.0" },
    { name: "Firefox", bundle_identifier: "org.mozilla.firefox", version: "130.0" },
    { name: "Notes", bundle_identifier: "com.apple.Notes", version: "1.0" }
  ] };
  const catalog = [
    { id: "chrome", identity: "macos:com.google.chrome", approved_version: "128.0", severity: "critical" },
    { id: "firefox", identity: "macos:org.mozilla.firefox", approved_version: "129.0", severity: "high" }
  ];
  const assessed = assessDevice(device, catalog);
  assert.equal(assessed.software[0].patch_status, "outdated");
  assert.equal(assessed.software[1].patch_status, "compliant");
  assert.equal(assessed.software[2].patch_status, "unmanaged");
  assert.deepEqual(assessed.patch_summary, { installed: 3, managed: 2, outdated: 1, compliant: 1, highest_severity: "critical" });
});
