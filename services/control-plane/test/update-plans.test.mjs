import assert from "node:assert/strict";
import test from "node:test";
import { evaluateUpdatePlan, sanitizeUpdatePlan } from "../src/update-plans.mjs";
import { PostureService } from "../src/posture-service.mjs";
import { Store } from "../src/store.mjs";

const NOW = Date.parse("2026-11-21T18:00:00Z");
const device = (id, version, extra = {}) => ({
  id, hostname: id, platform: "windows", apps_source: "intune", last_check_in: "2026-11-21T10:00:00Z",
  user: { name: `user-${id}` }, crowdstrike: { product_type: "Workstation" },
  apps: version === null ? [{ name: "Notepad++", version: "8.0" }] : [{ name: "Google Chrome", version }], ...extra
});

const chrome = (rings) => sanitizeUpdatePlan({
  name: "Chrome 143", app: 'e/ Software f/ Name = "Google Chrome"', target_version: "143.0", platform: "windows", rings
});

test("update plans: devices fall into the first matching ring; status comes from inventory", () => {
  const plan = chrome([
    { name: "Pilot", devices: "e/ Device f/ Hostname starts_with pilot", start: "2026-11-18", deadline: "2026-11-20" },
    { name: "Everyone", start: "2026-11-21", deadline: "2026-12-05" }
  ]);
  const devices = [
    device("pilot-1", "143.0.7499.40"), device("pilot-2", "142.0.7444.10"),
    device("pc-1", "143.1.0"), device("pc-2", "141.0"), device("pc-3", null),
    device("pc-4", "142.0", { apps_source: null, apps: [] }), device("mac-1", "130", { platform: "macos" })
  ];
  const result = evaluateUpdatePlan(plan, devices, { now: NOW });
  const [pilot, everyone] = result.rings;
  assert.deepEqual(pilot.counts, { updated: 1, pending: 1, no_data: 0 });
  assert.equal(pilot.state, "overdue", "past its deadline with devices left");
  assert.deepEqual(everyone.counts, { updated: 1, pending: 1, no_data: 1 }, "pc-3 has no Chrome; the Mac is outside the plan");
  assert.equal(everyone.state, "in_progress");
  assert.equal(everyone.days_left, 14);
  assert.deepEqual(result.totals, { updated: 2, pending: 2, no_data: 1, total: 4, pct: 50 });
  assert.equal(result.state, "overdue");
  assert.equal(result.current_ring, "Pilot");
  assert.equal(pilot.members.find((item) => item.id === "pilot-2").version, "142.0.7444.10");
});

test("update plans: validation", () => {
  assert.throws(() => sanitizeUpdatePlan({ name: "", app: 'e/ Software f/ Name = "x"', target_version: "1", rings: [{}] }), /name/);
  assert.throws(() => sanitizeUpdatePlan({ name: "a", app: "e/ Software", target_version: "1", rings: [{}] }), /which software/);
  assert.throws(() => sanitizeUpdatePlan({ name: "a", app: 'e/ Software f/ Name = "x"', target_version: "latest", rings: [{}] }), /version/);
  assert.throws(() => sanitizeUpdatePlan({ name: "a", app: 'e/ Software f/ Name = "x"', target_version: "1", rings: [] }), /ring/);
  assert.throws(() => sanitizeUpdatePlan({ name: "a", app: 'e/ Software f/ Name = "x"', target_version: "1", rings: [{ name: "R", start: "2026-12-01", deadline: "2026-11-01" }] }), /before the start/);
  assert.throws(() => sanitizeUpdatePlan({ name: "a", app: 'e/ Software f/ Name = "x"', target_version: "1", rings: [{ name: "R", devices: "e/ Device f/ Nope = 1" }] }), /Ring "R"/);
});

test("update plans: saved, tracked with a daily history, deleted", async () => {
  const service = new PostureService(new Store(), { env: { POSTURE_DATA_MODE: "sample" }, now: () => NOW });
  const plan = await service.saveUpdatePlan({ name: "Chrome", app: 'e/ Software f/ Name contains "Chrome"', target_version: "999", rings: [{ name: "Everyone" }] });
  await assert.rejects(service.saveUpdatePlan({ name: "chrome", app: 'e/ Software f/ Name contains "Chrome"', target_version: "1", rings: [{}] }), /already exists/);
  const data = await service.updatePlansData();
  assert.equal(data.plans.length, 1);
  assert.equal(data.plans[0].history.length, 1);
  assert.equal(data.plans[0].rings[0].members, undefined, "device lists only for the plan being opened");
  const detail = await service.updatePlansData({ withDevices: plan.id });
  assert.ok(Array.isArray(detail.plans[0].rings[0].members));
  assert.equal(detail.plans[0].rings[0].devices, null, "the ring condition is kept");
  assert.ok(Array.isArray(data.suggestions));
  await service.deleteUpdatePlan(plan.id);
  assert.equal((await service.updatePlansData()).plans.length, 0);
});
