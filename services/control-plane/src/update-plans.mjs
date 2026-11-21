// Update plans: roll a software update out in rings (pilot -> broad) and track it from inventory.
// PatchOps doesn't install anything: you deploy with Intune / Jamf as usual, and each device moves
// from "to update" to "updated" when its inventory reports the new version.
import { randomUUID } from "node:crypto";
import { QueryError, matchesClause, parseEntityClause, parseQuery, runQuery } from "./fleet-query.mjs";
import { compareVersions } from "./patch-engine.mjs";

const text = (value, max = 120) => String(value ?? "").trim().slice(0, max);
const day = (value) => (/^\d{4}-\d{2}-\d{2}$/.test(String(value ?? "")) ? String(value) : null);
const DAY = 86_400_000;

function validQuery(source, entity, label) {
  const value = text(source, 4000);
  if (!value) return null;
  try {
    if (entity === "Device") parseQuery(value);
    else parseEntityClause(value, entity);
  } catch (error) {
    throw new QueryError(`${label}: ${error.message}`);
  }
  return value;
}

export function sanitizeUpdatePlan(input) {
  const name = text(input?.name, 80);
  if (!name) throw new QueryError("Give the plan a name");
  const app = validQuery(input?.app, "App", "Software");
  if (!app || !/f\/\s*\w+/.test(app)) throw new QueryError("Say which software this plan updates");
  const target = text(input?.target_version, 40);
  if (!/^\d/.test(target)) throw new QueryError("Set the version to reach, e.g. 143.0");
  const rings = (Array.isArray(input?.rings) ? input.rings : []).slice(0, 6).map((ring, index) => ({
    name: text(ring?.name, 40) || `Ring ${index + 1}`,
    // No condition = "everyone else": every device not in an earlier ring.
    devices: validQuery(ring?.devices, "Device", `Ring "${text(ring?.name, 40) || index + 1}"`),
    start: day(ring?.start),
    deadline: day(ring?.deadline)
  }));
  if (!rings.length) throw new QueryError("Add at least one ring");
  for (const ring of rings) if (ring.start && ring.deadline && ring.deadline < ring.start) throw new QueryError(`Ring "${ring.name}": the deadline is before the start`);
  return {
    id: /^plan_[\w-]{4,40}$/.test(input?.id ?? "") ? input.id : `plan_${randomUUID().slice(0, 12)}`,
    name,
    app,
    platform: ["windows", "macos"].includes(input?.platform) ? input.platform : null,
    target_version: target,
    owner: text(input?.owner, 80),
    notes: text(input?.notes, 1000),
    status: ["draft", "active", "paused", "done"].includes(input?.status) ? input.status : "active",
    rings,
    created_at: text(input?.created_at, 40) || new Date().toISOString()
  };
}

// Highest installed version of the plan's software on a device, or null when it isn't installed.
function installedVersion(device, appClause, now) {
  let best = null;
  for (const app of device.apps ?? []) {
    if (!matchesClause(app, appClause, now)) continue;
    if (!best || compareVersions(app.version ?? "", best) > 0) best = app.version ?? "";
  }
  return best;
}

export function evaluateUpdatePlan(plan, devices, { now = Date.now() } = {}) {
  const appClause = parseEntityClause(plan.app, "App");
  const ringQueries = plan.rings.map((ring) => (ring.devices ? parseQuery(ring.devices) : null));
  const today = new Date(now).toISOString().slice(0, 10);
  const rings = plan.rings.map((ring) => ({ ...ring, counts: { updated: 0, pending: 0, no_data: 0 }, members: [] }));
  const assigned = new Set();
  plan.rings.forEach((ring, index) => {
    const members = ringQueries[index] ? runQuery(ringQueries[index], devices, { now }) : devices;
    for (const device of members) {
      if (assigned.has(device.id) || (plan.platform && device.platform !== plan.platform)) continue;
      assigned.add(device.id);
      let status;
      let version = null;
      if (!device.apps_source) status = "no_data";
      else {
        version = installedVersion(device, appClause, now);
        if (version === null) continue; // the software isn't on this device: not part of the rollout
        status = compareVersions(version, plan.target_version) >= 0 ? "updated" : "pending";
      }
      rings[index].counts[status] += 1;
      rings[index].members.push({ id: device.id, hostname: device.hostname, platform: device.platform, user: device.user?.name || device.user?.email || "", version, status, last_seen: device.last_check_in ?? null });
    }
  });
  for (const ring of rings) {
    const total = ring.counts.updated + ring.counts.pending;
    ring.total = total;
    ring.pct = total ? Math.round((ring.counts.updated / total) * 1000) / 10 : null;
    // Whole days until the deadline (0 = due today), counted in calendar days.
    ring.days_left = ring.deadline ? Math.round((Date.parse(`${ring.deadline}T00:00:00Z`) - Date.parse(`${today}T00:00:00Z`)) / DAY) : null;
    ring.state = !total ? "empty"
      : !ring.counts.pending ? "done"
      : ring.days_left !== null && ring.days_left < 0 ? "overdue"
      : ring.start && today < ring.start ? "upcoming"
      : "in_progress";
  }
  const totals = rings.reduce((sum, ring) => ({ updated: sum.updated + ring.counts.updated, pending: sum.pending + ring.counts.pending, no_data: sum.no_data + ring.counts.no_data }), { updated: 0, pending: 0, no_data: 0 });
  const total = totals.updated + totals.pending;
  return {
    ...plan,
    rings,
    totals: { ...totals, total, pct: total ? Math.round((totals.updated / total) * 1000) / 10 : null },
    state: plan.status !== "active" ? plan.status : total && !totals.pending ? "complete" : rings.some((ring) => ring.state === "overdue") ? "overdue" : "on_track",
    current_ring: rings.find((ring) => ["in_progress", "overdue"].includes(ring.state))?.name ?? rings.find((ring) => ring.state === "upcoming")?.name ?? null
  };
}
