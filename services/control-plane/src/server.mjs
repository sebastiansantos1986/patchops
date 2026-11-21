import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { bearerToken, createDashboardSession, hashPassword, safeEqual, verifyDashboardSession, verifyPassword } from "./auth.mjs";
import { PostgresStore } from "./postgres-store.mjs";
import { readRelaySnapshot, relayAuthorized } from "./relay.mjs";
import { gzipSync } from "node:zlib";
import { QueryError } from "./fleet-query.mjs";
import { PostureService } from "./posture-service.mjs";
import { CveFeeds, feedSettings } from "./integrations/cve-feeds.mjs";
import { DiskCache, cacheSettings } from "./disk-cache.mjs";
import { loadEnvFile } from "./env-file.mjs";
import { Store } from "./store.mjs";

function secret(optionValue, environmentValue, localDefault, name) {
  const value = optionValue ?? environmentValue ?? (process.env.RENDER ? undefined : localDefault);
  if (!value) throw new Error(`${name} must be configured outside local development`);
  return value;
}

// Agents only update the fields they own, with bounded sizes (never ids, tokens or enrollment state).
const clip = (value, length = 200) => (value === undefined || value === null ? undefined : String(value).slice(0, length));
const compact = (object) => Object.fromEntries(Object.entries(object).filter(([, value]) => value !== undefined));
export function agentHeartbeat(input) {
  return compact({
    seen_at: clip(input.seen_at, 40), hostname: clip(input.hostname), model: clip(input.model), architecture: clip(input.architecture, 20),
    assigned_user: clip(input.assigned_user), agent_version: clip(input.agent_version, 20),
    disk_encrypted: typeof input.disk_encrypted === "boolean" ? input.disk_encrypted : undefined,
    uptime_seconds: Number.isFinite(input.uptime_seconds) ? input.uptime_seconds : undefined,
    last_reboot_at: clip(input.last_reboot_at, 40), reboot_pending: typeof input.reboot_pending === "boolean" ? input.reboot_pending : undefined,
    battery_percent: Number.isFinite(input.battery_percent) ? input.battery_percent : undefined,
    online: typeof input.online === "boolean" ? input.online : undefined,
    installed_kbs: Array.isArray(input.installed_kbs) ? input.installed_kbs.map((kb) => String(kb).toUpperCase()).filter((kb) => /^KB\d{4,8}$/.test(kb)).slice(0, 2000) : undefined,
    installed_kbs_at: Array.isArray(input.installed_kbs) ? clip(input.installed_kbs_at ?? input.seen_at, 40) ?? new Date().toISOString() : undefined
  });
}
export function agentInventory(input) {
  const os = input.os && typeof input.os === "object" ? compact({ name: clip(input.os.name, 80), version: clip(input.os.version, 40), build: clip(input.os.build, 40), release: clip(input.os.release, 20), edition: clip(input.os.edition, 120) }) : undefined;
  const software = Array.isArray(input.software) ? input.software.slice(0, 5000).map((app) => compact({
    name: clip(app?.name), version: clip(app?.version, 80), publisher: clip(app?.publisher), install_source: clip(app?.install_source ?? app?.installSource, 40),
    bundle_identifier: clip(app?.bundle_identifier ?? app?.bundleIdentifier, 200)
  })).filter((app) => app.name) : undefined;
  return compact({ os, software, inventory_captured_at: clip(input.captured_at, 40) });
}

export function createApp(store, options = {}) {
  store ??= process.env.DATABASE_URL ? new PostgresStore(process.env.DATABASE_URL) : new Store();
  const enrollmentToken = secret(options.enrollmentToken, process.env.PATCHOPS_ENROLLMENT_TOKEN, "POC-MACOS-ENROLL-TOKEN", "PATCHOPS_ENROLLMENT_TOKEN");
  const dashboardUsername = options.dashboardUsername ?? process.env.PATCHOPS_DASHBOARD_USERNAME ?? "admin";
  const dashboardPassword = secret(options.dashboardPassword, process.env.PATCHOPS_DASHBOARD_PASSWORD, "patchops-dev", "PATCHOPS_DASHBOARD_PASSWORD");
  const sessionSecret = secret(options.sessionSecret, process.env.PATCHOPS_SESSION_SECRET, "local-development-session-secret", "PATCHOPS_SESSION_SECRET");
  // Public CVE feeds are fetched only by the real server (no injected env), never in tests.
  const feeds = options.feeds ?? (options.env || process.env.NODE_TEST_CONTEXT ? undefined : new CveFeeds(feedSettings(process.env)));
  const diskCache = options.diskCache ?? (options.env || process.env.NODE_TEST_CONTEXT ? null : new DiskCache(cacheSettings(process.env)));
  const realServer = !(options.env || process.env.NODE_TEST_CONTEXT);
  let relayQueue = Promise.resolve();
  const posture = options.posture ?? new PostureService(store, {
    env: options.env ?? process.env, feeds, diskCache,
    waitForFirstSync: !realServer,
    log: realServer ? (message) => console.log(`${new Date().toLocaleTimeString()} ${message}`) : null
  });
  return createServer(async (request, response) => {
    response.setHeader("content-type", "application/json");
    response.setHeader("access-control-allow-origin", "*");
    response.setHeader("access-control-allow-headers", "authorization, content-type");
    response.setHeader("access-control-allow-methods", "GET, POST, PATCH, DELETE, OPTIONS");
    if (request.method === "OPTIONS") return response.writeHead(204).end();
    // Large JSON (device lists, dashboards) is compressed when the browser accepts it.
    const send = (status, payload) => {
      const json = JSON.stringify(payload);
      if (json.length > 20_000 && /\bgzip\b/.test(request.headers["accept-encoding"] ?? "")) {
        response.setHeader("content-encoding", "gzip");
        response.setHeader("vary", "accept-encoding");
        return response.writeHead(status).end(gzipSync(json, { level: 4 }));
      }
      return response.writeHead(status).end(json);
    };
    const body = async () => {
      const chunks = [];
      let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 8 * 1024 * 1024) throw Object.assign(new Error("request body is too large"), { status: 413 });
        chunks.push(chunk);
      }
      return chunks.length ? JSON.parse(Buffer.concat(chunks)) : {};
    };
    const dashboardSession = () => verifyDashboardSession(bearerToken(request), sessionSecret);
    const dashboardAuthorized = () => Boolean(dashboardSession());
    const dashboardCanWrite = () => ["owner", "administrator", "operator"].includes(dashboardSession()?.role);
    const dashboardCanManageUsers = () => ["owner", "administrator"].includes(dashboardSession()?.role);
    const deviceAuthorized = (deviceID) => store.authenticateDevice(deviceID, bearerToken(request));
    const requestURL = () => new URL(request.url, "http://patchops.local");

    try {
      if (request.method === "GET" && request.url === "/api/health") {
        const database = store.status ?? "ok";
        return send(database === "ok" ? 200 : 503, { status: database === "ok" ? "ok" : "database_unavailable", service: "patchops-control-plane", storage: process.env.DATABASE_URL ? "postgres" : "memory", database });
      }
      await store.ready;
      // Relay uploads from a local PatchOps (own token; can only upload source records).
      if (request.method === "POST" && request.url === "/api/relay/snapshot") {
        if (!posture.relayToken) return send(404, { error: "not_found" });
        if (!relayAuthorized(request.headers.authorization, posture.relayToken)) return send(401, { error: "unauthorized" });
        await posture.init();
        // One upload at a time: a large snapshot is held in memory while it's parsed.
        const previous = relayQueue;
        let release;
        relayQueue = new Promise((resolve) => { release = resolve; });
        try {
          await previous;
          return send(200, await posture.receiveRelay(await readRelaySnapshot(request)));
        } finally { release(); }
      }
      if (request.method === "POST" && request.url === "/api/auth/login") {
        const input = await body();
        const storedUser = await store.findConsoleUser(input.username);
        const bootstrapOwner = safeEqual(input.username, dashboardUsername) && safeEqual(input.password, dashboardPassword)
          ? { id: "bootstrap-owner", username: dashboardUsername, full_name: "PatchOps Owner", role: "owner", status: "active" }
          : null;
        const user = storedUser?.status === "active" && verifyPassword(input.password, storedUser.password_hash) ? storedUser : bootstrapOwner;
        if (!user) return send(401, { error: "invalid_credentials" });
        const safeUser = { id: user.id, username: user.username, full_name: user.full_name, email: user.email ?? "", role: user.role, status: user.status };
        return send(200, { token: createDashboardSession(sessionSecret, safeUser), expires_in: 28800, user: safeUser });
      }
      if (request.method === "GET" && request.url === "/api/auth/me") {
        const session = dashboardSession();
        return session ? send(200, { user: { id: session.sub, username: session.username, role: session.role } }) : send(401, { error: "unauthorized" });
      }
      if (request.method === "GET" && request.url === "/api/admin/users") return dashboardCanManageUsers() ? send(200, { users: await store.listConsoleUsers(), bootstrap_owner: { username: dashboardUsername, role: "owner", status: "active" } }) : send(dashboardAuthorized() ? 403 : 401, { error: dashboardAuthorized() ? "forbidden" : "unauthorized" });
      if (request.method === "POST" && request.url === "/api/admin/users") {
        if (!dashboardCanManageUsers()) return send(dashboardAuthorized() ? 403 : 401, { error: dashboardAuthorized() ? "forbidden" : "unauthorized" });
        const input = await body();
        const username = String(input.username ?? "").trim();
        const password = String(input.password ?? "");
        const role = ["administrator", "operator", "reviewer"].includes(input.role) ? input.role : null;
        if (!/^[a-zA-Z0-9._-]{3,64}$/.test(username) || password.length < 12 || !role) return send(400, { error: "invalid_user", message: "Use a 3–64 character username, a password of at least 12 characters, and a supported role." });
        if (safeEqual(username.toLowerCase(), dashboardUsername.toLowerCase())) return send(409, { error: "username_reserved" });
        const user = await store.createConsoleUser({ username, full_name: String(input.full_name ?? "").trim().slice(0, 120), email: String(input.email ?? "").trim().slice(0, 254), role, status: "active", password_hash: hashPassword(password) });
        return user ? send(201, user) : send(409, { error: "username_exists" });
      }
      if (request.method === "PATCH" && request.url.startsWith("/api/admin/users/")) {
        if (!dashboardCanManageUsers()) return send(dashboardAuthorized() ? 403 : 401, { error: dashboardAuthorized() ? "forbidden" : "unauthorized" });
        const id = decodeURIComponent(request.url.slice("/api/admin/users/".length));
        const input = await body();
        if (id === dashboardSession()?.sub && input.status === "disabled") return send(400, { error: "cannot_disable_current_user" });
        if (id === dashboardSession()?.sub && input.role && input.role !== dashboardSession()?.role) return send(400, { error: "cannot_change_current_role" });
        const changes = {};
        if (["administrator", "operator", "reviewer"].includes(input.role)) changes.role = input.role;
        if (["active", "disabled"].includes(input.status)) changes.status = input.status;
        if (input.password !== undefined) {
          if (String(input.password).length < 12) return send(400, { error: "weak_password" });
          changes.password_hash = hashPassword(input.password);
        }
        const user = await store.updateConsoleUser(id, changes);
        return user ? send(200, user) : send(404, { error: "user_not_found" });
      }
      if (request.method === "GET" && request.url === "/api/devices") return dashboardAuthorized() ? send(200, { devices: await store.listDevices() }) : send(401, { error: "unauthorized" });
      if (request.method === "GET" && request.url.startsWith("/api/devices/")) {
        if (!dashboardAuthorized()) return send(401, { error: "unauthorized" });
        const device = await store.getDevice(decodeURIComponent(request.url.slice("/api/devices/".length)));
        return device ? send(200, device) : send(404, { error: "device_not_found" });
      }
      if (request.method === "GET" && request.url === "/api/posture") return dashboardAuthorized() ? send(200, await posture.overview()) : send(401, { error: "unauthorized" });
      if (request.method === "POST" && request.url === "/api/posture/sync") {
        if (!dashboardCanWrite()) return send(dashboardAuthorized() ? 403 : 401, { error: dashboardAuthorized() ? "forbidden" : "unauthorized" });
        const input = await body().catch(() => ({}));
        await posture.sync({ force: true, full: Boolean(input?.full) });
        await posture.compute({ fresh: true });
        return send(200, await posture.overview());
      }
      if (request.method === "GET" && request.url === "/api/posture/export.csv") {
        if (!dashboardAuthorized()) return send(401, { error: "unauthorized" });
        response.setHeader("content-type", "text/csv; charset=utf-8");
        response.setHeader("content-disposition", `attachment; filename="fleet-posture-${new Date().toISOString().slice(0, 10)}.csv"`);
        return response.writeHead(200).end(await posture.csv());
      }
      if (request.method === "GET" && request.url.startsWith("/api/posture/devices/")) {
        if (!dashboardAuthorized()) return send(401, { error: "unauthorized" });
        const device = await posture.device(decodeURIComponent(request.url.slice("/api/posture/devices/".length)));
        return device ? send(200, device) : send(404, { error: "device_not_found" });
      }
      if (request.url.startsWith("/api/fleet/")) {
        if (!dashboardAuthorized()) return send(401, { error: "unauthorized" });
        const writeDenied = () => (dashboardCanWrite() ? null : send(403, { error: "forbidden" }));
        try {
          if (request.method === "GET" && request.url === "/api/fleet/config") return send(200, await posture.configSummary());
          if (request.method === "GET" && request.url === "/api/fleet/sources") return send(200, await posture.sources());
          if (request.method === "GET" && request.url === "/api/fleet/vulnerabilities") return send(200, await posture.vulnerabilities());
          if (request.method === "POST" && request.url === "/api/fleet/query") {
            const input = await body();
            return send(200, await posture.query(input.query, { groupBy: input.group_by || null, limit: input.limit }));
          }
          if (request.method === "POST" && request.url === "/api/fleet/query/parse") return send(200, posture.parse((await body()).query));
          if (request.method === "POST" && request.url === "/api/fleet/software-rules/preview") return send(200, await posture.previewSoftwareRule((await body()).rule));
          if (request.method === "POST" && request.url === "/api/fleet/software-rules") return writeDenied() ?? send(200, { software_rules: await posture.saveSoftwareRules((await body()).rules) });
          if (request.method === "POST" && request.url === "/api/fleet/tracked-patches") return writeDenied() ?? send(200, { tracked_patches: await posture.saveTrackedPatches((await body()).patches) });
          if (request.method === "POST" && request.url === "/api/fleet/dashboards") return writeDenied() ?? send(200, await posture.saveDashboard((await body()).dashboard));
          if (request.url.startsWith("/api/fleet/dashboards/")) {
            const id = decodeURIComponent(request.url.slice("/api/fleet/dashboards/".length));
            if (request.method === "DELETE") return writeDenied() ?? (await posture.deleteDashboard(id) ? send(200, { deleted: true }) : send(404, { error: "dashboard_not_found" }));
            if (request.method === "GET") {
              const data = await posture.dashboardData(id);
              return data ? send(200, data) : send(404, { error: "dashboard_not_found" });
            }
          }
          return send(404, { error: "not_found" });
        } catch (error) {
          if (error instanceof QueryError) return send(400, { error: "invalid_query", message: error.message, position: error.position ?? null });
          throw error;
        }
      }
      if (request.method === "GET" && request.url === "/api/catalog") return dashboardAuthorized() ? send(200, { catalog: await store.listCatalogEntries() }) : send(401, { error: "unauthorized" });
      if (request.method === "POST" && request.url === "/api/catalog") {
        if (!dashboardCanWrite()) return send(dashboardAuthorized() ? 403 : 401, { error: dashboardAuthorized() ? "forbidden" : "unauthorized" });
        const entry = await store.saveCatalogEntry(await body());
        return entry ? send(200, entry) : send(400, { error: "invalid_catalog_entry" });
      }
      if (request.method === "GET" && request.url === "/api/remediations") return dashboardAuthorized() ? send(200, { remediations: await store.listRemediations() }) : send(401, { error: "unauthorized" });
      if (request.method === "POST" && request.url === "/api/remediations") {
        if (!dashboardCanWrite()) return send(dashboardAuthorized() ? 403 : 401, { error: dashboardAuthorized() ? "forbidden" : "unauthorized" });
        const remediation = await store.createRemediation(await body());
        return remediation ? send(201, remediation) : send(400, { error: "device_or_outdated_software_not_found" });
      }
      if (request.method === "GET" && request.url === "/api/notifications/actions") return dashboardAuthorized() ? send(200, { mode: "simulation", actions: await store.listNotificationActions() }) : send(401, { error: "unauthorized" });
      if (request.method === "GET" && request.url === "/api/notifications") return dashboardAuthorized() ? send(200, { notifications: await store.listNotifications() }) : send(401, { error: "unauthorized" });
      if (request.method === "GET" && request.url === "/api/settings/notifications") return dashboardAuthorized() ? send(200, await store.getNotificationSettings()) : send(401, { error: "unauthorized" });
      if (request.method === "POST" && request.url === "/api/settings/notifications") return dashboardCanWrite() ? send(200, await store.saveNotificationSettings(await body())) : send(dashboardAuthorized() ? 403 : 401, { error: dashboardAuthorized() ? "forbidden" : "unauthorized" });
      if (request.method === "GET" && request.url === "/api/settings/agent") return dashboardAuthorized() ? send(200, await store.getAgentSettings()) : send(401, { error: "unauthorized" });
      if (request.method === "POST" && request.url === "/api/settings/agent") return dashboardCanWrite() ? send(200, await store.saveAgentSettings(await body())) : send(dashboardAuthorized() ? 403 : 401, { error: dashboardAuthorized() ? "forbidden" : "unauthorized" });
      if (request.method === "POST" && request.url === "/api/notifications") {
        if (!dashboardCanWrite()) return send(dashboardAuthorized() ? 403 : 401, { error: dashboardAuthorized() ? "forbidden" : "unauthorized" });
        const notification = await store.createNotification(await body());
        return notification ? send(201, notification) : send(400, { error: "invalid_notification" });
      }
      if (request.method === "GET" && request.url.startsWith("/api/agent/notifications?")) {
        const deviceID = requestURL().searchParams.get("device_id");
        if (!await deviceAuthorized(deviceID)) return send(401, { error: "unauthorized" });
        return send(200, { notifications: await store.pendingNotifications(deviceID) });
      }
      if (request.method === "GET" && request.url.startsWith("/api/agent/policy?")) {
        const deviceID = requestURL().searchParams.get("device_id");
        if (!await deviceAuthorized(deviceID)) return send(401, { error: "unauthorized" });
        return send(200, await store.getAgentSettings());
      }
      if (request.method === "POST" && request.url === "/api/agent/notifications/ack") {
        const input = await body();
        if (!await deviceAuthorized(input.device_id)) return send(401, { error: "unauthorized" });
        return await store.acknowledgeNotification(input.device_id, input.notification_id) ? send(200, { accepted: true }) : send(404, { error: "notification_not_found" });
      }
      if (request.method === "POST" && request.url === "/api/agent/enroll") {
        const suppliedToken = String(request.headers.authorization ?? "").replace(/^Enrollment\s+/i, "");
        return safeEqual(suppliedToken, enrollmentToken) ? send(201, await store.enroll(await body())) : send(401, { error: "invalid_enrollment_token" });
      }
      if (request.method === "POST" && request.url === "/api/agent/heartbeat") {
        const input = await body();
        if (!await deviceAuthorized(input.device_id)) return send(401, { error: "unauthorized" });
        return await store.updateDevice(input.device_id, agentHeartbeat(input)) ? send(200, { accepted: true, pending_jobs: [] }) : send(404, { error: "device_not_found" });
      }
      if (request.method === "POST" && request.url === "/api/agent/inventory") {
        const input = await body();
        if (!await deviceAuthorized(input.device_id)) return send(401, { error: "unauthorized" });
        return await store.updateDevice(input.device_id, agentInventory(input)) ? send(200, { accepted: true, software_count: input.software?.length ?? 0 }) : send(404, { error: "device_not_found" });
      }
      if (request.method === "POST" && request.url === "/api/agent/findings") {
        const input = await body();
        if (!await deviceAuthorized(input.device_id)) return send(401, { error: "unauthorized" });
        return await store.updateDevice(input.device_id, { findings: input.findings, findings_captured_at: input.captured_at }) ? send(200, { accepted: true, finding_count: input.findings?.length ?? 0 }) : send(404, { error: "device_not_found" });
      }
      if (request.method === "POST" && request.url === "/api/campaigns") return dashboardCanWrite() ? send(201, await store.createCampaign(await body())) : send(dashboardAuthorized() ? 403 : 401, { error: dashboardAuthorized() ? "forbidden" : "unauthorized" });
      if (request.method === "POST" && request.url === "/api/notifications/actions") {
        const input = await body();
        if (await store.hasDevice(input.device_id) && !await deviceAuthorized(input.device_id)) return send(401, { error: "unauthorized" });
        const event = await store.recordNotificationAction(input);
        return event ? send(event.duplicate ? 200 : 201, event) : send(400, { error: "invalid_notification_action" });
      }
      return send(404, { error: "not_found" });
    } catch (error) {
      if (error.status === 413 || error.code === "ERR_BUFFER_TOO_LARGE") return send(413, { error: "too_large", message: error.message });
      if (error.status === 409 || error.status === 404) return send(error.status, { error: error.message });
      return send(400, { error: "invalid_request", message: error.message });
    }
  });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  loadEnvFile();
  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.HOST ?? "127.0.0.1";
  createApp().listen(port, host, () => console.log(`PatchOps API listening on http://${host}:${port}`));
}
