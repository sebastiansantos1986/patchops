import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { bearerToken, createDashboardSession, hashPassword, safeEqual, verifyDashboardSession, verifyPassword } from "./auth.mjs";
import { PostgresStore } from "./postgres-store.mjs";
import { Store } from "./store.mjs";

function secret(optionValue, environmentValue, localDefault, name) {
  const value = optionValue ?? environmentValue ?? (process.env.RENDER ? undefined : localDefault);
  if (!value) throw new Error(`${name} must be configured outside local development`);
  return value;
}

export function createApp(store, options = {}) {
  store ??= process.env.DATABASE_URL ? new PostgresStore(process.env.DATABASE_URL) : new Store();
  const enrollmentToken = secret(options.enrollmentToken, process.env.PATCHOPS_ENROLLMENT_TOKEN, "POC-MACOS-ENROLL-TOKEN", "PATCHOPS_ENROLLMENT_TOKEN");
  const dashboardUsername = options.dashboardUsername ?? process.env.PATCHOPS_DASHBOARD_USERNAME ?? "admin";
  const dashboardPassword = secret(options.dashboardPassword, process.env.PATCHOPS_DASHBOARD_PASSWORD, "patchops-dev", "PATCHOPS_DASHBOARD_PASSWORD");
  const sessionSecret = secret(options.sessionSecret, process.env.PATCHOPS_SESSION_SECRET, "local-development-session-secret", "PATCHOPS_SESSION_SECRET");
  return createServer(async (request, response) => {
    response.setHeader("content-type", "application/json");
    response.setHeader("access-control-allow-origin", "*");
    response.setHeader("access-control-allow-headers", "authorization, content-type");
    response.setHeader("access-control-allow-methods", "GET, POST, PATCH, OPTIONS");
    if (request.method === "OPTIONS") return response.writeHead(204).end();
    const send = (status, body) => response.writeHead(status).end(JSON.stringify(body));
    const body = async () => {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      return chunks.length ? JSON.parse(Buffer.concat(chunks)) : {};
    };
    const dashboardSession = () => verifyDashboardSession(bearerToken(request), sessionSecret);
    const dashboardAuthorized = () => Boolean(dashboardSession());
    const dashboardCanWrite = () => ["owner", "administrator", "operator"].includes(dashboardSession()?.role);
    const dashboardCanManageUsers = () => ["owner", "administrator"].includes(dashboardSession()?.role);
    const deviceAuthorized = (deviceID) => store.authenticateDevice(deviceID, bearerToken(request));
    const requestURL = () => new URL(request.url, "http://patchops.local");

    try {
      await store.ready;
      if (request.method === "GET" && request.url === "/api/health") return send(200, { status: "ok", service: "patchops-control-plane", storage: process.env.DATABASE_URL ? "postgres" : "memory" });
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
        const { agent_token: _agentToken, ...safeHeartbeat } = input;
        return await store.updateDevice(input.device_id, safeHeartbeat) ? send(200, { accepted: true, pending_jobs: [] }) : send(404, { error: "device_not_found" });
      }
      if (request.method === "POST" && request.url === "/api/agent/inventory") {
        const input = await body();
        if (!await deviceAuthorized(input.device_id)) return send(401, { error: "unauthorized" });
        return await store.updateDevice(input.device_id, { os: input.os, software: input.software, inventory_captured_at: input.captured_at }) ? send(200, { accepted: true, software_count: input.software?.length ?? 0 }) : send(404, { error: "device_not_found" });
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
      return send(400, { error: "invalid_request", message: error.message });
    }
  });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.HOST ?? "127.0.0.1";
  createApp().listen(port, host, () => console.log(`PatchOps API listening on http://${host}:${port}`));
}
