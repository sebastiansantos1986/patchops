import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { bearerToken, createDashboardSession, safeEqual, verifyDashboardSession } from "./auth.mjs";
import { Store } from "./store.mjs";

function secret(optionValue, environmentValue, localDefault, name) {
  const value = optionValue ?? environmentValue ?? (process.env.RENDER ? undefined : localDefault);
  if (!value) throw new Error(`${name} must be configured outside local development`);
  return value;
}

export function createApp(store = new Store(), options = {}) {
  const enrollmentToken = secret(options.enrollmentToken, process.env.PATCHOPS_ENROLLMENT_TOKEN, "POC-MACOS-ENROLL-TOKEN", "PATCHOPS_ENROLLMENT_TOKEN");
  const dashboardPassword = secret(options.dashboardPassword, process.env.PATCHOPS_DASHBOARD_PASSWORD, "patchops-dev", "PATCHOPS_DASHBOARD_PASSWORD");
  const sessionSecret = secret(options.sessionSecret, process.env.PATCHOPS_SESSION_SECRET, "local-development-session-secret", "PATCHOPS_SESSION_SECRET");
  return createServer(async (request, response) => {
    response.setHeader("content-type", "application/json");
    response.setHeader("access-control-allow-origin", "*");
    response.setHeader("access-control-allow-headers", "authorization, content-type");
    response.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
    if (request.method === "OPTIONS") return response.writeHead(204).end();
    const send = (status, body) => response.writeHead(status).end(JSON.stringify(body));
    const body = async () => {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      return chunks.length ? JSON.parse(Buffer.concat(chunks)) : {};
    };
    const dashboardAuthorized = () => verifyDashboardSession(bearerToken(request), sessionSecret);
    const deviceAuthorized = (deviceID) => store.authenticateDevice(deviceID, bearerToken(request));

    try {
      if (request.method === "GET" && request.url === "/api/health") return send(200, { status: "ok", service: "patchops-control-plane" });
      if (request.method === "POST" && request.url === "/api/auth/login") {
        const input = await body();
        return safeEqual(input.password, dashboardPassword) ? send(200, { token: createDashboardSession(sessionSecret), expires_in: 28800 }) : send(401, { error: "invalid_credentials" });
      }
      if (request.method === "GET" && request.url === "/api/devices") return dashboardAuthorized() ? send(200, { devices: store.listDevices() }) : send(401, { error: "unauthorized" });
      if (request.method === "GET" && request.url === "/api/notifications/actions") return dashboardAuthorized() ? send(200, { mode: "simulation", actions: [...store.notificationActions.values()] }) : send(401, { error: "unauthorized" });
      if (request.method === "POST" && request.url === "/api/agent/enroll") {
        const suppliedToken = String(request.headers.authorization ?? "").replace(/^Enrollment\s+/i, "");
        return safeEqual(suppliedToken, enrollmentToken) ? send(201, store.enroll(await body())) : send(401, { error: "invalid_enrollment_token" });
      }
      if (request.method === "POST" && request.url === "/api/agent/heartbeat") {
        const input = await body();
        if (!deviceAuthorized(input.device_id)) return send(401, { error: "unauthorized" });
        const { agent_token: _agentToken, ...safeHeartbeat } = input;
        return store.updateDevice(input.device_id, safeHeartbeat) ? send(200, { accepted: true, pending_jobs: [] }) : send(404, { error: "device_not_found" });
      }
      if (request.method === "POST" && request.url === "/api/agent/inventory") {
        const input = await body();
        if (!deviceAuthorized(input.device_id)) return send(401, { error: "unauthorized" });
        return store.updateDevice(input.device_id, { os: input.os, software: input.software, inventory_captured_at: input.captured_at }) ? send(200, { accepted: true, software_count: input.software?.length ?? 0 }) : send(404, { error: "device_not_found" });
      }
      if (request.method === "POST" && request.url === "/api/agent/findings") {
        const input = await body();
        if (!deviceAuthorized(input.device_id)) return send(401, { error: "unauthorized" });
        return store.updateDevice(input.device_id, { findings: input.findings, findings_captured_at: input.captured_at }) ? send(200, { accepted: true, finding_count: input.findings?.length ?? 0 }) : send(404, { error: "device_not_found" });
      }
      if (request.method === "POST" && request.url === "/api/campaigns") return dashboardAuthorized() ? send(201, store.createCampaign(await body())) : send(401, { error: "unauthorized" });
      if (request.method === "POST" && request.url === "/api/notifications/actions") {
        const input = await body();
        if (store.devices.has(input.device_id) && !deviceAuthorized(input.device_id)) return send(401, { error: "unauthorized" });
        const event = store.recordNotificationAction(input);
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
