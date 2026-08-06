import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { Store } from "./store.mjs";

export function createApp(store = new Store()) {
  return createServer(async (request, response) => {
    response.setHeader("content-type", "application/json");
    response.setHeader("access-control-allow-origin", "*");
    if (request.method === "OPTIONS") return response.writeHead(204).end();
    const send = (status, body) => response.writeHead(status).end(JSON.stringify(body));
    const body = async () => {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      return chunks.length ? JSON.parse(Buffer.concat(chunks)) : {};
    };

    try {
      if (request.method === "GET" && request.url === "/api/health") return send(200, { status: "ok", service: "patchops-control-plane" });
      if (request.method === "GET" && request.url === "/api/devices") return send(200, { devices: [...store.devices.values()] });
      if (request.method === "GET" && request.url === "/api/notifications/actions") return send(200, { mode: "simulation", actions: [...store.notificationActions.values()] });
      if (request.method === "POST" && request.url === "/api/agent/enroll") return send(201, store.enroll(await body()));
      if (request.method === "POST" && request.url === "/api/agent/heartbeat") {
        const input = await body();
        return store.updateDevice(input.device_id, input) ? send(200, { accepted: true, pending_jobs: [] }) : send(404, { error: "device_not_found" });
      }
      if (request.method === "POST" && request.url === "/api/agent/inventory") {
        const input = await body();
        return store.updateDevice(input.device_id, { os: input.os, software: input.software, inventory_captured_at: input.captured_at }) ? send(200, { accepted: true, software_count: input.software?.length ?? 0 }) : send(404, { error: "device_not_found" });
      }
      if (request.method === "POST" && request.url === "/api/agent/findings") {
        const input = await body();
        return store.updateDevice(input.device_id, { findings: input.findings, findings_captured_at: input.captured_at }) ? send(200, { accepted: true, finding_count: input.findings?.length ?? 0 }) : send(404, { error: "device_not_found" });
      }
      if (request.method === "POST" && request.url === "/api/campaigns") return send(201, store.createCampaign(await body()));
      if (request.method === "POST" && request.url === "/api/notifications/actions") {
        const event = store.recordNotificationAction(await body());
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
