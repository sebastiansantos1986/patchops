import { randomUUID } from "node:crypto";

const apiUrl = process.env.PATCHOPS_API_URL ?? "http://127.0.0.1:3000/api";
const actionId = randomUUID();
const event = { action_id: actionId, notification_id: "automated-lab-test", device_id: "lab-automation", platform: process.platform === "darwin" ? "macos" : "windows", action: "install_now" };

async function post() {
  const response = await fetch(`${apiUrl}/notifications/actions`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(event) });
  if (!response.ok) throw new Error(`Lab action failed: ${response.status}`);
  return response.json();
}

const first = await post();
const duplicate = await post();
if (first.duplicate || !duplicate.duplicate) throw new Error("Idempotency check failed");
console.log("Notification action path passed: accepted once, duplicate safely ignored.");
