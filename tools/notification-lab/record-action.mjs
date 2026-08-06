import { randomUUID } from "node:crypto";

const [action, platform = "macos"] = process.argv.slice(2);
const apiUrl = process.env.PATCHOPS_API_URL ?? "http://127.0.0.1:3000/api";
const response = await fetch(`${apiUrl}/notifications/actions`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    action_id: randomUUID(),
    notification_id: "lab-security-update",
    device_id: process.env.PATCHOPS_DEVICE_ID ?? `lab-${platform}`,
    platform,
    action
  })
});

if (!response.ok) throw new Error(`Action rejected: ${response.status} ${await response.text()}`);
const result = await response.json();
console.log(`Recorded ${result.action} for ${result.device_id} (${result.mode} mode)`);
