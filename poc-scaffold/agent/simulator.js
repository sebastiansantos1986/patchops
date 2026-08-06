/*
  PatchOps Agent Simulator - POC outline

  This is intentionally dependency-free pseudocode-style JavaScript.
  Fill in API_URL and use Node 18+ fetch when implementing.
*/

const API_URL = process.env.PATCHOPS_API_URL || "http://127.0.0.1:3000/api";

async function post(path, body) {
  const response = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body, null, 2)
  });

  if (!response.ok) {
    throw new Error(`${path} failed: ${response.status}`);
  }

  return response.json();
}

async function simulateDevice(device) {
  const enrollment = await post("/agent/enroll", {
    tenant_id: device.tenant_id,
    enrollment_token: device.enrollment_token,
    hostname: device.hostname,
    platform: device.platform,
    serial_number: device.serial_number,
    agent_version: device.agent_version
  });

  await post("/agent/heartbeat", {
    device_id: enrollment.device_id,
    agent_token: enrollment.agent_token,
    seen_at: new Date().toISOString(),
    uptime_seconds: device.uptime_seconds,
    last_reboot_at: device.last_reboot_at,
    reboot_pending: device.reboot_pending,
    battery_percent: device.battery_percent,
    online: true
  });

  await post("/agent/inventory", {
    device_id: enrollment.device_id,
    captured_at: new Date().toISOString(),
    os: device.os,
    software: device.software
  });

  await post("/agent/findings", {
    device_id: enrollment.device_id,
    captured_at: new Date().toISOString(),
    findings: device.findings
  });

  console.log(`Simulated ${device.hostname}`);
}

async function main() {
  try {
    const health = await fetch(`${API_URL}/health`);
    if (!health.ok) throw new Error(`health check returned ${health.status}`);
  } catch (error) {
    throw new Error(
      `PatchOps API is not reachable at ${API_URL}. Start it in another terminal with "npm run dev" or "npm run api", then retry "npm run simulate".`,
      { cause: error }
    );
  }

  const windows = await import("../sample-data/windows-device.json", { with: { type: "json" } });
  const macos = await import("../sample-data/macos-device.json", { with: { type: "json" } });

  await simulateDevice(windows.default);
  await simulateDevice(macos.default);
}

main().catch((error) => {
  console.error(`\nSimulation failed: ${error.message}\n`);
  process.exit(1);
});
