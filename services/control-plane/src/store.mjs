import { createHash, randomUUID } from "node:crypto";

const tokenHash = (token) => createHash("sha256").update(token).digest("hex");

export class Store {
  constructor() {
    this.devices = new Map();
    this.campaigns = new Map();
    this.notificationActions = new Map();
  }

  enroll(input) {
    const existing = [...this.devices.values()].find((device) => device.serial_number === input.serial_number);
    const id = existing?.id ?? `dev_${randomUUID()}`;
    const { enrollment_token: _enrollmentToken, agent_token: _agentToken, ...safeInput } = input;
    const agentToken = `pat_${randomUUID()}_${randomUUID()}`;
    const device = { ...existing, ...safeInput, id, agent_token_hash: tokenHash(agentToken), enrollment_status: "active", last_seen_at: new Date().toISOString(), software: existing?.software ?? [], findings: existing?.findings ?? [] };
    this.devices.set(id, device);
    return { device_id: id, agent_token: agentToken, policy_version: "pol_001" };
  }

  authenticateDevice(id, token) {
    const device = this.devices.get(id);
    return Boolean(device?.agent_token_hash && token && device.agent_token_hash === tokenHash(token));
  }

  listDevices() {
    return [...this.devices.values()].map(({ agent_token_hash: _agentTokenHash, ...device }) => device);
  }

  updateDevice(id, changes) {
    const device = this.devices.get(id);
    if (!device) return null;
    Object.assign(device, changes, { last_seen_at: new Date().toISOString() });
    return device;
  }

  createCampaign(input) {
    const campaign = { id: `camp_${randomUUID()}`, status: "draft", created_at: new Date().toISOString(), ...input };
    this.campaigns.set(campaign.id, campaign);
    return campaign;
  }

  recordNotificationAction(input) {
    const allowedActions = new Set(["install_now", "schedule", "defer", "restart", "details", "dismiss"]);
    if (!input.action_id || !allowedActions.has(input.action)) return null;
    if (this.notificationActions.has(input.action_id)) return { ...this.notificationActions.get(input.action_id), duplicate: true };
    const event = {
      action_id: input.action_id,
      notification_id: input.notification_id ?? "notification-lab",
      device_id: input.device_id ?? "lab-device",
      platform: input.platform,
      action: input.action,
      mode: "simulation",
      received_at: new Date().toISOString(),
      duplicate: false
    };
    this.notificationActions.set(event.action_id, event);
    return event;
  }
}
