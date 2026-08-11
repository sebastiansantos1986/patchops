import { createHash, randomUUID } from "node:crypto";

const tokenHash = (token) => createHash("sha256").update(token).digest("hex");

export class Store {
  constructor() {
    this.ready = Promise.resolve();
    this.devices = new Map();
    this.campaigns = new Map();
    this.notifications = new Map();
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

  hasDevice(id) { return this.devices.has(id); }

  listDevices() {
    return [...this.devices.values()].map(({ agent_token_hash: _agentTokenHash, ...device }) => device);
  }

  listNotificationActions() { return [...this.notificationActions.values()]; }

  listNotifications() { return [...this.notifications.values()].sort((left, right) => right.created_at.localeCompare(left.created_at)); }

  createNotification(input) {
    if (!this.devices.has(input.device_id) || !input.title?.trim() || !input.body?.trim()) return null;
    const notification = {
      id: `ntf_${randomUUID()}`,
      device_id: input.device_id,
      title: input.title.trim().slice(0, 120),
      subtitle: String(input.subtitle ?? "PatchOps test notification").trim().slice(0, 120),
      body: input.body.trim().slice(0, 500),
      category: "PATCHOPS_UPDATE",
      mode: "simulation",
      status: "queued",
      created_at: new Date().toISOString()
    };
    this.notifications.set(notification.id, notification);
    return notification;
  }

  pendingNotifications(deviceID) {
    return [...this.notifications.values()].filter((notification) => notification.device_id === deviceID && notification.status === "queued");
  }

  acknowledgeNotification(deviceID, notificationID) {
    const notification = this.notifications.get(notificationID);
    if (!notification || notification.device_id !== deviceID) return null;
    Object.assign(notification, { status: "delivered", delivered_at: new Date().toISOString() });
    return notification;
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
    const notification = this.notifications.get(event.notification_id);
    if (notification && notification.device_id === event.device_id) Object.assign(notification, { status: "acknowledged", action: event.action, acknowledged_at: event.received_at });
    return event;
  }
}
