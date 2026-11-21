import { createHash, randomUUID } from "node:crypto";
import { assessDevice, softwareIdentity } from "./patch-engine.mjs";

const tokenHash = (token) => createHash("sha256").update(token).digest("hex");
const defaultNotificationSettings = () => ({
  presentation: "custom",
  app_name: "PatchOps Security Updates",
  organization: "Your Organization",
  accent_color: "#2563EB",
  symbol: "arrow.down.circle.fill",
  popup_width: 540,
  position: "center",
  sound: "Funk",
  primary_label: "Install Now",
  secondary_label: "Remind Me Later",
  show_close: true,
  max_deferrals: 3,
  require_deferral_reason: false,
  support_email: "",
  support_phone: "",
  help_url: ""
});
const defaultAgentSettings = () => ({ inventory_interval_seconds: 900, notification_poll_seconds: 15, allow_custom_popups: true, allow_system_notifications: true });

export class Store {
  constructor() {
    this.ready = Promise.resolve();
    this.devices = new Map();
    this.campaigns = new Map();
    this.notifications = new Map();
    this.notificationActions = new Map();
    this.notificationSettings = defaultNotificationSettings();
    this.agentSettings = defaultAgentSettings();
    this.consoleUsers = new Map();
    this.patchCatalog = new Map();
    this.remediations = new Map();
  }

  listConsoleUsers() {
    return [...this.consoleUsers.values()].map(({ password_hash: _passwordHash, ...user }) => user).sort((left, right) => left.username.localeCompare(right.username));
  }

  findConsoleUser(username) {
    return [...this.consoleUsers.values()].find((user) => user.username.toLowerCase() === String(username ?? "").toLowerCase()) ?? null;
  }

  createConsoleUser(input) {
    if ([...this.consoleUsers.values()].some((user) => user.username.toLowerCase() === input.username.toLowerCase())) return null;
    const user = { id: `usr_${randomUUID()}`, ...input, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    this.consoleUsers.set(user.id, user);
    const { password_hash: _passwordHash, ...safeUser } = user;
    return safeUser;
  }

  updateConsoleUser(id, changes) {
    const user = this.consoleUsers.get(id);
    if (!user) return null;
    Object.assign(user, changes, { updated_at: new Date().toISOString() });
    const { password_hash: _passwordHash, ...safeUser } = user;
    return safeUser;
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
    return [...this.devices.values()].map(({ agent_token_hash: _agentTokenHash, ...device }) => assessDevice(device, this.listCatalogEntries()));
  }

  getDevice(id) {
    const device = this.devices.get(id);
    if (!device) return null;
    const { agent_token_hash: _agentTokenHash, ...safeDevice } = device;
    return { ...assessDevice(safeDevice, this.listCatalogEntries()), remediations: this.listRemediations(id) };
  }

  listCatalogEntries() { return [...this.patchCatalog.values()].sort((left, right) => left.name.localeCompare(right.name)); }

  saveCatalogEntry(input) {
    const platform = String(input.platform ?? "").toLowerCase();
    const software = { name: input.name, bundle_identifier: input.identifier, product_code: input.identifier };
    const identity = softwareIdentity(platform, software);
    if (!["macos", "windows"].includes(platform) || !String(input.name ?? "").trim() || !String(input.identifier ?? "").trim() || !String(input.approved_version ?? "").trim()) return null;
    const existing = [...this.patchCatalog.values()].find((entry) => entry.identity === identity);
    const entry = {
      id: existing?.id ?? `cat_${randomUUID()}`,
      identity,
      platform,
      name: String(input.name).trim().slice(0, 120),
      identifier: String(input.identifier).trim().slice(0, 180),
      approved_version: String(input.approved_version).trim().slice(0, 80),
      severity: ["critical", "high", "medium", "low"].includes(input.severity) ? input.severity : "medium",
      source: "administrator_baseline",
      updated_at: new Date().toISOString()
    };
    this.patchCatalog.set(entry.id, entry);
    return entry;
  }

  listRemediations(deviceID) {
    return [...this.remediations.values()].filter((item) => !deviceID || item.device_id === deviceID).sort((left, right) => right.created_at.localeCompare(left.created_at));
  }

  createRemediation(input) {
    const device = this.getDevice(input.device_id);
    const software = device?.software.find((item) => item.catalog_id === input.catalog_id);
    if (!device || !software || software.patch_status !== "outdated") return null;
    const remediation = {
      id: `rem_${randomUUID()}`,
      device_id: device.id,
      catalog_id: software.catalog_id,
      software_name: software.name,
      installed_version: software.version,
      target_version: software.approved_version,
      type: "install_approved_package",
      status: "draft",
      execution_mode: "simulation",
      created_at: new Date().toISOString()
    };
    this.remediations.set(remediation.id, remediation);
    return remediation;
  }

  listNotificationActions() { return [...this.notificationActions.values()]; }

  listNotifications() { return [...this.notifications.values()].sort((left, right) => right.created_at.localeCompare(left.created_at)); }

  getNotificationSettings() { return this.notificationSettings; }

  saveNotificationSettings(input) {
    const color = /^#[0-9A-F]{6}$/i.test(input.accent_color ?? "") ? input.accent_color : this.notificationSettings.accent_color;
    this.notificationSettings = {
      ...this.notificationSettings,
      ...input,
      accent_color: color,
      popup_width: Math.min(720, Math.max(420, Number(input.popup_width) || 540)),
      max_deferrals: Math.min(10, Math.max(0, Number(input.max_deferrals) || 0))
    };
    return this.notificationSettings;
  }

  getConfig(key) { return this.config?.[key] === undefined ? null : structuredClone(this.config[key]); }

  saveConfig(key, value) { this.config = { ...this.config, [key]: structuredClone(value) }; return value; }

  getRelaySnapshot(source) { return this.relaySnapshots?.[source] ?? null; }

  saveRelaySnapshot(source, compressed, receivedAt = new Date().toISOString()) { this.relaySnapshots = { ...this.relaySnapshots, [source]: { data: compressed, received_at: receivedAt } }; }

  getPostureHistory() { return this.postureHistory ?? []; }

  savePostureHistory(history) { this.postureHistory = history; return history; }

  getAgentSettings() { return this.agentSettings; }

  saveAgentSettings(input) {
    this.agentSettings = {
      ...this.agentSettings,
      ...input,
      inventory_interval_seconds: Math.min(86400, Math.max(60, Number(input.inventory_interval_seconds) || 900)),
      notification_poll_seconds: Math.min(300, Math.max(5, Number(input.notification_poll_seconds) || 15)),
      allow_custom_popups: input.allow_custom_popups !== false,
      allow_system_notifications: input.allow_system_notifications !== false
    };
    return this.agentSettings;
  }

  createNotification(input) {
    if (!this.devices.has(input.device_id) || !input.title?.trim() || !input.body?.trim()) return null;
    const notification = {
      id: `ntf_${randomUUID()}`,
      device_id: input.device_id,
      title: input.title.trim().slice(0, 120),
      subtitle: String(input.subtitle ?? "PatchOps test notification").trim().slice(0, 120),
      body: input.body.trim().slice(0, 500),
      category: "PATCHOPS_UPDATE",
      presentation: input.presentation === "system" ? "system" : "custom",
      appearance: { ...this.notificationSettings, ...(input.appearance ?? {}) },
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
