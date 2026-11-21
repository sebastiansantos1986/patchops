import { createHash, randomUUID } from "node:crypto";
import pg from "pg";
import { assessDevice, softwareIdentity } from "./patch-engine.mjs";

const { Pool } = pg;
const tokenHash = (token) => createHash("sha256").update(token).digest("hex");
const defaultNotificationSettings = () => ({ presentation: "custom", app_name: "PatchOps Security Updates", organization: "Your Organization", accent_color: "#2563EB", symbol: "arrow.down.circle.fill", popup_width: 540, position: "center", sound: "Funk", primary_label: "Install Now", secondary_label: "Remind Me Later", show_close: true, max_deferrals: 3, require_deferral_reason: false, support_email: "", support_phone: "", help_url: "" });
const defaultAgentSettings = () => ({ inventory_interval_seconds: 900, notification_poll_seconds: 15, allow_custom_popups: true, allow_system_notifications: true });

export class PostgresStore {
  constructor(connectionString) {
    this.pool = new Pool({ connectionString, max: 5 });
    this.ready = this.initialize();
  }

  // Keeps retrying until the database answers, instead of crashing the whole service in a loop.
  // /api/health reports the database state meanwhile.
  async initialize() {
    this.pool.on("error", (error) => console.error(`[db] connection error: ${error.code ?? error.message}`));
    for (let attempt = 1; ; attempt += 1) {
      try {
        await this.createTables();
        this.status = "ok";
        if (attempt > 1) console.log("[db] connected");
        return;
      } catch (error) {
        const wait = Math.min(30, 2 ** attempt);
        this.status = error.code === "ENOTFOUND" ? "host_not_found" : error.code ?? "unreachable";
        console.error(`[db] can't reach the database (${error.code ?? error.message}${error.hostname ? ` for host ${error.hostname}` : ""}). Check DATABASE_URL: use the database's Internal URL from the same Render region and environment. Retrying in ${wait}s.`);
        await new Promise((resolve) => setTimeout(resolve, wait * 1000));
      }
    }
  }

  async createTables() {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS patchops_devices (id TEXT PRIMARY KEY, serial_number TEXT UNIQUE NOT NULL, agent_token_hash TEXT NOT NULL, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS patchops_campaigns (id TEXT PRIMARY KEY, data JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS patchops_notifications (id TEXT PRIMARY KEY, device_id TEXT NOT NULL, data JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS patchops_notification_actions (action_id TEXT PRIMARY KEY, data JSONB NOT NULL, received_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS patchops_settings (key TEXT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS patchops_console_users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, data JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS patchops_patch_catalog (id TEXT PRIMARY KEY, identity TEXT UNIQUE NOT NULL, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS patchops_remediations (id TEXT PRIMARY KEY, device_id TEXT NOT NULL, data JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    `);
  }

  async listConsoleUsers() {
    await this.ready;
    return (await this.pool.query("SELECT data FROM patchops_console_users ORDER BY LOWER(username)")).rows.map((row) => row.data);
  }

  async findConsoleUser(username) {
    await this.ready;
    const result = await this.pool.query("SELECT id, password_hash, data FROM patchops_console_users WHERE LOWER(username) = LOWER($1)", [String(username ?? "")]);
    return result.rowCount ? { ...result.rows[0].data, id: result.rows[0].id, password_hash: result.rows[0].password_hash } : null;
  }

  async createConsoleUser(input) {
    await this.ready;
    const id = `usr_${randomUUID()}`;
    const now = new Date().toISOString();
    const { password_hash, ...safeInput } = input;
    const user = { id, ...safeInput, created_at: now, updated_at: now };
    try {
      await this.pool.query("INSERT INTO patchops_console_users (id, username, password_hash, data) VALUES ($1, $2, $3, $4)", [id, input.username, password_hash, user]);
      return user;
    } catch (error) {
      if (error.code === "23505") return null;
      throw error;
    }
  }

  async updateConsoleUser(id, changes) {
    await this.ready;
    const result = await this.pool.query("SELECT data, password_hash FROM patchops_console_users WHERE id = $1", [id]);
    if (!result.rowCount) return null;
    const { password_hash, ...safeChanges } = changes;
    const user = { ...result.rows[0].data, ...safeChanges, updated_at: new Date().toISOString() };
    await this.pool.query("UPDATE patchops_console_users SET username = $2, password_hash = $3, data = $4, updated_at = NOW() WHERE id = $1", [id, user.username, password_hash ?? result.rows[0].password_hash, user]);
    return user;
  }

  async enroll(input) {
    await this.ready;
    const result = await this.pool.query("SELECT id, data FROM patchops_devices WHERE serial_number = $1", [input.serial_number]);
    const existing = result.rows[0]?.data;
    const id = result.rows[0]?.id ?? `dev_${randomUUID()}`;
    const { enrollment_token: _enrollmentToken, agent_token: _agentToken, ...safeInput } = input;
    const agentToken = `pat_${randomUUID()}_${randomUUID()}`;
    const device = { ...existing, ...safeInput, id, enrollment_status: "active", last_seen_at: new Date().toISOString(), software: existing?.software ?? [], findings: existing?.findings ?? [] };
    await this.pool.query("INSERT INTO patchops_devices (id, serial_number, agent_token_hash, data) VALUES ($1, $2, $3, $4) ON CONFLICT (serial_number) DO UPDATE SET agent_token_hash = EXCLUDED.agent_token_hash, data = EXCLUDED.data, updated_at = NOW()", [id, input.serial_number, tokenHash(agentToken), device]);
    return { device_id: id, agent_token: agentToken, policy_version: "pol_001" };
  }

  async authenticateDevice(id, token) {
    if (!id || !token) return false;
    await this.ready;
    const result = await this.pool.query("SELECT agent_token_hash FROM patchops_devices WHERE id = $1", [id]);
    return result.rows[0]?.agent_token_hash === tokenHash(token);
  }

  async hasDevice(id) {
    await this.ready;
    return (await this.pool.query("SELECT 1 FROM patchops_devices WHERE id = $1", [id])).rowCount === 1;
  }

  async listDevices() {
    await this.ready;
    const catalog = await this.listCatalogEntries();
    return (await this.pool.query("SELECT data FROM patchops_devices ORDER BY updated_at DESC")).rows.map((row) => assessDevice(row.data, catalog));
  }

  async getDevice(id) {
    await this.ready;
    const result = await this.pool.query("SELECT data FROM patchops_devices WHERE id = $1", [id]);
    if (!result.rowCount) return null;
    return { ...assessDevice(result.rows[0].data, await this.listCatalogEntries()), remediations: await this.listRemediations(id) };
  }

  async listCatalogEntries() {
    await this.ready;
    return (await this.pool.query("SELECT data FROM patchops_patch_catalog ORDER BY data->>'name'")).rows.map((row) => row.data);
  }

  async saveCatalogEntry(input) {
    await this.ready;
    const platform = String(input.platform ?? "").toLowerCase();
    const identity = softwareIdentity(platform, { name: input.name, bundle_identifier: input.identifier, product_code: input.identifier });
    if (!["macos", "windows"].includes(platform) || !String(input.name ?? "").trim() || !String(input.identifier ?? "").trim() || !String(input.approved_version ?? "").trim()) return null;
    const existing = await this.pool.query("SELECT id FROM patchops_patch_catalog WHERE identity = $1", [identity]);
    const entry = { id: existing.rows[0]?.id ?? `cat_${randomUUID()}`, identity, platform, name: String(input.name).trim().slice(0, 120), identifier: String(input.identifier).trim().slice(0, 180), approved_version: String(input.approved_version).trim().slice(0, 80), severity: ["critical", "high", "medium", "low"].includes(input.severity) ? input.severity : "medium", source: "administrator_baseline", updated_at: new Date().toISOString() };
    await this.pool.query("INSERT INTO patchops_patch_catalog (id, identity, data) VALUES ($1, $2, $3) ON CONFLICT (identity) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()", [entry.id, entry.identity, entry]);
    return entry;
  }

  async listRemediations(deviceID) {
    await this.ready;
    const result = deviceID
      ? await this.pool.query("SELECT data FROM patchops_remediations WHERE device_id = $1 ORDER BY created_at DESC", [deviceID])
      : await this.pool.query("SELECT data FROM patchops_remediations ORDER BY created_at DESC");
    return result.rows.map((row) => row.data);
  }

  async createRemediation(input) {
    await this.ready;
    const device = await this.getDevice(input.device_id);
    const software = device?.software.find((item) => item.catalog_id === input.catalog_id);
    if (!device || !software || software.patch_status !== "outdated") return null;
    const remediation = { id: `rem_${randomUUID()}`, device_id: device.id, catalog_id: software.catalog_id, software_name: software.name, installed_version: software.version, target_version: software.approved_version, type: "install_approved_package", status: "draft", execution_mode: "simulation", created_at: new Date().toISOString() };
    await this.pool.query("INSERT INTO patchops_remediations (id, device_id, data) VALUES ($1, $2, $3)", [remediation.id, remediation.device_id, remediation]);
    return remediation;
  }

  async updateDevice(id, changes) {
    await this.ready;
    const result = await this.pool.query("SELECT data FROM patchops_devices WHERE id = $1", [id]);
    if (!result.rowCount) return null;
    const device = { ...result.rows[0].data, ...changes, last_seen_at: new Date().toISOString() };
    await this.pool.query("UPDATE patchops_devices SET data = $2, updated_at = NOW() WHERE id = $1", [id, device]);
    return device;
  }

  async createCampaign(input) {
    await this.ready;
    const campaign = { id: `camp_${randomUUID()}`, status: "draft", created_at: new Date().toISOString(), ...input };
    await this.pool.query("INSERT INTO patchops_campaigns (id, data) VALUES ($1, $2)", [campaign.id, campaign]);
    return campaign;
  }

  async listNotificationActions() {
    await this.ready;
    return (await this.pool.query("SELECT data FROM patchops_notification_actions ORDER BY received_at DESC")).rows.map((row) => row.data);
  }

  async listNotifications() {
    await this.ready;
    return (await this.pool.query("SELECT data FROM patchops_notifications ORDER BY created_at DESC")).rows.map((row) => row.data);
  }

  async getNotificationSettings() {
    await this.ready;
    const result = await this.pool.query("SELECT data FROM patchops_settings WHERE key = 'notifications'");
    return { ...defaultNotificationSettings(), ...(result.rows[0]?.data ?? {}) };
  }

  async saveNotificationSettings(input) {
    await this.ready;
    const current = await this.getNotificationSettings();
    const settings = {
      ...current,
      ...input,
      accent_color: /^#[0-9A-F]{6}$/i.test(input.accent_color ?? "") ? input.accent_color : current.accent_color,
      popup_width: Math.min(720, Math.max(420, Number(input.popup_width) || 540)),
      max_deferrals: Math.min(10, Math.max(0, Number(input.max_deferrals) || 0))
    };
    await this.pool.query("INSERT INTO patchops_settings (key, data) VALUES ('notifications', $1) ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()", [settings]);
    return settings;
  }

  async getConfig(key) {
    await this.ready;
    const result = await this.pool.query("SELECT data FROM patchops_settings WHERE key = $1", [`config:${key}`]);
    return result.rowCount ? result.rows[0].data : null;
  }

  async saveConfig(key, value) {
    await this.ready;
    await this.pool.query("INSERT INTO patchops_settings (key, data) VALUES ($1, $2::jsonb) ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()", [`config:${key}`, JSON.stringify(value)]);
    return value;
  }

  async getPostureHistory() {
    await this.ready;
    const result = await this.pool.query("SELECT data FROM patchops_settings WHERE key = 'posture_history'");
    return Array.isArray(result.rows[0]?.data) ? result.rows[0].data : [];
  }

  async savePostureHistory(history) {
    await this.ready;
    // Serialize explicitly: node-postgres would otherwise send a JS array as a Postgres array.
    await this.pool.query("INSERT INTO patchops_settings (key, data) VALUES ('posture_history', $1::jsonb) ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()", [JSON.stringify(history)]);
    return history;
  }

  async getAgentSettings() {
    await this.ready;
    const result = await this.pool.query("SELECT data FROM patchops_settings WHERE key = 'agent'");
    return { ...defaultAgentSettings(), ...(result.rows[0]?.data ?? {}) };
  }

  async saveAgentSettings(input) {
    await this.ready;
    const current = await this.getAgentSettings();
    const settings = {
      ...current,
      ...input,
      inventory_interval_seconds: Math.min(86400, Math.max(60, Number(input.inventory_interval_seconds) || 900)),
      notification_poll_seconds: Math.min(300, Math.max(5, Number(input.notification_poll_seconds) || 15)),
      allow_custom_popups: input.allow_custom_popups !== false,
      allow_system_notifications: input.allow_system_notifications !== false
    };
    await this.pool.query("INSERT INTO patchops_settings (key, data) VALUES ('agent', $1) ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()", [settings]);
    return settings;
  }

  async createNotification(input) {
    await this.ready;
    if (!input.title?.trim() || !input.body?.trim() || !await this.hasDevice(input.device_id)) return null;
    const settings = await this.getNotificationSettings();
    const notification = {
      id: `ntf_${randomUUID()}`,
      device_id: input.device_id,
      title: input.title.trim().slice(0, 120),
      subtitle: String(input.subtitle ?? "PatchOps test notification").trim().slice(0, 120),
      body: input.body.trim().slice(0, 500),
      category: "PATCHOPS_UPDATE",
      presentation: input.presentation === "system" ? "system" : "custom",
      appearance: { ...settings, ...(input.appearance ?? {}) },
      mode: "simulation",
      status: "queued",
      created_at: new Date().toISOString()
    };
    await this.pool.query("INSERT INTO patchops_notifications (id, device_id, data) VALUES ($1, $2, $3)", [notification.id, notification.device_id, notification]);
    return notification;
  }

  async pendingNotifications(deviceID) {
    await this.ready;
    return (await this.pool.query("SELECT data FROM patchops_notifications WHERE device_id = $1 AND data->>'status' = 'queued' ORDER BY created_at", [deviceID])).rows.map((row) => row.data);
  }

  async acknowledgeNotification(deviceID, notificationID) {
    await this.ready;
    const result = await this.pool.query("SELECT data FROM patchops_notifications WHERE id = $1 AND device_id = $2", [notificationID, deviceID]);
    if (!result.rowCount) return null;
    const notification = { ...result.rows[0].data, status: "delivered", delivered_at: new Date().toISOString() };
    await this.pool.query("UPDATE patchops_notifications SET data = $2 WHERE id = $1", [notificationID, notification]);
    return notification;
  }

  async recordNotificationAction(input) {
    await this.ready;
    const allowed = new Set(["install_now", "schedule", "defer", "restart", "details", "dismiss"]);
    if (!input.action_id || !allowed.has(input.action)) return null;
    const existing = await this.pool.query("SELECT data FROM patchops_notification_actions WHERE action_id = $1", [input.action_id]);
    if (existing.rowCount) return { ...existing.rows[0].data, duplicate: true };
    const event = { action_id: input.action_id, notification_id: input.notification_id ?? "notification-lab", device_id: input.device_id ?? "lab-device", platform: input.platform, action: input.action, mode: "simulation", received_at: new Date().toISOString(), duplicate: false };
    await this.pool.query("INSERT INTO patchops_notification_actions (action_id, data) VALUES ($1, $2)", [event.action_id, event]);
    const notificationResult = await this.pool.query("SELECT data FROM patchops_notifications WHERE id = $1 AND device_id = $2", [event.notification_id, event.device_id]);
    if (notificationResult.rowCount) {
      const notification = { ...notificationResult.rows[0].data, status: "acknowledged", action: event.action, acknowledged_at: event.received_at };
      await this.pool.query("UPDATE patchops_notifications SET data = $2 WHERE id = $1", [notification.id, notification]);
    }
    return event;
  }
}
