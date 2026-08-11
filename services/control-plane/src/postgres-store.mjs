import { createHash, randomUUID } from "node:crypto";
import pg from "pg";

const { Pool } = pg;
const tokenHash = (token) => createHash("sha256").update(token).digest("hex");

export class PostgresStore {
  constructor(connectionString) {
    this.pool = new Pool({ connectionString, max: 5 });
    this.ready = this.initialize();
  }

  async initialize() {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS patchops_devices (id TEXT PRIMARY KEY, serial_number TEXT UNIQUE NOT NULL, agent_token_hash TEXT NOT NULL, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS patchops_campaigns (id TEXT PRIMARY KEY, data JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS patchops_notifications (id TEXT PRIMARY KEY, device_id TEXT NOT NULL, data JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS patchops_notification_actions (action_id TEXT PRIMARY KEY, data JSONB NOT NULL, received_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    `);
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
    return (await this.pool.query("SELECT data FROM patchops_devices ORDER BY updated_at DESC")).rows.map((row) => row.data);
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

  async createNotification(input) {
    await this.ready;
    if (!input.title?.trim() || !input.body?.trim() || !await this.hasDevice(input.device_id)) return null;
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
