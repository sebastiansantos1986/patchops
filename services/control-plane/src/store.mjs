import { randomUUID } from "node:crypto";

export class Store {
  constructor() {
    this.devices = new Map();
    this.campaigns = new Map();
  }

  enroll(input) {
    const existing = [...this.devices.values()].find((device) => device.serial_number === input.serial_number);
    const id = existing?.id ?? `dev_${randomUUID()}`;
    const device = { ...existing, ...input, id, enrollment_status: "active", last_seen_at: new Date().toISOString(), software: existing?.software ?? [], findings: existing?.findings ?? [] };
    this.devices.set(id, device);
    return { device_id: id, agent_token: `poc_${randomUUID()}`, policy_version: "pol_001" };
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
}
