-- PatchOps POC database schema.
-- Target: SQLite for local POC. Adapt types/indexes for PostgreSQL later.

CREATE TABLE organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  serial_number TEXT,
  platform TEXT NOT NULL,
  os_name TEXT,
  os_version TEXT,
  os_build TEXT,
  assigned_user TEXT,
  department TEXT,
  agent_version TEXT,
  enrollment_status TEXT NOT NULL,
  last_seen_at TEXT,
  uptime_seconds INTEGER,
  last_reboot_at TEXT,
  reboot_pending INTEGER DEFAULT 0,
  risk_state TEXT,
  FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE installed_software (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  name TEXT NOT NULL,
  publisher TEXT,
  version TEXT,
  install_source TEXT,
  detected_at TEXT NOT NULL,
  FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  software_name TEXT NOT NULL,
  installed_version TEXT,
  fixed_version TEXT,
  severity TEXT NOT NULL,
  cve_ids TEXT,
  finding_type TEXT NOT NULL,
  status TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  remediated_at TEXT,
  FOREIGN KEY (organization_id) REFERENCES organizations(id),
  FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE campaigns (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  name TEXT NOT NULL,
  source_finding_id TEXT,
  target_scope TEXT NOT NULL,
  status TEXT NOT NULL,
  notification_template TEXT,
  failure_threshold_percent INTEGER,
  generate_evidence_report INTEGER DEFAULT 1,
  created_at TEXT NOT NULL,
  launched_at TEXT,
  completed_at TEXT,
  FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE campaign_jobs (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  status TEXT NOT NULL,
  attempts INTEGER DEFAULT 0,
  before_version TEXT,
  after_version TEXT,
  last_error TEXT,
  scheduled_at TEXT,
  started_at TEXT,
  completed_at TEXT,
  FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
  FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE agent_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  device_id TEXT,
  event_type TEXT NOT NULL,
  severity TEXT,
  message TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE notification_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  campaign_id TEXT,
  device_id TEXT,
  template TEXT,
  event_type TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (organization_id) REFERENCES organizations(id),
  FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
  FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE evidence_snapshots (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  campaign_id TEXT NOT NULL,
  summary_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (organization_id) REFERENCES organizations(id),
  FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);

