# Backend API Contract

Base path: `/api`

## Agent Endpoints

### `POST /agent/enroll`

Request:

```json
{
  "tenant_id": "acme-prod",
  "enrollment_token": "POC-WINDOWS-ENROLL-TOKEN",
  "hostname": "WIN-LAP-8821",
  "platform": "windows",
  "serial_number": "WIN-8821-SERIAL",
  "agent_version": "0.1.0"
}
```

Response:

```json
{
  "device_id": "dev_win_8821",
  "agent_token": "poc-agent-token",
  "policy_version": "pol_001"
}
```

### `POST /agent/heartbeat`

Request:

```json
{
  "device_id": "dev_win_8821",
  "agent_token": "poc-agent-token",
  "seen_at": "2026-07-07T16:42:00Z",
  "uptime_seconds": 1576800,
  "last_reboot_at": "2026-06-19T11:12:00Z",
  "reboot_pending": false,
  "battery_percent": 84,
  "online": true
}
```

Response:

```json
{
  "accepted": true,
  "pending_jobs": []
}
```

### `POST /agent/inventory`

Request:

```json
{
  "device_id": "dev_win_8821",
  "captured_at": "2026-07-07T16:43:00Z",
  "os": {
    "name": "Windows 11 Pro",
    "version": "23H2",
    "build": "22631.3880"
  },
  "software": [
    {
      "name": "Google Chrome",
      "publisher": "Google",
      "version": "127.0.6533",
      "install_source": "registry"
    }
  ]
}
```

Response:

```json
{
  "accepted": true,
  "software_count": 1
}
```

### `POST /agent/findings`

Request:

```json
{
  "device_id": "dev_win_8821",
  "captured_at": "2026-07-07T16:44:00Z",
  "findings": [
    {
      "software_name": "Google Chrome",
      "installed_version": "127.0.6533",
      "fixed_version": "128.0.6613",
      "severity": "critical",
      "cve_ids": ["CVE-2026-1842"],
      "finding_type": "vulnerable_version"
    }
  ]
}
```

Response:

```json
{
  "accepted": true,
  "finding_count": 1
}
```

## Campaign Endpoints

### `POST /campaigns`

Creates a remediation campaign from a finding.

Request:

```json
{
  "name": "Chrome critical exposure remediation",
  "source_finding_id": "finding_chrome_critical",
  "target_scope": "all_affected_devices",
  "ring_strategy": ["pilot", "department", "offline_retry"],
  "notification_template": "critical_app_update",
  "failure_threshold_percent": 8,
  "generate_evidence_report": true
}
```

Response:

```json
{
  "campaign_id": "camp_chrome_2026_07",
  "job_count": 72,
  "status": "draft"
}
```

### `POST /agent/jobs/:job_id/status`

Updates a campaign job.

Request:

```json
{
  "status": "succeeded",
  "started_at": "2026-07-07T17:02:00Z",
  "completed_at": "2026-07-07T17:04:00Z",
  "before_version": "127.0.6533",
  "after_version": "128.0.6613",
  "message": "Chrome updated successfully"
}
```

## Notification Endpoints

### `POST /notifications/events`

Request:

```json
{
  "campaign_id": "camp_chrome_2026_07",
  "device_id": "dev_win_8821",
  "event_type": "acknowledged",
  "template": "critical_app_update",
  "created_at": "2026-07-07T17:00:00Z"
}
```

## Reporting Endpoints

### `GET /reports/evidence/:campaign_id`

Returns evidence report data for the Evidence Report screen.

