# Web Data Contract

The static prototype currently contains hardcoded data. The POC should replace core screens with data from these response shapes.

## Devices

Fields required:

- id
- hostname
- platform
- os_name
- os_version
- assigned_user
- department
- last_seen_at
- uptime_seconds
- last_reboot_at
- reboot_pending
- agent_version
- risk_state
- open_findings_count

Used by:

- Overview
- Devices
- Finding Detail
- Notifications
- Evidence Report

## Software Inventory

Fields required:

- normalized_name
- publisher
- installed_count
- latest_version
- outdated_count
- severity
- patchable
- unsupported

Used by:

- Software
- Overview top risk software
- Findings

## Findings

Fields required:

- id
- software_name
- installed_version
- fixed_version
- severity
- cve_ids
- affected_device_count
- internet_facing_count
- status
- first_seen_at
- sla_due_at

Used by:

- Findings
- Finding Detail
- Campaign Builder
- Evidence Report

## Campaigns

Fields required:

- id
- name
- source_finding_id
- status
- ring_strategy
- job_count
- succeeded_count
- failed_count
- deferred_count
- offline_count
- notification_template
- evidence_report_id

Used by:

- Campaigns
- Campaign Builder
- Evidence Report

## Notification Events

Fields required:

- campaign_id
- device_id
- template
- event_type
- created_at

Used by:

- Notifications
- Evidence Report

