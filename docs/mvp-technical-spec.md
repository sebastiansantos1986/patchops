# PatchOps MVP Technical Spec

## Product Goal

PatchOps is a cross-platform vulnerability exposure, software inventory, and patch compliance platform for Windows and macOS fleets. The MVP should prove that the platform can enroll devices, collect live software inventory, detect missing OS and third-party app patches, map exposure to severity/CVE context where available, run controlled patch campaigns, and produce compliance-ready reporting in near real time.

The first version should prioritize vulnerability visibility, reliable patch execution, and audit-ready evidence over broad device management.

## MVP Positioning

PatchOps v1 is not an MDM product. It should not try to manage device settings, profiles, Wi-Fi, VPN, certificates, remote wipe, app store assignment, or full endpoint lifecycle management.

It should solve a sharper problem:

- Show what software is installed across the fleet.
- Show which devices are exposed because of missing OS or app patches.
- Show what is outdated, risky, unsupported, vulnerable, or unauthorized.
- Patch OS updates and a curated set of high-value third-party apps.
- Give IT/security teams a live operational dashboard for exposure, installs, failures, pending reboots, and compliance.
- Produce reports that prove patch posture for audits, cyber insurance, security reviews, and leadership.
- Let admins deploy remediation in rings with maintenance windows and deferral rules.

## Product Non-Goals

The MVP should avoid full MDM scope:

- No remote wipe.
- No device configuration profiles.
- No Wi-Fi/VPN/certificate profile management.
- No app store purchasing or license assignment.
- No identity provider lifecycle management.
- No full EDR/XDR behavior analytics.
- No remote desktop/control.
- No generalized software deployment for arbitrary internal apps in v1.

PatchOps may integrate with MDMs later, but the core product should remain focused on vulnerability exposure, app/OS patching, compliance, and reporting.

## MDM and Endpoint Integrations

PatchOps should integrate with popular MDM/UEM tools, but integrations should support the product rather than redefine it.

The integration principle:

- MDMs help deploy the PatchOps agent.
- MDMs provide device ownership, groups, labels, and platform context.
- PatchOps performs vulnerability exposure scanning, patch orchestration, compliance snapshots, and reporting.
- PatchOps should avoid taking over full MDM responsibilities.

Recommended first integrations:

- Microsoft Intune
- Jamf Pro
- Kandji
- Workspace ONE
- Mosyle
- Addigy

MVP integration capabilities:

- Import devices.
- Import users/owners where available.
- Import groups, smart groups, labels, or assignment groups.
- Deploy or document agent bootstrap commands.
- Map MDM groups to PatchOps remediation rings.
- Show whether a device exists in both systems.
- Optionally hand off specific macOS update flows where Apple requires MDM-supervised behavior.

Do not include these in MVP integrations:

- Remote wipe.
- Device profile management.
- Wi-Fi/VPN/certificate profile control.
- Full app store license management.
- General purpose device lifecycle management.

## Deployment Model

Recommended v1 model: SaaS-first.

Reasons:

- Faster iteration.
- Easier live telemetry and reporting.
- Simpler catalog updates.
- Easier support and observability.
- Lower operational burden for customers.

Future option: self-hosted or private-cloud deployment for regulated customers, but this should not be in the MVP unless it is a hard sales requirement.

## Agent Strategy

Use one shared agent platform with OS-specific adapters.

Do not build two unrelated agents. Build:

- Shared agent core
- Windows adapter
- macOS adapter

## Agent Download and Deployment

The product needs an Agents/Deployment page in the console. This should be one of the first real admin workflows because every other feature depends on agent rollout.

MVP requirements:

- Download Windows bootstrap or installer.
- Download macOS bootstrap or installer.
- Show current agent version.
- Show supported platforms.
- Show enrollment token or one-time deployment token.
- Copy deployment command.
- Rotate enrollment token.
- Show package checksum once production installers exist.
- Show agent rollout coverage by platform.
- Show outdated agent versions.
- Show install failures and last check-in.

POC download format:

- Windows: PowerShell bootstrap script.
- macOS: shell bootstrap script.

Production download format:

- Windows: signed MSI or MSIX installer.
- macOS: signed and notarized PKG installer.

The POC bootstrap scripts should eventually download the signed package, verify checksum/signature, install the service/daemon, enroll the device, and start the first inventory scan.

### Shared Agent Core

Responsibilities:

- Device enrollment
- Device identity and certificate handling
- Secure API communication
- Heartbeats
- Job polling or command-channel handling
- Local job queue
- Retry and backoff
- Telemetry buffering while offline
- Local logging
- Policy evaluation helpers
- Software inventory normalization
- Vulnerability/exposure scan result normalization
- Install result reporting
- Compliance evidence collection
- Uptime and last reboot collection
- User notification delivery, acknowledgement, and deferral tracking
- Self-update support

### Windows Agent Adapter

Responsibilities:

- Windows OS inventory
- Installed software inventory from registry and package sources
- Windows Update detection
- Microsoft Update detection
- MSI/MSIX install handling
- Winget or curated package catalog integration
- Reboot detection and scheduling
- User deferral prompts
- BitLocker-aware update flow where needed

Likely implementation language: Go or Rust.

Windows service model:

- Runs as a Windows Service.
- Uses signed binaries.
- Logs to local files and Windows Event Log.
- Supports silent installation and uninstall.

### macOS Agent Adapter

Responsibilities:

- macOS OS inventory
- Installed app inventory from `/Applications`, receipts, bundles, and package metadata
- Apple `softwareupdate` integration
- Optional MDM-aware OS update handoff where Apple requires MDM for specific supervised-device flows
- PKG and DMG install handling
- App version detection
- Reboot detection and scheduling
- User deferral prompts
- FileVault-aware update flow where needed

Likely implementation language: Go or Rust.

macOS service model:

- Runs via LaunchDaemon.
- Uses signed and notarized binaries.
- Uses a signed installer package.
- Logs to local files and unified logging where appropriate.

## Backend Architecture

Recommended MVP stack:

- API: Go, Node.js, Python, or .NET
- Database: PostgreSQL
- Queue: Redis, SQS, Pub/Sub, or equivalent
- Object storage: S3-compatible storage for packages and artifacts
- Realtime: WebSocket or server-sent events for dashboard activity
- Observability: structured logs, metrics, traces
- Admin UI: React/Next.js or similar

### Core Backend Services

1. Device API

Receives:

- Enrollment requests
- Heartbeats
- Inventory snapshots
- Patch scan results
- Vulnerability/exposure scan results
- Job status updates
- Logs and failure summaries

Sends:

- Assigned policies
- Pending jobs
- Campaign instructions
- Catalog metadata
- Agent update instructions

2. Policy Engine

Determines:

- Which updates a device should receive
- Maintenance windows
- User deferral limits
- Forced reboot rules
- Exclusions
- Ring assignment
- Vulnerability severity thresholds
- Compliance policy thresholds
- Unauthorized or unsupported software rules

3. Vulnerability and Patch Catalog Service

Tracks:

- OS update metadata
- Third-party app metadata
- Latest approved versions
- Known vulnerable versions
- CVE identifiers where available
- CVSS/severity metadata where available
- Installer URLs or package artifacts
- Install commands
- Detection rules
- Supersedence
- Compliance mapping

4. Remediation Campaign Orchestrator

Manages:

- Ring-based rollout
- Scheduling
- Retry behavior
- Failure thresholds
- Pause/resume
- Rollback/remediation where possible
- Progress reporting

5. Reporting Service

Produces:

- Fleet compliance
- Device-level patch state
- Software inventory
- Vulnerable software reports
- CVE/exposure summaries
- Unsupported software reports
- Patch history
- Remediation campaign summaries
- Audit reports

6. Event Stream

Powers:

- Live dashboard activity
- New exposure detected
- Exposure remediated
- Installing now
- Failed installs
- Pending reboots
- Offline devices
- Blocked devices

7. Compliance Evidence Service

Stores:

- Device compliance snapshots
- Missing patch evidence
- Remediation timestamps
- Policy exception reasons
- Report export history
- Audit-ready proof that a device moved from exposed to remediated

8. Integration Service

Manages:

- MDM/UEM connector configuration
- OAuth/API token storage
- Device and group sync jobs
- Integration health checks
- Mapping external groups to PatchOps remediation rings
- Audit logs for imported metadata

## MVP Third-Party App Catalog

Start with a curated catalog, not a giant open-ended app library.

Recommended v1 apps:

- Google Chrome
- Microsoft Edge
- Mozilla Firefox
- Zoom Workplace
- Slack
- Adobe Acrobat Reader
- Microsoft Teams
- Java Runtime, if the target customer base needs it

For each app, define:

- Supported OS
- Version detection method
- Latest version source
- Installer package
- Silent install command
- Install success detection
- Reboot requirement
- Failure parsing
- Rollback or remediation notes

## Data Model

### Organization

Fields:

- id
- name
- plan
- created_at

### User

Fields:

- id
- organization_id
- name
- email
- role
- status
- created_at

### Device

Fields:

- id
- organization_id
- hostname
- serial_number
- platform
- os_name
- os_version
- architecture
- assigned_user
- department
- last_seen_at
- enrollment_status
- agent_version
- risk_state
- reboot_pending
- uptime_seconds
- last_reboot_at
- notification_state

### Installed Software

Fields:

- id
- device_id
- normalized_app_id
- name
- publisher
- version
- install_path
- install_source
- detected_at

### Software Title

Fields:

- id
- normalized_name
- publisher
- category
- supported
- latest_version
- severity
- patchable
- known_vulnerable
- cve_count
- unsupported
- compliance_status

### Patch

Fields:

- id
- platform
- patch_type
- title
- vendor
- version
- severity
- cve_ids
- cvss_score
- release_date
- supersedes
- reboot_required
- detection_rule
- install_rule

### Exposure Finding

Fields:

- id
- organization_id
- device_id
- software_title_id
- installed_version
- fixed_version
- severity
- cve_ids
- finding_type
- status
- first_seen_at
- last_seen_at
- remediated_at
- evidence

### Policy

Fields:

- id
- organization_id
- name
- scope
- maintenance_window
- deferral_limit
- reboot_rule
- auto_approve_critical
- enabled

### Campaign

Fields:

- id
- organization_id
- name
- type
- target_scope
- ring_strategy
- status
- starts_at
- created_by
- created_at

### Job

Fields:

- id
- campaign_id
- device_id
- patch_id
- status
- attempts
- last_error
- scheduled_at
- started_at
- completed_at

### Compliance Snapshot

Fields:

- id
- organization_id
- device_id
- policy_id
- compliance_state
- missing_critical_count
- missing_high_count
- unsupported_software_count
- unauthorized_software_count
- generated_at
- evidence

### Agent Event

Fields:

- id
- organization_id
- device_id
- event_type
- severity
- message
- metadata
- created_at

### Audit Event

Fields:

- id
- organization_id
- actor_id
- action
- target_type
- target_id
- metadata
- created_at

## Admin UI MVP

The current prototype should evolve into these first screens:

1. Overview Dashboard

- Fleet compliance
- Critical exposure
- Installing now
- Pending reboots
- Live patch activity
- Top risk software
- Deployment rings
- Windows/macOS agent health

2. Exposure Findings

- Open vulnerabilities by severity
- CVE and fixed-version context
- Affected devices
- Unsupported software findings
- SLA/due date state
- Recommended remediation campaign
- Before/after compliance evidence
- Finding detail view with affected devices, installed versions, fixed versions, remediation status, and evidence timeline

3. Devices

- Device table
- OS, user, department, risk, last seen
- Missing patches
- Installed software count
- Reboot state
- Device detail drawer/page

4. Software Inventory

- Application list
- Publisher
- Installed count
- Latest version
- Outdated count
- Severity
- Patchability
- Unauthorized/EOL flags

5. Patch Campaigns

- Campaign list
- New campaign wizard
- Campaign builder from a finding
- Source finding/CVE context
- Target devices by finding, platform, group, MDM label, online state, or risk
- Ring selection
- Maintenance window
- Deferral settings
- User notification template selection
- Reboot and app-restart rules
- Failure threshold
- Auto-pause safety controls
- Compliance evidence generation after completion
- Progress view

6. User Notifications

- Popup templates for critical updates, reboot deadlines, maintenance windows, and blocked remediation
- User acknowledgement and deferral tracking
- Uptime and last reboot displayed in prompts
- Delivery status by campaign
- Stale reboot and high-uptime device signals
- Evidence that users were notified before forced remediation

7. Reports

- Executive compliance
- Device-level detail
- Software exposure
- Patch history
- Policy exceptions
- Evidence report preview
- Before/after remediation proof
- User notification proof
- Exception register
- PDF and CSV export controls
- CSV export first, PDF later

8. Integrations

- Connected MDM/UEM systems
- Device/group sync status
- Agent deployment instructions per tool
- External group to remediation ring mapping
- Integration health and last sync
- Scoped permissions and audit log

9. Policies

- Critical update policy
- Third-party auto-patch policy
- Reboot/deferral policy
- Unauthorized software policy

10. Administration

- Roles and permissions
- Approval workflow
- Default SLAs by severity
- Notification branding
- SSO/OIDC and MFA requirement
- API tokens and webhooks
- Data retention and audit retention
- Agent package trust settings

11. Audit

- Admin actions
- Policy changes
- Campaign approvals
- Manual overrides
- Agent-reported exceptions

## Security Requirements

PatchOps agents are privileged software, so security is not optional.

MVP security baseline:

- Signed Windows and macOS agent binaries
- Signed Windows installer
- Signed and notarized macOS installer
- Per-device identity
- TLS for all communication
- Prefer mutual TLS or certificate-backed device auth
- Role-based admin permissions
- Audit log for admin actions
- Signed package metadata
- Hash verification for downloaded installers
- Agent self-update signing
- Secrets never stored in plaintext
- Tenant isolation in backend queries

## Agent Communication Model

Recommended MVP:

- Agent checks in every 5-15 minutes.
- Agent sends heartbeat and status.
- Agent polls for pending jobs.
- Agent uploads job results and inventory deltas.
- Backend streams events to UI.

Future:

- Long-lived command channel for faster response.
- Peer cache or local relay for large enterprises.

## Inventory Frequency

Recommended:

- Heartbeat: every 5 minutes
- Lightweight status: every 5-15 minutes
- Full software inventory: daily, plus after installs/uninstalls where detectable
- Patch scan: daily, plus before campaign execution
- Compliance snapshot: every 15-60 minutes depending on scale

## Build Milestones

### Milestone 1: Product Blueprint

Deliverables:

- MVP technical spec
- UI prototype
- Data model
- Agent architecture
- Initial third-party app catalog list

### Milestone 2: Backend Foundation

Build:

- Auth placeholder or basic admin auth
- Organizations
- Devices
- Software inventory ingestion
- Agent events
- Dashboard API
- PostgreSQL schema

Success:

- Backend can receive device inventory and show it in UI.

### Milestone 3: Agent Inventory POC

Build:

- Windows inventory agent
- macOS inventory agent
- Enrollment token
- Heartbeat
- Software inventory upload
- Local log file

Success:

- A Windows device and macOS device appear in the dashboard with real software inventory.

### Milestone 4: Patch Detection

Build:

- OS patch scan for Windows
- OS patch scan for macOS
- Third-party version comparison for curated catalog
- Missing patch report

Success:

- Dashboard shows real missing OS and third-party updates.

### Milestone 5: Patch Campaign MVP

Build:

- Create campaign
- Target devices/groups
- Ring rollout
- Maintenance window
- Agent job execution
- Install status reporting
- Failure summary

Success:

- Admin can run a controlled Chrome or Zoom update campaign and see live results.

### Milestone 6: Reboot and Deferral Handling

Build:

- Reboot detection
- User deferral tracking
- Forced reboot policy
- Pending reboot dashboard

Success:

- Admin can see which devices need reboots and enforce rules safely.

### Milestone 7: Reporting

Build:

- Compliance reports
- Software exposure reports
- Patch history
- CSV export

Success:

- Admin can export useful reports for leadership and audit.

## Suggested Team

Minimum serious MVP team:

- 1 backend/platform engineer
- 1 endpoint engineer with Windows experience
- 1 endpoint engineer with macOS update, packaging, and optional MDM integration experience
- 1 frontend engineer
- 1 product-minded QA/security engineer, part-time at first

One very strong full-stack engineer can prototype pieces, but a production patch platform needs endpoint depth.

## Timeline Estimate

Prototype:

- UI and mocked backend: 2-4 weeks

Technical POC:

- Real inventory from Windows and macOS agents: 4-8 weeks

MVP:

- Inventory, OS patch detection, limited third-party app patching, dashboard, campaign execution: 3-6 months

Production-ready v1:

- Hardened security, installer signing, reliable patch execution, reporting, scale testing, support tooling: 9-12 months

## Main Risks

1. macOS OS update control

Apple update behavior can be tricky. PatchOps should patch what it can directly through the local agent, and support optional handoff/integration where Apple requires an MDM-supervised flow.

2. Third-party app detection

Different apps install differently. Version detection and silent install behavior vary across Windows and macOS.

3. Reboot safety

Forced reboots are operationally sensitive. Deferrals and user prompts need careful design.

4. Agent trust

The agent must be secure, signed, observable, and difficult to tamper with.

5. Catalog maintenance

Third-party app patching is only as good as the catalog. Catalog update workflow becomes a product capability.

6. Scale and telemetry noise

Live metrics are useful only if events are normalized and not overwhelming.

## Immediate Next Build Step

Build the first real technical POC:

1. Backend endpoint: `POST /api/agent/enroll`
2. Backend endpoint: `POST /api/agent/heartbeat`
3. Backend endpoint: `POST /api/agent/inventory`
4. Database tables: devices, installed_software, agent_events
5. Minimal Windows inventory script/agent
6. Minimal macOS inventory script/agent
7. UI page that shows real reported devices and installed software

The POC does not need to patch anything yet. First prove that devices can enroll and report accurate inventory. That becomes the foundation for safe patching.
