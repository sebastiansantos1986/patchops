# PatchOps 6-Week POC Implementation Plan

## POC Goal

Build a small but real proof of concept that proves the core product loop:

1. Enroll a device.
2. Receive heartbeat, uptime, last reboot, installed software, and findings.
3. Display devices, software, findings, and campaign status from API-backed data.
4. Simulate a remediation campaign.
5. Capture notification and evidence events.

The POC does not need to patch real devices yet. It should prove the data flow, agent contract, UI surfaces, and reporting model.

## Success Criteria

- A simulated Windows device can enroll and report inventory.
- A simulated macOS device can enroll and report inventory.
- Backend stores devices, software, findings, campaigns, events, and notification acknowledgements.
- UI can be adapted from the static prototype to read JSON/API data.
- Campaign Builder can create a mock campaign from a finding.
- Evidence Report can show real stored events from the mock campaign.

## Week 1: Backend Skeleton

Build:

- HTTP API service.
- Basic local database.
- Device enrollment endpoint.
- Device heartbeat endpoint.
- Inventory upload endpoint.
- Findings upload endpoint.
- Seed data loader.

Deliverables:

- `backend/schema.sql`
- `backend/api-contract.md`
- Running API with health check.

Acceptance:

- `POST /api/agent/enroll` returns a device id and agent token.
- `POST /api/agent/heartbeat` updates last seen, uptime, and last reboot.
- `POST /api/agent/inventory` stores installed software.
- `POST /api/agent/findings` stores exposure findings.

## Week 2: Agent Simulator

Build:

- Windows sample payload.
- macOS sample payload.
- Agent simulator script.
- Configurable tenant, platform, hostname, and API URL.

Deliverables:

- `agent/simulator.js`
- `sample-data/windows-device.json`
- `sample-data/macos-device.json`

Acceptance:

- Running the simulator creates/updates two devices.
- Devices include uptime and last reboot.
- Devices include installed apps.
- Findings appear for Chrome, Zoom, Adobe, Java, and OS baseline examples.

## Week 3: UI Data Integration

Build:

- Replace static UI data with local JSON/API reads for core pages.
- Devices page reads API-backed devices.
- Software page reads normalized software inventory.
- Findings page reads open exposure findings.

Deliverables:

- `web/data-contract.md`
- UI integration mapping from prototype fields to API fields.

Acceptance:

- Devices, software, and findings reflect simulator data.
- Empty/error/loading states exist for core pages.

## Week 4: Campaign Simulation

Build:

- Create remediation campaign endpoint.
- Campaign job table.
- Mock job assignment to devices.
- Mock job status updates from simulator.

Deliverables:

- Campaign endpoints in API contract.
- Mock campaign execution path.

Acceptance:

- Creating a campaign from a finding creates jobs for affected devices.
- Simulator can mark jobs as success, failed, deferred, or offline.
- Campaign progress can be shown in UI.

## Week 5: Notifications and Evidence

Build:

- Notification event endpoint.
- User acknowledgement/deferral event endpoint.
- Evidence snapshot endpoint.
- Evidence report JSON response.

Deliverables:

- Notification event model.
- Evidence report API response.

Acceptance:

- Campaign records prompt sent, acknowledged, deferred, and expired counts.
- Evidence report shows before/after versions and exception register.

## Week 6: Demo Hardening

Build:

- One-command local demo startup.
- Seed/reset script.
- README with demo flow.
- Basic validation and error messages.
- Export report JSON/CSV placeholder.

Deliverables:

- Local demo instructions.
- Final POC walkthrough.

Acceptance:

- A reviewer can run the backend, run the simulator, open the UI, and review:
  - Overview
  - Devices
  - Software
  - Findings
  - Finding Detail
  - Campaign Builder
  - Notifications
  - Evidence Report

## Recommended POC Stack

Keep the POC boring and fast:

- Backend: Node.js, Go, Python, or .NET
- Database: SQLite for local POC, PostgreSQL for production path
- Agent simulator: Node.js or Go
- UI: evolve current static prototype, then migrate into React/Next.js if needed

For a first POC, SQLite plus a simple HTTP API is enough. The important thing is validating the product data model and flow.

## POC Non-Goals

- No real OS patching.
- No real third-party package installation.
- No production auth.
- No production signing/notarization.
- No real MDM API integration.
- No multi-tenant billing.
- No EDR behavior analytics.

## After POC

If the POC validates the flow, the next phase is:

1. Build a real Windows inventory agent.
2. Build a real macOS inventory agent.
3. Replace mock findings with real version comparison.
4. Add first real third-party patch action, likely Chrome.
5. Add signed installers and secure enrollment.

