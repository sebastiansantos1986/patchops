# PatchOps

PatchOps is a security-focused patch orchestration platform for Windows and macOS fleets. It combines third-party and OS patch visibility, safe staged deployments, user notifications, and audit-ready compliance evidence while working alongside Jamf and Intune.

This repository contains:

- A clickable PatchPilot-style web console prototype.
- A runnable control-plane API foundation.
- A shared Go agent lifecycle scaffold for Windows and macOS adapters.
- A native SwiftUI macOS test agent with inventory and actionable notifications.
- A downloadable universal macOS VM-lab agent for Apple silicon and Intel Macs, with a published checksum and package manifest.
- A placeholder Windows agent bootstrap download while its native package is under development.
- Evidence report sample exports.
- MVP technical specification.
- 6-week POC build plan.
- Backend/agent/data-contract scaffold for the first working proof of concept.

## Run the local foundation

Requires Node.js 20+. Go 1.22+ is needed only to build or test the agent.

```bash
npm run dev
```

Open the dashboard at `http://127.0.0.1:8765`. The API health endpoint is `http://127.0.0.1:3000/api/health`.
Sign in to the local dashboard with username `admin` and password `patchops-dev`.

In another terminal, seed the API with the simulated Windows and macOS devices:

```bash
npm run simulate
```

Run API tests with `npm run check` and agent tests with `npm run check:agent`. Run one safe agent lifecycle cycle with `go run ./agents/cmd/patchops-agent --once`.

## Native macOS test agent

The SwiftUI lab agent collects read-only system and application inventory and can sync it to the local POC API. Its native notification buttons record actions in simulation mode; they cannot install software or restart the Mac.

```bash
npm run macos:probe
npm run macos:install
```

See [the macOS agent guide](clients/macos/PatchOpsAgent/README.md) for the test flow, collected fields, and production hardening requirements.

## Demo Flow

Use this flow when showing the concept:

1. Overview
2. Findings
3. Finding Detail
4. Campaign Builder
5. Notifications
6. Evidence Report
7. Agents
8. Integrations
9. Admin

The product story is:

```text
Scan -> Find exposure -> Review impact -> Notify users -> Patch -> Prove compliance
```

## What Works In This Prototype

The dashboard is a static frontend backed by the development API, and most primary interactions are wired:

- Sidebar navigation.
- Finding to detail flow.
- Campaign builder flow.
- Evidence report preview.
- Agent bootstrap downloads.
- Copy deployment commands.
- Report sample downloads.
- Toast notifications for common actions.
- Admin/policy/integration review surfaces.

## What Is Not Real Yet

- Local development uses an in-memory store; hosted development uses PostgreSQL without production backup guarantees.
- The native macOS agent is a user-launched lab build, not yet a production daemon.
- No real patch installation.
- No real MDM integration.
- Development password authentication is implemented; production SSO, user accounts, and RBAC remain.
- No real PDF generation.

The POC scaffold under `poc-scaffold/` describes how to build the first working version. The runnable foundation lives under `services/` and `agents/`.

## Key Documents

- [MVP Technical Spec](docs/mvp-technical-spec.md)
- [Product Architecture](docs/architecture.md)
- [Security Model](docs/security-model.md)
- [Delivery Roadmap](docs/roadmap.md)
- [6-Week POC Plan](docs/poc-plan.md)
- [Backend API Contract](poc-scaffold/backend/api-contract.md)
- [Database Schema](poc-scaffold/backend/schema.sql)
- [Web Data Contract](poc-scaffold/web/data-contract.md)

## Free development hosting

The repository includes two deployment paths:

- `.github/workflows/pages.yml` publishes the dashboard to GitHub Pages after changes reach `main`.
- `render.yaml` provisions both the dashboard and Node control-plane API on Render.

### Publish the full stack on Render

In Render, choose **New → Blueprint**, connect this repository, and apply `render.yaml`. The Blueprint creates:

```text
https://patchops-dashboard-sebastiansantos1986.onrender.com
https://patchops-api-sebastiansantos1986.onrender.com
```

The dashboard is a free static site served from Render's CDN. The API is a free web service and can take approximately one minute to wake after 15 minutes without traffic. Hosted device, campaign, and notification records are stored in the Blueprint-managed PostgreSQL database, so they survive API sleep, restarts, and redeploys.

The free Render PostgreSQL instance is for development only: it has a 1 GB limit, expires after 30 days, and does not include backups. Upgrade or migrate it before retaining important fleet history.

The Blueprint configures the hosted development credentials automatically:

- Dashboard username: `admin`
- Dashboard password: generated securely by Render
- macOS agent enrollment token: generated securely by Render

Render also generates `PATCHOPS_SESSION_SECRET` automatically. Open the API service's **Environment** page to reveal or copy the generated dashboard password and enrollment token. Never commit those values. Enter the enrollment token in the macOS agent Settings screen; the agent exchanges it for a device-scoped credential and stores both secrets in macOS Keychain.

### Publish the dashboard

After merging the deployment pull request, open **Settings → Pages** in GitHub and set **Source** to **GitHub Actions**. The workflow publishes the site at:

```text
https://sebastiansantos1986.github.io/patchops/
```

### Publish only the API

In Render, choose **New → Blueprint**, connect this repository, and apply `render.yaml`. The configured service URL is:

```text
https://patchops-api-sebastiansantos1986.onrender.com
```

The dashboard reads that URL from `config.js`. If Render assigns a different service name, update `config.js` to match. The free API sleeps when idle; hosted records remain in PostgreSQL subject to the free database's 30-day development limit.

## Security Note

Open **Agents** in the hosted console and download the macOS agent ZIP, SHA-256 checksum, and user-level installer. The package manifest is published beside them in `downloads/`. Keep the downloaded ZIP and installer together on the VM and run:

```bash
bash install-macos-agent.sh
```

The installer verifies the app signature and installs it in `~/Applications`. Open PatchOps Agent, choose the hosted development API in Settings, and enter the enrollment token from the Render API service. The test device appears under **Devices** after enrollment and synchronization.

To test remote alerts, keep PatchOps Agent open on the VM, open **Notifications** in the dashboard, choose the enrolled VM, and select **Send to test Mac**. The agent checks the hosted queue every 15 seconds, displays a native Notification Center banner, and reports the user's selected action to the delivery table. All actions remain simulation-only.

This is an ad-hoc-signed, non-notarized development build for isolated VMs. It does not install a root daemon or privileged helper and cannot patch or reboot a machine. Do not use it on production endpoints. Production releases require Developer ID signing and Apple notarization. The Windows download remains a placeholder until its native package is implemented.
