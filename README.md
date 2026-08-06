# PatchOps

PatchOps is a security-focused patch orchestration platform for Windows and macOS fleets. It combines third-party and OS patch visibility, safe staged deployments, user notifications, and audit-ready compliance evidence while working alongside Jamf and Intune.

This repository contains:

- A clickable PatchPilot-style web console prototype.
- A runnable control-plane API foundation.
- A shared Go agent lifecycle scaffold for Windows and macOS adapters.
- A native SwiftUI macOS test agent with inventory and actionable notifications.
- Placeholder Windows/macOS agent bootstrap downloads.
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

The dashboard remains a static design prototype, but most primary interactions are wired:

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

- The API is a POC seam with an in-memory store, not a production service.
- The native macOS agent is a user-launched lab build, not yet a production daemon.
- No real patch installation.
- No real MDM integration.
- No real auth/SSO.
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

The repository includes two deployment definitions:

- `.github/workflows/pages.yml` publishes the dashboard to GitHub Pages after changes reach `main`.
- `render.yaml` provisions the Node control-plane API as a free Render web service.

### Publish the dashboard

After merging the deployment pull request, open **Settings → Pages** in GitHub and set **Source** to **GitHub Actions**. The workflow publishes the site at:

```text
https://sebastiansantos1986.github.io/patchops/
```

### Publish the API

In Render, choose **New → Blueprint**, connect this repository, and apply `render.yaml`. The configured service URL is:

```text
https://patchops-api-sebastiansantos1986.onrender.com
```

The dashboard reads that URL from `config.js`. If Render assigns a different service name, update `config.js` to match. The free API sleeps when idle and uses in-memory data, so simulated devices disappear after a restart or redeploy.

## Security Note

The files in `downloads/` are placeholders for demo purposes only. Production agents must use signed Windows installers and signed/notarized macOS packages.
