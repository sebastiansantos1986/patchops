# PatchOps Prototype

PatchOps is a concept prototype for a vulnerability exposure, OS/app patching, user notification, and compliance reporting platform for Windows and macOS fleets.

This repository contains:

- A clickable static web UI prototype.
- Placeholder Windows/macOS agent bootstrap downloads.
- Evidence report sample exports.
- MVP technical specification.
- 6-week POC build plan.
- Backend/agent/data-contract scaffold for the first working proof of concept.

## Open The Prototype

Open `index.html` directly in a browser, or serve the folder with any static file server.

```bash
python3 -m http.server 8765
```

Then open:

```text
http://127.0.0.1:8765
```

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

This is a static prototype, but most primary interactions are wired:

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

- No real backend API.
- No real device agent.
- No real patch installation.
- No real MDM integration.
- No real auth/SSO.
- No real PDF generation.

The POC scaffold under `poc-scaffold/` describes how to build the first working version.

## Key Documents

- [MVP Technical Spec](docs/mvp-technical-spec.md)
- [6-Week POC Plan](docs/poc-plan.md)
- [Backend API Contract](poc-scaffold/backend/api-contract.md)
- [Database Schema](poc-scaffold/backend/schema.sql)
- [Web Data Contract](poc-scaffold/web/data-contract.md)

## GitHub Pages

Because `index.html` is at the repository root, this can be published with GitHub Pages:

1. Go to repository Settings.
2. Open Pages.
3. Select the default branch.
4. Select root folder.
5. Save.

## Security Note

The files in `downloads/` are placeholders for demo purposes only. Production agents must use signed Windows installers and signed/notarized macOS packages.

