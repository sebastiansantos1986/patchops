# Delivery Roadmap

## Milestone 0 — repository foundation (current)

- Preserve the clickable dashboard and original discovery artifacts.
- Document product, platform, and trust boundaries.
- Prove enrollment, heartbeat, inventory, findings, and campaign API seams.
- Establish a shared Go agent lifecycle without privileged execution.

## Milestone 1 — working 90-day proof of concept

- PostgreSQL persistence and migrations; tenant-aware API authentication.
- Agent identity bootstrap, local SQLite queue, retries, and structured telemetry.
- API-backed device, finding, and campaign screens with loading/error/empty states.
- Native Windows and macOS notification design prototypes and event capture.
- One signed test package per platform, installed only in a controlled lab.

## Milestone 2 — focused internal MVP

- Ten curated applications with strong version detection and signer verification.
- Static/dynamic groups, maintenance windows, deadlines, deferrals, rings, and pause guardrails.
- Windows Update integration and macOS MDM/DDM handoff.
- Audit evidence exports, RBAC, OIDC/SAML, agent self-update, and pilot operations.

## Deferred deliberately

Native MDM replacement, arbitrary software distribution, remote control, full vulnerability scanning, billing, and a broad app catalog remain out of scope until the focused patch loop is dependable.
