# PatchOps Product Architecture

## Product boundary

PatchOps is a security-focused patch orchestration layer for Windows and macOS. It owns third-party application inventory, desired-state patch policy, user experience, deployment evidence, and cross-platform reporting. It complements Jamf and Intune; it does not attempt to replace endpoint lifecycle management in v1.

## Foundation architecture

```text
Administrator -> Web console -> Control-plane API -> policy/job queue
                                      |                    |
                                  PostgreSQL        Windows/macOS agent
                                      |                    |
                                  audit log  <- signed execution result
```

The repository begins as a modular monolith:

- `index.html`: clickable PatchPilot-style product/dashboard prototype.
- `services/control-plane`: dependency-free API proving the agent data loop.
- `agents`: shared Go agent lifecycle with future Windows and macOS adapters.
- `poc-scaffold`: API/data contracts, samples, and simulator.
- `docs`: product boundaries, roadmap, security, and architectural decisions.

## Core flow

1. An agent creates a device-held key and enrolls with a short-lived token.
2. The control plane issues device identity and desired policy.
3. The agent uploads normalized inventory and evaluates typed jobs locally.
4. Packages are accepted only after hash and publisher validation.
5. The agent reports signed, idempotent results; the control plane builds audit evidence.
6. Deployment rings advance only while health/failure guardrails pass.

## Platform responsibilities

Shared agent core owns identity, local SQLite state, retries, policy, downloads, telemetry, and self-update. Windows adapters own Windows Update APIs, registry/MSI detection, Authenticode, service hosting, and native notifications. macOS adapters own bundle/receipt detection, PKG/DMG workflows, code-signing checks, LaunchDaemon hosting, and native notifications. Enforced macOS OS updates use MDM/DDM integration when required by Apple.

## Production evolution

The POC in-memory store is intentionally replaceable. The next persistence boundary is PostgreSQL, followed by a durable job queue and S3-compatible package storage. Services should split only when scale, tenancy, or a security boundary makes the operational cost worthwhile.
