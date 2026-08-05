# Security Model

Patch software is remote privileged execution, so PatchOps defaults to constrained, verifiable actions.

## Trust rules

- No fleet-wide shared agent secret. Production enrollment creates a device key and certificate.
- No arbitrary command field in ordinary patch jobs. Jobs are typed desired-state instructions.
- Package metadata includes SHA-256, size, expected Windows publisher or Apple Team ID, and immutable revision.
- Catalog metadata and agent self-updates use separate signing keys with threshold/rotation procedures.
- Agent jobs are idempotent, expire, have bounded output/runtime, and retain complete audit history.
- Custom scripts are an explicitly privileged feature with signing, approval, revisions, and scope controls.
- Sensitive local values live in Windows DPAPI/certificate storage or macOS Keychain with restrictive filesystem permissions.
- Rollouts start in a pilot ring and automatically pause on configured install or agent-health thresholds.

## POC limitations

The current API returns a POC token and stores data in memory. It binds only to loopback by default. It must not be exposed to untrusted networks or used to install packages. Production work requires mTLS, authorization/RBAC, tenant isolation, durable audit storage, rate limiting, secrets management, and independent security review.
