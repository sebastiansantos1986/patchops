# ADR 0002: Use MDM/DDM for enforceable macOS OS updates

Status: Accepted

The PatchOps agent owns third-party application patching, inventory, notification UX, and evidence on macOS. Enforceable Apple OS-update workflows use Apple MDM/Declarative Device Management directly or through Jamf/Intune integrations. This avoids an unreliable agent-only promise while preserving one cross-platform operations view.
