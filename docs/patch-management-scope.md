# PatchOps patch-management boundary

PatchOps is currently an agent-based patch-management product for macOS and Windows. It is not an MDM replacement.

## Current product loop

1. Enroll an endpoint agent with device-scoped credentials.
2. Collect operating-system and installed-application inventory.
3. Define an administrator-approved application version in the patch catalog.
4. Compare installed versions with the approved baseline.
5. Explain whether each application is unmanaged, compliant, or outdated.
6. Create a typed remediation draft for outdated software.
7. Notify the endpoint user and record their response.
8. Later, execute only verified, allowlisted packages and rescan for proof.

The current remediation implementation stops at step 6. Every draft is marked `simulation` and cannot download packages, elevate privileges, close applications, install updates, or restart a device.

## Agent responsibilities

- Collect read-only device and software inventory.
- Authenticate with a unique device credential.
- Retrieve centrally managed policy.
- Display approved native user notifications.
- Eventually execute typed, signed, allowlisted patch jobs.
- Return installation results and a fresh inventory snapshot.

## Control-plane responsibilities

- Store current and historical inventory.
- Maintain approved patch baselines and installer metadata.
- Calculate patch posture.
- Target devices and rollout rings.
- Require authorization for mutable actions.
- Preserve remediation and user-action evidence.

## Explicitly deferred MDM capabilities

- Apple Automated Device Enrollment
- Configuration profiles
- Declarative Device Management
- FileVault key escrow
- Activation Lock management
- Remote lock and wipe
- Windows CSP policy management

These can be integrated later where OS-native enforcement requires them without changing the core patch-management model.
