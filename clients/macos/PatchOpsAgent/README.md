# PatchOps macOS Agent Lab

This is a native SwiftUI test agent for macOS 13 or newer. It provides a polished local dashboard, gathers read-only device and application inventory, enrolls with the PatchOps POC API, and sends native actionable Notification Center alerts.

Version 0.5 runs as a hidden per-user LaunchAgent, refreshes inventory every 15 minutes, and polls the authenticated PatchOps notification queue every 15 seconds. A dashboard administrator controls the test Mac and chooses either a native system banner or a fully branded PUSH-style SwiftUI popup. Delivery and the selected simulation action return to the console; the endpoint user has no agent dashboard or menu-bar controls.

## Safety boundary

This build is permanently in simulation mode. **Install now**, **Later**, and **Details** record a notification action, but never install packages, close applications, or restart the Mac. It does not require administrator privileges and does not install a background daemon.

Collected fields:

- Hostname, hardware model, serial number, and CPU architecture
- macOS version and build
- Uptime, last reboot time, and battery percentage when available
- Application name, version, bundle identifier, and source folder from `/Applications`, `/System/Applications`, and the current user's `Applications` folder

## Build and inspect before installation

From the repository root:

```bash
npm run macos:probe
npm run macos:build
```

The probe prints the exact inventory JSON to the terminal. The build creates `clients/macos/PatchOpsAgent/dist/PatchOps Agent.app` with a local ad-hoc signature suitable for this test Mac.

## Install on a test Mac

Start the local control plane in one terminal:

```bash
npm run api
```

Then build and install the hidden managed agent:

```bash
npm run macos:install
```

The development installer configures the local API and enrollment token, registers `~/Library/LaunchAgents/com.patchops.agent.lab.plist`, and starts the process. Inventory, timing, notification design, and allowed presentation types are controlled from the web console. Enrollment and device credentials are stored in macOS Keychain; they are not written to the settings JSON file.

To verify API enrollment without opening the app, run `npm run macos:sync-probe` while the API is running.

## Current development limits

- The app runs as an unprivileged per-user LaunchAgent; a production system-wide service and privileged patch helper are not implemented.
- The app has a local ad-hoc signature and is not notarized for distribution.
- Non-secret settings are stored in a user settings file; enrollment and agent tokens use macOS Keychain.
- The API uses an in-memory POC store.
- Application inventory is bundle-based; package receipts and vulnerability matching come next.

Before production use, add a Developer ID signature and notarization, mutually authenticated transport, a launch service, signed policy verification, token rotation/revocation, and a separately privileged helper for approved patch operations.
