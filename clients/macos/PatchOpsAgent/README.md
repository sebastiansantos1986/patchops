# PatchOps macOS Agent Lab

This is a native SwiftUI test agent for macOS 13 or newer. It provides a polished local dashboard, gathers read-only device and application inventory, enrolls with the PatchOps POC API, and sends native actionable Notification Center alerts.

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

Then build, copy to `~/Applications`, and open the agent:

```bash
npm run macos:install
```

In the app:

1. Select **Overview** and choose **Scan now**.
2. Review the **Inventory** list.
3. Choose **Sync to PatchOps** while the local API is running.
4. Select **Notifications**, grant permission, and send a test notification.
5. Click a notification action and confirm its simulation result in the app or at `http://127.0.0.1:3000/api/notifications/actions`.

To verify API enrollment without opening the app, run `npm run macos:sync-probe` while the API is running.

## Current development limits

- The app runs when opened; it is not yet a LaunchAgent or root LaunchDaemon.
- The app has a local ad-hoc signature and is not notarized for distribution.
- POC settings and tokens are stored in a user settings file, not Keychain.
- The API uses an in-memory POC store.
- Application inventory is bundle-based; package receipts and vulnerability matching come next.

Before production use, add a Developer ID signature and notarization, Keychain-backed enrollment identity, mutually authenticated transport, a launch service, signed policy verification, and a separately privileged helper for approved patch operations.
