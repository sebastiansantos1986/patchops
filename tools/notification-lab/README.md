# Native Notification Lab

This harness validates that a real user click reaches the PatchOps control plane exactly once. It is intentionally locked to `simulation` mode: it cannot install packages, close applications, or restart a device.

## macOS lab test

Start PatchOps with `npm run dev`, then in another terminal run `npm run notification:macos`. Choose a button in the native dialog and inspect recorded events at `http://127.0.0.1:3000/api/notifications/actions`.

## Windows lab test

Start the PatchOps API on the Windows lab device, then run:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\notification-lab\windows-popup.ps1
```

## Automated transport test

With the API running, execute `npm run notification:test`. The test submits the same action twice and verifies that the second delivery is marked as a duplicate while only one event is stored.

## Safety gate before real actions

Replacing simulation with installation or restart requires signed jobs, device authentication, package signature/hash validation, an explicit lab-only policy, execution timeouts, and a second confirmation for restart. Do not remove the simulation lock merely by changing the UI text.
