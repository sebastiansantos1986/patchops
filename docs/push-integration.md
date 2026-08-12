# PUSH notification integration

PatchOps incorporates the white-label notification design concepts from Sebastian Santos's [PUSH](https://github.com/sebastiansantos1986/PUSH) project. The integration intentionally separates presentation from enforcement:

- The PatchOps API authenticates administrators and devices, stores settings, queues notifications, and records delivery evidence.
- The PatchOps macOS agent polls its device-scoped queue and chooses either a native system banner or the custom PUSH-style SwiftUI popup.
- The Settings workspace controls application name, organization, accent color, SF Symbol, popup size and position, sound, support contacts, button labels, close behavior, and deferral policy.
- Endpoint actions are simulation-only in the VM lab. The PUSH privileged installer, update commands, LaunchDaemon, fullscreen hard block, and password workflows are not included.

PUSH is MIT licensed. Copyright © 2026 Sebastian Santos.
