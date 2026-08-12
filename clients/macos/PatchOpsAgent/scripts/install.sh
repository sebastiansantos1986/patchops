#!/bin/bash
set -euo pipefail

SCRIPT_DIRECTORY="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIRECTORY="$(cd "$SCRIPT_DIRECTORY/.." && pwd)"
SOURCE_APP="$PROJECT_DIRECTORY/dist/PatchOps Agent.app"
INSTALL_DIRECTORY="$HOME/Applications"
INSTALLED_APP="$INSTALL_DIRECTORY/PatchOps Agent.app"
LAUNCH_AGENTS_DIRECTORY="$HOME/Library/LaunchAgents"
LAUNCH_AGENT="$LAUNCH_AGENTS_DIRECTORY/com.patchops.agent.lab.plist"
SUPPORT_DIRECTORY="$HOME/Library/Application Support/PatchOpsAgent"

"$SCRIPT_DIRECTORY/build.sh"
mkdir -p "$INSTALL_DIRECTORY"

if [ -e "$INSTALLED_APP" ]; then
  BACKUP_APP="$INSTALL_DIRECTORY/PatchOps Agent.previous.$(date +%Y%m%d%H%M%S).app"
  mv "$INSTALLED_APP" "$BACKUP_APP"
  echo "Preserved previous app: $BACKUP_APP"
fi

/usr/bin/ditto "$SOURCE_APP" "$INSTALLED_APP"
codesign --verify --deep --strict "$INSTALLED_APP"
mkdir -p "$SUPPORT_DIRECTORY"
cat > "$SUPPORT_DIRECTORY/settings.json" <<JSON
{"apiURL":"${PATCHOPS_API_URL:-http://127.0.0.1:3000/api}","tenantID":"${PATCHOPS_TENANT_ID:-acme-prod}","enrollmentToken":"","deviceID":null,"agentToken":null}
JSON
security add-generic-password -U -s com.patchops.agent -a enrollment-token -w "${PATCHOPS_ENROLLMENT_TOKEN:-POC-MACOS-ENROLL-TOKEN}" -T "$INSTALLED_APP/Contents/MacOS/PatchOpsAgent" >/dev/null
mkdir -p "$LAUNCH_AGENTS_DIRECTORY"
cat > "$LAUNCH_AGENT" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.patchops.agent.lab</string>
  <key>ProgramArguments</key><array><string>$INSTALLED_APP/Contents/MacOS/PatchOpsAgent</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
</dict></plist>
PLIST
launchctl bootout "gui/$(id -u)/com.patchops.agent.lab" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$LAUNCH_AGENT"
echo "Installed managed background agent: $INSTALLED_APP"
echo "LaunchAgent: $LAUNCH_AGENT"
