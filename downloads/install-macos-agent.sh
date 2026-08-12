#!/bin/sh
# PatchOps macOS VM Lab Installer
# Installs the ad-hoc signed, unprivileged test app for the current user only.

set -eu
SCRIPT_DIRECTORY="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ARCHIVE="$SCRIPT_DIRECTORY/PatchOps-Agent-macOS-0.5.0.zip"
INSTALL_DIRECTORY="$HOME/Applications"
INSTALLED_APP="$INSTALL_DIRECTORY/PatchOps Agent.app"
LAUNCH_AGENTS_DIRECTORY="$HOME/Library/LaunchAgents"
LAUNCH_AGENT="$LAUNCH_AGENTS_DIRECTORY/com.patchops.agent.lab.plist"
SUPPORT_DIRECTORY="$HOME/Library/Application Support/PatchOpsAgent"
SETTINGS_FILE="$SUPPORT_DIRECTORY/settings.json"
API_URL="${PATCHOPS_API_URL:-https://patchops-api-sebastiansantos1986.onrender.com/api}"
TENANT_ID="${PATCHOPS_TENANT_ID:-acme-prod}"

if [ ! -f "$ARCHIVE" ]; then
  echo "Keep this installer beside PatchOps-Agent-macOS-0.5.0.zip, then retry." >&2
  exit 1
fi

mkdir -p "$INSTALL_DIRECTORY"
ditto -x -k "$ARCHIVE" "$INSTALL_DIRECTORY"
codesign --verify --deep --strict "$INSTALLED_APP"
mkdir -p "$SUPPORT_DIRECTORY"
if [ ! -f "$SETTINGS_FILE" ]; then
  cat > "$SETTINGS_FILE" <<JSON
{"apiURL":"$API_URL","tenantID":"$TENANT_ID","enrollmentToken":"","deviceID":null,"agentToken":null}
JSON
fi
if ! security find-generic-password -s com.patchops.agent -a enrollment-token >/dev/null 2>&1; then
  ENROLLMENT_TOKEN="${PATCHOPS_ENROLLMENT_TOKEN:-}"
  if [ -z "$ENROLLMENT_TOKEN" ]; then
    printf "PatchOps enrollment token: "
    stty -echo
    IFS= read -r ENROLLMENT_TOKEN
    stty echo
    printf "\n"
  fi
  [ -n "$ENROLLMENT_TOKEN" ] || { echo "An enrollment token is required for a new installation." >&2; exit 1; }
  security add-generic-password -U -s com.patchops.agent -a enrollment-token -w "$ENROLLMENT_TOKEN" -T "$INSTALLED_APP/Contents/MacOS/PatchOpsAgent" >/dev/null
fi
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

echo "Installed PatchOps managed background agent in $INSTALL_DIRECTORY"
echo "The agent now starts at login, stays hidden, syncs inventory, and receives console notifications."
