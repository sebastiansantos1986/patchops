#!/bin/sh
# PatchOps Agent for Mac: installer for test Macs.
# Run it as the Mac's normal user (not with sudo), in the folder that also contains PatchOps-Agent-macOS.zip:
#
#   PATCHOPS_API_URL=https://your-patchops-api.example.com/api sh install-on-mac.sh
#
# It asks for the enrollment token (input hidden) unless PATCHOPS_ENROLLMENT_TOKEN is set.
# The agent is read-only: it reports hardware, macOS version and apps every 15 minutes, runs as a
# hidden per-user background agent, and needs no administrator rights.
set -eu
SCRIPT_DIRECTORY="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ARCHIVE="$SCRIPT_DIRECTORY/PatchOps-Agent-macOS.zip"
INSTALL_DIRECTORY="$HOME/Applications"
INSTALLED_APP="$INSTALL_DIRECTORY/PatchOps Agent.app"
LAUNCH_AGENT="$HOME/Library/LaunchAgents/com.patchops.agent.lab.plist"
SUPPORT_DIRECTORY="$HOME/Library/Application Support/PatchOpsAgent"
SETTINGS_FILE="$SUPPORT_DIRECTORY/settings.json"

[ "$(id -u)" != "0" ] || { echo "Run this as the Mac's user, not with sudo." >&2; exit 1; }
[ -f "$ARCHIVE" ] || { echo "Keep this installer next to PatchOps-Agent-macOS.zip." >&2; exit 1; }

API_URL="${PATCHOPS_API_URL:-}"
if [ -z "$API_URL" ]; then printf "PatchOps API URL (https://…/api): "; IFS= read -r API_URL; fi
API_URL="${API_URL%/}"
case "$API_URL" in */api) ;; *) API_URL="$API_URL/api" ;; esac
case "$API_URL" in https://*|http://127.0.0.1*|http://localhost*) ;; *) echo "Use an https:// API URL." >&2; exit 1 ;; esac

ENROLLMENT_TOKEN="${PATCHOPS_ENROLLMENT_TOKEN:-}"
if [ -z "$ENROLLMENT_TOKEN" ]; then
  printf "PatchOps enrollment token: "; stty -echo; IFS= read -r ENROLLMENT_TOKEN; stty echo; printf "\n"
fi
[ -n "$ENROLLMENT_TOKEN" ] || { echo "An enrollment token is required." >&2; exit 1; }

launchctl bootout "gui/$(id -u)/com.patchops.agent.lab" 2>/dev/null || true
mkdir -p "$INSTALL_DIRECTORY"
rm -rf "$INSTALLED_APP"
ditto -x -k "$ARCHIVE" "$INSTALL_DIRECTORY"
# This build has a local (ad-hoc) signature, not an Apple Developer ID. A copied or downloaded zip is
# quarantined and macOS would refuse to start it; for these test Macs we clear the flag on this one app.
xattr -dr com.apple.quarantine "$INSTALLED_APP" 2>/dev/null || true
codesign --verify --deep --strict "$INSTALLED_APP"

mkdir -p "$SUPPORT_DIRECTORY"
cat > "$SETTINGS_FILE" <<JSON
{"apiURL":"$API_URL","tenantID":"default","enrollmentToken":"","deviceID":null,"agentToken":null}
JSON
# Tokens live in the user's Keychain, never in the settings file.
security delete-generic-password -s com.patchops.agent -a agent-token >/dev/null 2>&1 || true
security add-generic-password -U -s com.patchops.agent -a enrollment-token -w "$ENROLLMENT_TOKEN" -T "$INSTALLED_APP/Contents/MacOS/PatchOpsAgent" >/dev/null

mkdir -p "$(dirname "$LAUNCH_AGENT")"
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
launchctl bootstrap "gui/$(id -u)" "$LAUNCH_AGENT"
echo "PatchOps Agent installed for $(id -un). It reports to $API_URL and starts at login."
echo "Remove it with: sh uninstall-on-mac.sh"
