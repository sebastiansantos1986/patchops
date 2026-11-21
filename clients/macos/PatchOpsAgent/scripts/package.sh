#!/bin/bash
# Builds the Mac agent and makes a kit to copy to test Macs:
#   dist/PatchOps-Agent-macOS-kit.zip  ->  PatchOps-Agent-macOS.zip, install-on-mac.sh, uninstall-on-mac.sh
set -euo pipefail
SCRIPT_DIRECTORY="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIRECTORY="$(cd "$SCRIPT_DIRECTORY/.." && pwd)"
DIST="$PROJECT_DIRECTORY/dist"
KIT="$DIST/PatchOps-Agent-macOS-kit"

"$SCRIPT_DIRECTORY/build.sh"
rm -rf "$KIT" "$KIT.zip"
mkdir -p "$KIT"
ditto -c -k --keepParent "$DIST/PatchOps Agent.app" "$KIT/PatchOps-Agent-macOS.zip"
cp "$SCRIPT_DIRECTORY/install-on-mac.sh" "$SCRIPT_DIRECTORY/uninstall-on-mac.sh" "$KIT/"
chmod +x "$KIT"/*.sh
(cd "$DIST" && ditto -c -k --keepParent "PatchOps-Agent-macOS-kit" "PatchOps-Agent-macOS-kit.zip")
shasum -a 256 "$KIT/PatchOps-Agent-macOS.zip"
echo "Kit ready: $KIT.zip"
