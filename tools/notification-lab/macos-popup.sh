#!/bin/bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This lab popup runs only on macOS."
  exit 1
fi

if ! choice=$(osascript 2>/dev/null <<'APPLESCRIPT'
set result to display dialog "Two verified security updates are ready: Google Chrome and Zoom.\n\nLAB MODE: buttons record actions only. No software will be installed." with title "PatchOps Security Update" buttons {"Details", "Later", "Install now"} default button "Install now" with icon caution
return button returned of result
APPLESCRIPT
); then
  echo "The popup needs an interactive macOS desktop session. Run this command from your normal Terminal while logged into the desktop."
  exit 1
fi

case "$choice" in
  "Install now") action="install_now" ;;
  "Later") action="defer" ;;
  *) action="details" ;;
esac

node "$(dirname "$0")/record-action.mjs" "$action" macos
