#!/bin/bash
set -euo pipefail

SCRIPT_DIRECTORY="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIRECTORY="$(cd "$SCRIPT_DIRECTORY/.." && pwd)"
SOURCE_APP="$PROJECT_DIRECTORY/dist/PatchOps Agent.app"
INSTALL_DIRECTORY="$HOME/Applications"
INSTALLED_APP="$INSTALL_DIRECTORY/PatchOps Agent.app"

"$SCRIPT_DIRECTORY/build.sh"
mkdir -p "$INSTALL_DIRECTORY"

if [ -e "$INSTALLED_APP" ]; then
  BACKUP_APP="$INSTALL_DIRECTORY/PatchOps Agent.previous.$(date +%Y%m%d%H%M%S).app"
  mv "$INSTALLED_APP" "$BACKUP_APP"
  echo "Preserved previous app: $BACKUP_APP"
fi

/usr/bin/ditto "$SOURCE_APP" "$INSTALLED_APP"
codesign --verify --deep --strict "$INSTALLED_APP"
open "$INSTALLED_APP"
echo "Installed and opened: $INSTALLED_APP"
