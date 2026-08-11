#!/bin/sh
# PatchOps macOS VM Lab Installer
# Installs the ad-hoc signed, unprivileged test app for the current user only.

set -eu
SCRIPT_DIRECTORY="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ARCHIVE="$SCRIPT_DIRECTORY/PatchOps-Agent-macOS-0.2.0.zip"
INSTALL_DIRECTORY="$HOME/Applications"

if [ ! -f "$ARCHIVE" ]; then
  echo "Keep this installer beside PatchOps-Agent-macOS-0.2.0.zip, then retry." >&2
  exit 1
fi

mkdir -p "$INSTALL_DIRECTORY"
ditto -x -k "$ARCHIVE" "$INSTALL_DIRECTORY"
codesign --verify --deep --strict "$INSTALL_DIRECTORY/PatchOps Agent.app"

echo "Installed PatchOps Agent in $INSTALL_DIRECTORY"
echo "Open it from Finder, select the hosted development API, and enter the Render enrollment token."
