#!/bin/bash
set -euo pipefail

SCRIPT_DIRECTORY="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIRECTORY="$(cd "$SCRIPT_DIRECTORY/.." && pwd)"
BUILD_DIRECTORY="${PATCHOPS_BUILD_DIRECTORY:-$PROJECT_DIRECTORY/dist}"
APP_DIRECTORY="$BUILD_DIRECTORY/PatchOps Agent.app"
CONTENTS_DIRECTORY="$APP_DIRECTORY/Contents"
MODULE_CACHE_DIRECTORY="${TMPDIR:-/tmp}/patchops-swift-module-cache"

mkdir -p "$BUILD_DIRECTORY" "$MODULE_CACHE_DIRECTORY"
TEMP_APP_DIRECTORY="$(mktemp -d "$BUILD_DIRECTORY/.PatchOpsAgent.XXXXXX")/PatchOps Agent.app"
trap 'rm -rf "$(dirname "$TEMP_APP_DIRECTORY")"' EXIT
mkdir -p "$TEMP_APP_DIRECTORY/Contents/MacOS" "$TEMP_APP_DIRECTORY/Contents/Resources"

CLANG_MODULE_CACHE_PATH="$MODULE_CACHE_DIRECTORY" \
SWIFT_MODULE_CACHE_PATH="$MODULE_CACHE_DIRECTORY" \
xcrun swiftc \
  -swift-version 5 \
  -parse-as-library \
  -O \
  -o "$TEMP_APP_DIRECTORY/Contents/MacOS/PatchOpsAgent" \
  "$PROJECT_DIRECTORY"/Sources/*.swift \
  -framework SwiftUI \
  -framework AppKit \
  -framework UserNotifications

cp "$PROJECT_DIRECTORY/Info.plist" "$TEMP_APP_DIRECTORY/Contents/Info.plist"
codesign --force --deep --sign - "$TEMP_APP_DIRECTORY"

if [ -e "$APP_DIRECTORY" ]; then
  BACKUP_DIRECTORY="$BUILD_DIRECTORY/PatchOps Agent.previous.app"
  if [ -e "$BACKUP_DIRECTORY" ]; then
    mv "$BACKUP_DIRECTORY" "$BUILD_DIRECTORY/PatchOps Agent.previous.$(date +%Y%m%d%H%M%S).app"
  fi
  mv "$APP_DIRECTORY" "$BACKUP_DIRECTORY"
fi
mv "$TEMP_APP_DIRECTORY" "$APP_DIRECTORY"

echo "Built: $APP_DIRECTORY"
echo "Signature: local ad-hoc test signature"
