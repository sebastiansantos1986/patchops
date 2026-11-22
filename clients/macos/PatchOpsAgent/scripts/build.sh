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

for ARCHITECTURE in arm64 x86_64; do
  CLANG_MODULE_CACHE_PATH="$MODULE_CACHE_DIRECTORY/$ARCHITECTURE" \
  SWIFT_MODULE_CACHE_PATH="$MODULE_CACHE_DIRECTORY/$ARCHITECTURE" \
  xcrun swiftc \
    -target "$ARCHITECTURE-apple-macos13.0" \
    -swift-version 5 \
    -parse-as-library \
    -O \
    -o "$BUILD_DIRECTORY/PatchOpsAgent-$ARCHITECTURE" \
    "$PROJECT_DIRECTORY"/Sources/*.swift \
    -framework SwiftUI \
    -framework AppKit \
    -framework Security \
    -framework UserNotifications
done

xcrun lipo -create \
  "$BUILD_DIRECTORY/PatchOpsAgent-arm64" \
  "$BUILD_DIRECTORY/PatchOpsAgent-x86_64" \
  -output "$TEMP_APP_DIRECTORY/Contents/MacOS/PatchOpsAgent"
rm -f "$BUILD_DIRECTORY/PatchOpsAgent-arm64" "$BUILD_DIRECTORY/PatchOpsAgent-x86_64"

cp "$PROJECT_DIRECTORY/Info.plist" "$TEMP_APP_DIRECTORY/Contents/Info.plist"

# App icon from the PatchOps brand artwork (assets/brand/patchops-icon-1024.png).
ICON_SOURCE="$PROJECT_DIRECTORY/../../../assets/brand/patchops-icon-1024.png"
if [ -f "$ICON_SOURCE" ]; then
  ICONSET="$(dirname "$TEMP_APP_DIRECTORY")/AppIcon.iconset"
  mkdir -p "$ICONSET"
  for SIZE in 16 32 128 256 512; do
    sips -z "$SIZE" "$SIZE" "$ICON_SOURCE" --out "$ICONSET/icon_${SIZE}x${SIZE}.png" >/dev/null
    sips -z "$((SIZE * 2))" "$((SIZE * 2))" "$ICON_SOURCE" --out "$ICONSET/icon_${SIZE}x${SIZE}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "$TEMP_APP_DIRECTORY/Contents/Resources/AppIcon.icns"
fi
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
