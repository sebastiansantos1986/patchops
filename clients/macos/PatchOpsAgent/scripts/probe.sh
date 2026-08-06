#!/bin/bash
set -euo pipefail

SCRIPT_DIRECTORY="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIRECTORY="$(cd "$SCRIPT_DIRECTORY/.." && pwd)"
BUILD_DIRECTORY="${TMPDIR:-/tmp}/patchops-agent-probe"
MODULE_CACHE_DIRECTORY="$BUILD_DIRECTORY/module-cache"

mkdir -p "$BUILD_DIRECTORY" "$MODULE_CACHE_DIRECTORY"
CLANG_MODULE_CACHE_PATH="$MODULE_CACHE_DIRECTORY" \
SWIFT_MODULE_CACHE_PATH="$MODULE_CACHE_DIRECTORY" \
xcrun swiftc \
  -swift-version 5 \
  -parse-as-library \
  -o "$BUILD_DIRECTORY/inventory-probe" \
  "$PROJECT_DIRECTORY/Sources/Models.swift" \
  "$PROJECT_DIRECTORY/Sources/InventoryCollector.swift" \
  "$PROJECT_DIRECTORY/Tools/InventoryProbe.swift"

"$BUILD_DIRECTORY/inventory-probe"
