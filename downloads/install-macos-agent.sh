#!/bin/sh
# PatchOps macOS Agent Bootstrap - POC placeholder
# This script is for product prototype/demo purposes only.
# A production installer should use a signed and notarized PKG.

TENANT="${TENANT:-acme-prod}"
ENROLL_TOKEN="${ENROLL_TOKEN:-POC-MACOS-ENROLL-TOKEN}"
API_URL="${API_URL:-https://api.patchops.example}"

echo "PatchOps macOS Agent bootstrap"
echo "Tenant: ${TENANT}"
echo "API: ${API_URL}"
echo "Enrollment token: ${ENROLL_TOKEN}"
echo ""
echo "POC only: download signed PKG, verify checksum, install LaunchDaemon, enroll device."

