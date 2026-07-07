# PatchOps Windows Agent Bootstrap - POC placeholder
# This script is for product prototype/demo purposes only.
# A production installer should use a signed MSI/MSIX and a signed agent binary.

param(
  [string]$Tenant = "acme-prod",
  [string]$EnrollToken = "POC-WINDOWS-ENROLL-TOKEN",
  [string]$ApiUrl = "https://api.patchops.example"
)

Write-Host "PatchOps Windows Agent bootstrap"
Write-Host "Tenant: $Tenant"
Write-Host "API: $ApiUrl"
Write-Host "Enrollment token: $EnrollToken"
Write-Host ""
Write-Host "POC only: download signed MSI, verify checksum, install Windows service, enroll device."

