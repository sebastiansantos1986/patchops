#!/bin/sh
# Removes the PatchOps Agent for the current Mac user (app, background agent, settings and Keychain tokens).
launchctl bootout "gui/$(id -u)/com.patchops.agent.lab" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/com.patchops.agent.lab.plist"
rm -rf "$HOME/Applications/PatchOps Agent.app" "$HOME/Library/Application Support/PatchOpsAgent"
for account in enrollment-token agent-token; do security delete-generic-password -s com.patchops.agent -a "$account" >/dev/null 2>&1 || true; done
echo "PatchOps Agent removed."
