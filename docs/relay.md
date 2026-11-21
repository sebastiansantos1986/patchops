# Relay: show your full fleet on the hosted PatchOps without storing credentials there

Your local PatchOps keeps the Intune, Jamf and CrowdStrike credentials in `.env` and syncs as usual.
After each sync it uploads the resulting device data to the hosted PatchOps. The hosted copy shows
those sources as **Relayed**, merged with the agents that report to it directly.

```
Intune / Jamf / CrowdStrike ──(your credentials, on your Mac)──> local PatchOps ──(relay token, HTTPS)──> hosted PatchOps <── agents
```

## What is sent, and what isn't

| Sent | Only if you switch it on | Never sent |
|---|---|---|
| Device name, serial, model, platform, OS version and build | User names and emails, and Entra group membership (`PATCHOPS_RELAY_USERS=true`) | API credentials or tokens |
| Installed apps and versions, installed KBs | CrowdStrike vulnerabilities per device (`PATCHOPS_RELAY_VULNERABILITIES=true`) | Raw API payloads (IP and MAC addresses, internal IDs) |
| Compliance, encryption, last check-in, Falcon sensor status | | Sample records shown on Data sources |

The hosted copy still works out Apple and Microsoft OS vulnerabilities itself from the public feeds,
based on each device's OS version.

The relay token can only upload. It can't log in, read data back or reach Intune, Jamf or CrowdStrike.
If it leaks, change it in both places; the worst someone could do with it is upload fake devices.

## Set it up

1. **Hosted (Render):** the API needs `PATCHOPS_RELAY_TOKEN`. The Blueprint generates one; if your service
   doesn't have it yet, add it under the API's **Environment** with a long random value, e.g. from
   `openssl rand -hex 32` on your Mac. Keep no Intune / Jamf / CrowdStrike variables on the hosted API.
2. **Local (`.env` on your Mac):**

   ```
   PATCHOPS_RELAY_URL=https://patchops-api-<name>.onrender.com/api
   PATCHOPS_RELAY_TOKEN=<the same value as on Render>
   ```

3. Restart `npm run dev`. The terminal shows `[relay] Microsoft Intune: sent 1,234 devices (…)` for each
   source shortly after start (from the saved data) and after every sync.
4. Hosted dashboard → **Data sources** shows each source as **Relayed from <your Mac's name>**, with the time.

The hosted data is as fresh as your Mac's last sync: when your Mac is off, the hosted site keeps showing
the last upload. The first upload after the free Render service has been asleep can take a minute.
