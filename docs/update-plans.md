# Update plans

Plan a software update in rings and track every device until it's done. PatchOps doesn't install
anything: you deploy with Intune, Jamf or your usual tool, and each device moves from **To update** to
**Updated** as soon as its inventory (Intune, Jamf, CrowdStrike or the PatchOps agent) reports the new version.

## Create a plan

- **Update plans → New plan**, or click an outdated app under *Start from an outdated app*, or
  **Plan update** next to an app in Posture → Outdated applications. The app and the newest version
  in your fleet are filled in.
- **Which software?** A software condition, e.g. name is "Google Chrome".
- **Updated means version:** this version or newer.
- **Rings:** each device belongs to the first ring it matches. A typical plan:
  - *Pilot*: a group (`e/ Device r/ ( e/ User r/ ( e/ Group f/ Name = "GRP-Pilot" ) )`) or a few device names, 3 days.
  - *Everyone*: tick **Everyone not in an earlier ring**, 2 weeks.
- **Preview on my fleet** shows how many devices each ring has and how many are already updated.

## Read a plan

- The big number is the share of devices with the software that are on the target version or newer.
- Each ring is a bar from its start to its deadline, filled by progress. The vertical line is today.
  Red means past the deadline with devices still to update.
- **Devices** lists every device by ring and status, with the version it reports; export it as CSV to
  hand to whoever deploys.
- Devices without app data (no inventory from any source) are counted separately and don't affect the
  percentage. Devices without the software aren't part of the plan.
- A daily history point is kept for 120 days (the small line under the percentage).
