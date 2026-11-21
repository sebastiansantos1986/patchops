// Makes dist/PatchOps-Agent-Windows-kit.zip with the agent, installer, uninstaller and README.
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const kit = join(root, "dist", "PatchOps-Agent-Windows-kit");
rmSync(kit, { recursive: true, force: true });
rmSync(`${kit}.zip`, { force: true });
mkdirSync(kit, { recursive: true });
for (const file of ["PatchOpsAgent.ps1", "Install-PatchOpsAgent.ps1", "Uninstall-PatchOpsAgent.ps1", "README.md"]) cpSync(join(root, "agents", "windows", file), join(kit, file));
execFileSync("zip", ["-qr", "PatchOps-Agent-Windows-kit.zip", "PatchOps-Agent-Windows-kit"], { cwd: join(root, "dist") });
console.log(`Kit ready: ${kit}.zip`);
