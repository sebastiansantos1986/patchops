import { spawn } from "node:child_process";

const children = [
  spawn(process.execPath, ["services/control-plane/src/server.mjs"], { stdio: "inherit" }),
  spawn(process.execPath, ["scripts/static-server.mjs"], { stdio: "inherit" })
];

const stop = () => children.forEach((child) => child.kill("SIGTERM"));
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
console.log("PatchOps console: http://127.0.0.1:8765\nPatchOps API:     http://127.0.0.1:3000/api/health");
