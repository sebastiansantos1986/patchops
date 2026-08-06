import { cp, mkdir, rm } from "node:fs/promises";

const output = new URL("../dist-web/", import.meta.url);

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
await Promise.all([
  cp(new URL("../index.html", import.meta.url), new URL("index.html", output)),
  cp(new URL("../config.js", import.meta.url), new URL("config.js", output)),
  cp(new URL("../downloads", import.meta.url), new URL("downloads", output), { recursive: true })
]);

console.log("Prepared PatchOps dashboard assets in dist-web/");
