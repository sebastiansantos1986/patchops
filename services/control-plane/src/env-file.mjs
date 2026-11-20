import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

// Loads KEY=value pairs from a local .env file (never committed) without
// overriding variables already set in the environment. Works on Node 20+.
export function loadEnvFile(path = resolve(process.cwd(), ".env"), env = process.env) {
  if (!existsSync(path)) return 0;
  let loaded = 0;
  for (const rawLine of readFileSync(path, "utf8").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match) continue;
    const [, key, rawValue] = match;
    let value = rawValue.trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, "");
    if (env[key] === undefined) {
      env[key] = value;
      loaded += 1;
    }
  }
  return loaded;
}
