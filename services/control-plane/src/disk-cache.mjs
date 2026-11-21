// Local, private snapshot of what the connectors and public feeds returned, so a
// restart shows data immediately and syncs only fetch what changed.
//
// Safety:
//  * contains inventory and vulnerability data only: never API secrets or tokens
//  * folder is created 0700 and files 0600 (readable only by the account running PatchOps)
//  * default location .patchops-cache/ in the project, which is git-ignored
//  * files are written atomically (temp file + rename), so a crash can't leave a half file
//  * POSTURE_CACHE=false turns it off; deleting the folder simply forces a full re-download

import { mkdir, readFile, rename, rm, writeFile, chmod } from "node:fs/promises";
import { resolve, join } from "node:path";
import { promisify } from "node:util";
import { gunzip as gunzipCallback, gzip as gzipCallback } from "node:zlib";

// Compression runs off the main thread so the dashboard stays responsive while saving.
const gzip = promisify(gzipCallback);
const gunzip = promisify(gunzipCallback);

const FORMAT_VERSION = 1;

export function cacheSettings(env = process.env) {
  return {
    enabled: !/^(0|false|no)$/i.test(env.POSTURE_CACHE ?? "true"),
    dir: resolve(env.POSTURE_CACHE_DIR?.trim() || resolve(process.cwd(), ".patchops-cache"))
  };
}

export class DiskCache {
  constructor({ enabled = true, dir } = {}) {
    this.enabled = enabled && Boolean(dir);
    this.dir = dir;
    this.writes = new Map();
    this.lastError = null;
  }

  path(name) {
    if (!/^[a-z0-9_-]+$/i.test(name)) throw new Error(`invalid cache name ${name}`);
    return join(this.dir, `${name}.json.gz`);
  }

  async read(name) {
    if (!this.enabled) return null;
    try {
      const parsed = JSON.parse((await gunzip(await readFile(this.path(name)))).toString("utf8"));
      return parsed?.format === FORMAT_VERSION ? parsed.data : null;
    } catch (error) {
      if (error.code !== "ENOENT") this.lastError = `Could not read cache ${name}: ${error.message}`;
      return null;
    }
  }

  // Writes are serialized per file; the latest value always wins.
  write(name, data) {
    if (!this.enabled) return Promise.resolve();
    const previous = this.writes.get(name) ?? Promise.resolve();
    const next = previous.catch(() => {}).then(async () => {
      await mkdir(this.dir, { recursive: true, mode: 0o700 });
      await chmod(this.dir, 0o700).catch(() => {});
      const target = this.path(name);
      const temp = `${target}.${process.pid}.tmp`;
      await writeFile(temp, await gzip(JSON.stringify({ format: FORMAT_VERSION, saved_at: new Date().toISOString(), data }), { level: 4 }), { mode: 0o600 });
      await rename(temp, target);
      this.lastError = null;
    }).catch((error) => { this.lastError = `Could not save cache ${name}: ${error.message}`; });
    this.writes.set(name, next);
    return next;
  }

  async clear() {
    if (this.enabled) await rm(this.dir, { recursive: true, force: true });
  }
}
