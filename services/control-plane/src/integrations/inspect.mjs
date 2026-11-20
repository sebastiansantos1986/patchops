// Helpers that let administrators see exactly what each API returns:
// a few raw sample records plus how often every field is populated.

const MAX_DEPTH = 3;

function walk(value, path, depth, seen) {
  if (value === null || value === undefined || value === "" || (Array.isArray(value) && !value.length)) return;
  if (Array.isArray(value)) {
    seen.add(`${path}[]`);
    if (depth < MAX_DEPTH) for (const item of value.slice(0, 5)) walk(item, `${path}[]`, depth + 1, seen);
    return;
  }
  if (typeof value === "object") {
    if (depth >= MAX_DEPTH) { seen.add(path); return; }
    for (const [key, child] of Object.entries(value)) walk(child, path ? `${path}.${key}` : key, depth + 1, seen);
    return;
  }
  seen.add(path);
}

export class FieldStats {
  constructor() { this.total = 0; this.counts = new Map(); this.examples = new Map(); }

  add(record) {
    this.total += 1;
    const seen = new Set();
    walk(record, "", 0, seen);
    for (const path of seen) {
      this.counts.set(path, (this.counts.get(path) ?? 0) + 1);
      if (!this.examples.has(path)) {
        const example = path.split(".").reduce((value, key) => {
          if (value === undefined || value === null) return undefined;
          const clean = key.replace(/\[\]$/g, "");
          const next = value[clean];
          return key.endsWith("[]") && Array.isArray(next) ? next[0] : next;
        }, record);
        if (example !== undefined && typeof example !== "object") this.examples.set(path, String(example).slice(0, 80));
      }
    }
  }

  toJSON() {
    return {
      records: this.total,
      fields: [...this.counts.entries()].map(([field, count]) => ({ field, filled: count, pct: this.total ? Math.round((count / this.total) * 1000) / 10 : 0, example: this.examples.get(field) ?? null }))
        .sort((left, right) => left.field.localeCompare(right.field))
    };
  }
}

// Removes values that look like secrets before samples are shown in the console.
export function redact(value) {
  if (Array.isArray(value)) return value.length > 15 ? [...value.slice(0, 15).map(redact), `… ${value.length - 15} more`] : value.map(redact);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, /secret|password|token|recovery_?key|private/i.test(key) ? "[redacted]" : redact(child)]));
  }
  return value;
}

export class Capability {
  constructor(label, scope) {
    this.label = label;
    this.scope = scope;
    this.state = "not_run";
    this.count = 0;
    this.error = null;
    this.stats = new FieldStats();
    this.samples = [];
    this.synced_at = null;
  }

  begin() { this.stats = new FieldStats(); this.samples = []; this.count = 0; this.error = null; }

  observe(raw) {
    this.count += 1;
    this.stats.add(raw);
    if (this.samples.length < 3) this.samples.push(redact(structuredClone(raw)));
  }

  finish(state = "ok", error = null) { this.state = state; this.error = error; this.synced_at = new Date().toISOString(); }

  toJSON() { return { label: this.label, scope: this.scope, state: this.state, count: this.count, error: this.error, synced_at: this.synced_at, query: this.query ?? null, fields: this.stats.toJSON().fields, samples: this.samples }; }
}
