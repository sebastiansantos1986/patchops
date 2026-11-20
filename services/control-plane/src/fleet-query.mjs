// A small, Cyclops-style query language over the merged fleet.
//
//   e/ Device f/ Platform = windows f/ OSRelease = 11 f/ LastSeenAt < 7d
//   e/ Device f/ Platform = windows r/ ( e/ SecurityPatch f/ UniquePatchId contains_any (KB5032190,KB5033375) )
//   e/ Device f/ Platform = macos not r/ ( e/ SoftwareRule f/ Name = "Okta Verify" f/ Status = installed )
//
// e/ picks an entity, f/ adds a filter (all filters must match), r/ ( … ) requires
// at least one related record matching the inner query, and "not r/" requires none.
// Whole queries can be combined with "and" / "or".

import { compareVersions } from "./patch-engine.mjs";

export class QueryError extends Error {
  constructor(message, position) {
    super(position === undefined ? message : `${message} (at character ${position + 1})`);
    this.name = "QueryError";
    this.position = position;
  }
}

const OPERATORS = ["not_contains", "contains_any", "contains_all", "not_in", "starts_with", "ends_with", "not_exists", "contains", "exists", "in", "!=", ">=", "<=", "=", ">", "<", "~"];
const UNARY = new Set(["exists", "not_exists"]);

const windowsRelease = (device) => {
  const build = Number(String(device.os?.version ?? "").split(".")[2]);
  return build ? (build >= 22000 ? "11" : "10") : "";
};

// Field definitions: getter + type. Types drive comparison: string, number, version, date, bool.
export const ENTITIES = {
  Device: {
    description: "One merged device (Intune + Jamf + PatchOps agent).",
    fields: {
      Hostname: ["string", (d) => d.hostname, "Device name"],
      SerialNumber: ["string", (d) => d.serial_number, "Hardware serial number"],
      Platform: ["string", (d) => d.platform, "windows or macos"],
      OSName: ["string", (d) => d.os?.name, "e.g. Windows 11, macOS"],
      OSVersion: ["version", (d) => d.os?.version, "Full version, compared as a version (e.g. 10.0.26100.7171, 26.1)"],
      OSRelease: ["number", (d) => Number(d.platform === "windows" ? windowsRelease(d) : String(d.os?.version ?? "").split(".")[0]) || null, "Windows: 10 or 11. macOS: major version (e.g. 26)"],
      OSBuild: ["number", (d) => (d.platform === "windows" ? Number(String(d.os?.version ?? "").split(".")[2]) || null : null), "Windows feature build (e.g. 26100)"],
      OSRevision: ["number", (d) => (d.platform === "windows" ? Number(String(d.os?.version ?? "").split(".")[3]) || null : null), "Windows update build revision (UBR, e.g. 7171)"],
      User: ["string", (d) => d.user?.name, "Primary user's name"],
      Email: ["string", (d) => d.user?.email, "Primary user's email / UPN"],
      Model: ["string", (d) => d.model, "Hardware model"],
      Manufacturer: ["string", (d) => d.manufacturer, "Hardware manufacturer"],
      LastSeenAt: ["date", (d) => d.last_check_in, "Most recent check-in. LastSeenAt < 7d = seen in the last 7 days"],
      Encrypted: ["bool", (d) => d.encrypted, "FileVault / BitLocker on"],
      Compliance: ["string", (d) => d.compliance ?? "", "Intune compliance state (compliant, noncompliant, ingraceperiod…)"],
      RiskLevel: ["string", (d) => d.risk_level, "critical, high, medium, low or healthy"],
      RiskScore: ["number", (d) => d.risk_score, "0-100"],
      IssueCount: ["number", (d) => d.issues?.length ?? 0, "Number of open issues"],
      InIntune: ["bool", (d) => Boolean(d.sources?.intune), "Present in Intune"],
      InJamf: ["bool", (d) => Boolean(d.sources?.jamf), "Present in Jamf"],
      HasAgent: ["bool", (d) => Boolean(d.sources?.agent), "PatchOps agent installed"],
      InCrowdStrike: ["bool", (d) => Boolean(d.sources?.crowdstrike), "Has a CrowdStrike Falcon host record"],
      CrowdStrikeReporting: ["bool", (d) => Boolean(d.crowdstrike_reporting), "Falcon sensor seen in the last 7 days"],
      CrowdStrikeLastSeenAt: ["date", (d) => d.sources?.crowdstrike?.last_check_in ?? null, "When the Falcon sensor last reported"],
      CrowdStrikeSensorVersion: ["version", (d) => d.crowdstrike?.version ?? null, "Falcon sensor version"],
      CrowdStrikeRFM: ["bool", (d) => (d.crowdstrike ? Boolean(d.crowdstrike.rfm) : null), "Sensor in reduced functionality mode"],
      CrowdStrikeContained: ["bool", (d) => (d.crowdstrike ? Boolean(d.crowdstrike.contained) : null), "Host network-contained"],
      CrowdStrikeTags: ["string", (d) => (d.crowdstrike?.tags ?? []).join(", "), "Falcon sensor/grouping tags"],
      OpenCVEs: ["number", (d) => d.vuln_summary?.total ?? null, "Open CVEs from CrowdStrike Spotlight"],
      CriticalCVEs: ["number", (d) => d.vuln_summary?.critical ?? null, "Open critical CVEs"],
      HighCVEs: ["number", (d) => d.vuln_summary?.high ?? null, "Open high CVEs"],
      ExploitedCVEs: ["number", (d) => d.vuln_summary?.exploited ?? null, "CVEs on CISA KEV or actively used"],
      HighestCVSS: ["number", (d) => d.vuln_summary?.max_score ?? null, "Highest CVSS base score on the device"],
      Ownership: ["string", (d) => d.ownership, "Intune ownership (company / personal)"],
      AppCount: ["number", (d) => d.apps?.length ?? 0, "Installed applications"]
    },
    relations: {
      App: (d) => d.apps ?? [],
      SecurityPatch: (d) => (d.patches ?? []).filter((patch) => patch.status === "installed").concat(
        (d.reported_kbs ?? []).filter((kb) => !(d.patches ?? []).some((patch) => patch.kb === kb)).map((kb) => ({ kb, title: "", status: "installed", method: "reported" }))
      ),
      MissingPatch: (d) => (d.patches ?? []).filter((patch) => patch.status === "missing"),
      SoftwareRule: (d) => d.software ?? [],
      Vulnerability: (d) => d.vulnerabilities ?? [],
      Issue: (d) => d.issues ?? []
    }
  },
  App: {
    description: "An installed application on the device.",
    fields: {
      Name: ["string", (a) => a.name, "Application name"],
      Version: ["version", (a) => a.version, "Installed version"],
      Publisher: ["string", (a) => a.publisher, "Publisher (Windows)"],
      BundleId: ["string", (a) => a.bundle_id, "Bundle identifier (macOS)"]
    }
  },
  SecurityPatch: {
    description: "A Windows update (KB) installed on the device: tracked KBs inferred from the build number, plus any KBs reported by the Intune Remediation script.",
    fields: {
      UniquePatchId: ["string", (p) => p.kb, "KB number, e.g. KB5032190"],
      Title: ["string", (p) => p.title, "Tracked update title"],
      Method: ["string", (p) => p.method, "build (inferred) or reported (exact)"]
    }
  },
  MissingPatch: {
    description: "A Windows update the device lacks: tracked KBs (by build number) plus KBs CrowdStrike Spotlight recommends.",
    fields: {
      UniquePatchId: ["string", (p) => p.kb, "KB number"],
      Title: ["string", (p) => p.title, "Tracked update title, or the CVEs it fixes"],
      Severity: ["string", (p) => p.severity, "Tracked update severity, or the highest CVE severity it fixes"],
      Method: ["string", (p) => p.method, "build (tracked update) or spotlight (CrowdStrike)"]
    }
  },
  Vulnerability: {
    description: "An open vulnerability reported by CrowdStrike Spotlight.",
    fields: {
      CVE: ["string", (v) => v.cve, "CVE id, e.g. CVE-2025-21298"],
      Severity: ["string", (v) => v.severity, "critical, high, medium or low"],
      Score: ["number", (v) => v.score, "CVSS base score"],
      ExPRT: ["string", (v) => v.exprt, "CrowdStrike ExPRT.AI rating"],
      ExploitStatus: ["string", (v) => v.exploit, "Unproven, Available, Easily accessible or Actively used"],
      KEV: ["bool", (v) => Boolean(v.kev), "On the CISA Known Exploited Vulnerabilities list"],
      Product: ["string", (v) => v.product, "Affected product and version"],
      Remediation: ["string", (v) => (v.remediation ?? []).join(" | "), "Recommended fix"],
      KB: ["string", (v) => (v.kbs ?? []).join(", "), "KBs that fix it (Windows)"],
      FirstSeen: ["date", (v) => v.first_seen, "When Spotlight first saw it on this device"]
    }
  },
  SoftwareRule: {
    description: "The device's status for each required / prohibited software rule.",
    fields: {
      Name: ["string", (r) => r.name, "Rule name, e.g. CrowdStrike Falcon"],
      Status: ["string", (r) => r.status, "installed, missing or unknown (no app inventory)"],
      Mode: ["string", (r) => r.mode, "required or prohibited"]
    }
  },
  Issue: {
    description: "An open posture issue on the device.",
    fields: {
      Id: ["string", (i) => i.id, "Issue id, e.g. not_encrypted, stale, noncompliant"],
      Title: ["string", (i) => i.title, "Issue title"],
      Severity: ["string", (i) => i.severity, "critical, high, medium or low"]
    }
  }
};

// Field names used by Cyclops / CrowdStrike, mapped onto PatchOps fields so existing
// queries can be pasted in unchanged.
const ALIASES = {
  device: { crowdstrikefalconosdistribution: "OSRelease", falconspotlightostype: "Platform", ostype: "Platform", lastseen: "LastSeenAt", lastseenat: "LastSeenAt", name: "Hostname", devicename: "Hostname", serial: "SerialNumber", os: "OSName", osdistribution: "OSRelease", user: "User", username: "User", upn: "Email", falconlastseen: "CrowdStrikeLastSeenAt", crowdstrikelastseen: "CrowdStrikeLastSeenAt", sensorversion: "CrowdStrikeSensorVersion", agentversion: "CrowdStrikeSensorVersion", falconsensorversion: "CrowdStrikeSensorVersion", reducedfunctionalitymode: "CrowdStrikeRFM" },
  vulnerability: { id: "CVE", cveid: "CVE", severity: "Severity", cvss: "Score", basescore: "Score", exprtrating: "ExPRT", product: "Product", cisakev: "KEV", iskev: "KEV" },
  securitypatch: { kb: "UniquePatchId", patchid: "UniquePatchId", id: "UniquePatchId" },
  missingpatch: { kb: "UniquePatchId", patchid: "UniquePatchId", id: "UniquePatchId" },
  app: { application: "Name", displayname: "Name", bundleidentifier: "BundleId" },
  softwarerule: { rule: "Name", state: "Status" }
};
const ENTITY_ALIASES = { vulnerability: "Vulnerability", vulnerabilities: "Vulnerability", vuln: "Vulnerability", cve: "Vulnerability", device: "Device", devices: "Device", app: "App", apps: "App", application: "App", software: "App", securitypatch: "SecurityPatch", patch: "SecurityPatch", patches: "SecurityPatch", missingpatch: "MissingPatch", softwarerule: "SoftwareRule", rule: "SoftwareRule", issue: "Issue", issues: "Issue" };

function resolveEntity(name, position) {
  const entity = ENTITY_ALIASES[String(name).toLowerCase()];
  if (!entity) throw new QueryError(`Unknown entity "${name}". Use one of: ${Object.keys(ENTITIES).join(", ")}`, position);
  return entity;
}

function resolveField(entity, name, position) {
  const fields = ENTITIES[entity].fields;
  const direct = Object.keys(fields).find((field) => field.toLowerCase() === name.toLowerCase());
  const alias = ALIASES[entity.toLowerCase()]?.[name.toLowerCase()];
  const field = direct ?? alias;
  if (!field) throw new QueryError(`Unknown field "${name}" on ${entity}. Available: ${Object.keys(fields).join(", ")}`, position);
  return field;
}

// ---------------- parser ----------------

export function parseQuery(source) {
  const input = String(source ?? "");
  let position = 0;
  const skip = () => { while (position < input.length && /\s/.test(input[position])) position += 1; };
  const peek = (pattern) => { skip(); const match = pattern.exec(input.slice(position)); return match && match.index === 0 ? match : null; };
  const take = (pattern, message) => {
    const match = peek(pattern);
    if (!match) throw new QueryError(message, position);
    position += match[0].length;
    return match;
  };

  function parseValue() {
    skip();
    if (input[position] === "(") {
      const start = position;
      let depth = 0;
      for (; position < input.length; position += 1) {
        if (input[position] === "(") depth += 1;
        if (input[position] === ")") { depth -= 1; if (!depth) break; }
      }
      if (depth) throw new QueryError("Unclosed value list", start);
      const inner = input.slice(start + 1, position);
      position += 1;
      return inner.split(",").map((item) => item.trim().replace(/^["']|["']$/g, "")).filter(Boolean);
    }
    if (input[position] === '"' || input[position] === "'") {
      const quoteChar = input[position];
      const end = input.indexOf(quoteChar, position + 1);
      if (end === -1) throw new QueryError("Unclosed quote", position);
      const value = input.slice(position + 1, end);
      position = end + 1;
      return value;
    }
    const rest = input.slice(position);
    const stop = /\s+(?:f\/|!?r\/|not\s+r\/|(?:and|or)\s+e\/)|\)/i.exec(rest);
    const value = (stop ? rest.slice(0, stop.index) : rest).trim();
    position += stop ? stop.index : rest.length;
    if (!value) throw new QueryError("Missing value", position);
    return value;
  }

  function parseClause() {
    const start = (skip(), position);
    take(/^e\//i, 'Expected "e/" followed by an entity, e.g. "e/ Device"');
    const entityName = take(/^[A-Za-z_]+/, "Expected an entity name after e/")[0];
    const entity = resolveEntity(entityName, start);
    const filters = [];
    const relations = [];
    while (true) {
      if (peek(/^f\//i)) {
        position += 2;
        const fieldStart = (skip(), position);
        const fieldName = take(/^[A-Za-z_][\w.]*/, "Expected a field name after f/")[0];
        const field = resolveField(entity, fieldName, fieldStart);
        skip();
        const opMatch = OPERATORS.map((op) => ({ op, ok: op.match(/^\w/) ? new RegExp(`^${op}\\b`, "i").test(input.slice(position)) : input.startsWith(op, position) })).find((item) => item.ok);
        if (!opMatch) throw new QueryError(`Expected an operator after "${fieldName}" (=, !=, <, >, contains, contains_any, in, exists…)`, position);
        position += opMatch.op.length;
        const op = opMatch.op.toLowerCase();
        filters.push({ field, op, value: UNARY.has(op) ? null : parseValue() });
        continue;
      }
      const relation = peek(/^(not\s+|!)?r\//i);
      if (relation) {
        position += relation[0].length;
        take(/^\(/, 'Expected "(" after r/');
        const inner = parseClause();
        if (!ENTITIES[entity].relations?.[inner.entity]) throw new QueryError(`${entity} has no related ${inner.entity}. Related entities: ${Object.keys(ENTITIES[entity].relations ?? {}).join(", ") || "none"}`, position);
        take(/^\)/, 'Expected ")" to close r/ (');
        relations.push({ negate: Boolean(relation[1]), clause: inner });
        continue;
      }
      break;
    }
    return { entity, filters, relations };
  }

  const clauses = [{ join: null, clause: parseClause() }];
  while (peek(/^(and|or)\b/i)) {
    const join = take(/^(and|or)\b/i, "")[1].toLowerCase();
    clauses.push({ join, clause: parseClause() });
  }
  skip();
  if (position < input.length) throw new QueryError(`Unexpected text "${input.slice(position, position + 20)}"`, position);
  if (clauses.some(({ clause }) => clause.entity !== "Device")) throw new QueryError('Top-level queries must start with "e/ Device"', 0);
  return clauses;
}

// ---------------- evaluator ----------------

const DURATION = /^(\d+(?:\.\d+)?)\s*(m|min|h|d|w|mo|y)$/i;
const UNIT_MS = { m: 60_000, min: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000, mo: 2_592_000_000, y: 31_536_000_000 };
const truthy = (value) => /^(true|yes|1|on)$/i.test(String(value));
const falsy = (value) => /^(false|no|0|off)$/i.test(String(value));
const norm = (value) => String(value ?? "").toLowerCase();
const PLATFORM_ALIASES = { win: "windows", windows: "windows", mac: "macos", macos: "macos", osx: "macos", "mac os": "macos" };

function compare(type, actual, op, expected, now) {
  if (op === "exists") return actual !== null && actual !== undefined && actual !== "";
  if (op === "not_exists") return actual === null || actual === undefined || actual === "";
  const values = Array.isArray(expected) ? expected : [expected];
  if (op === "contains_any" || op === "in" || op === "not_in") {
    const hit = values.some((value) => (op === "contains_any" ? norm(actual).includes(norm(value)) : compare(type, actual, "=", value, now)));
    return op === "not_in" ? !hit : hit;
  }
  if (op === "contains_all") return values.every((value) => norm(actual).includes(norm(value)));
  const value = Array.isArray(expected) ? expected[0] : expected;
  if (op === "contains" || op === "~") return norm(actual).includes(norm(value));
  if (op === "not_contains") return !norm(actual).includes(norm(value));
  if (op === "starts_with") return norm(actual).startsWith(norm(value));
  if (op === "ends_with") return norm(actual).endsWith(norm(value));

  if (type === "date") {
    if (!actual) return false;
    const duration = DURATION.exec(String(value).trim());
    if (duration) {
      // Relative: LastSeenAt < 7d means "less than 7 days ago".
      const age = now - Date.parse(actual);
      const limit = Number(duration[1]) * UNIT_MS[duration[2].toLowerCase()];
      return { "<": age < limit, "<=": age <= limit, ">": age > limit, ">=": age >= limit, "=": Math.abs(age - limit) < UNIT_MS.d, "!=": Math.abs(age - limit) >= UNIT_MS.d }[op];
    }
    const left = Date.parse(actual);
    const right = Date.parse(value);
    if (Number.isNaN(right)) throw new QueryError(`"${value}" is not a date or duration like 7d`);
    return { "<": left < right, "<=": left <= right, ">": left > right, ">=": left >= right, "=": actual.slice(0, 10) === String(value).slice(0, 10), "!=": actual.slice(0, 10) !== String(value).slice(0, 10) }[op];
  }
  if (type === "bool") {
    const wanted = truthy(value) ? true : falsy(value) ? false : null;
    if (wanted === null) throw new QueryError(`"${value}" is not true or false`);
    if (op === "=") return actual === wanted;
    if (op === "!=") return actual !== wanted;
    throw new QueryError(`Operator ${op} is not supported for true/false fields`);
  }
  if (type === "number" || type === "version") {
    if (actual === null || actual === undefined || actual === "") return op === "!=";
    const order = type === "number" ? Math.sign(Number(actual) - Number(value)) : compareVersions(String(actual), String(value));
    if (type === "number" && Number.isNaN(Number(value))) throw new QueryError(`"${value}" is not a number`);
    return { "=": order === 0, "!=": order !== 0, "<": order < 0, "<=": order <= 0, ">": order > 0, ">=": order >= 0 }[op];
  }
  const left = norm(actual);
  const right = PLATFORM_ALIASES[norm(value)] && ["windows", "macos"].includes(left) ? PLATFORM_ALIASES[norm(value)] : norm(value);
  return { "=": left === right, "!=": left !== right, "<": left < right, "<=": left <= right, ">": left > right, ">=": left >= right }[op];
}

function matchesClause(record, clause, now) {
  const definition = ENTITIES[clause.entity];
  for (const filter of clause.filters) {
    const [type, getter] = definition.fields[filter.field];
    if (!compare(type, getter(record), filter.op, filter.value, now)) return false;
  }
  for (const relation of clause.relations) {
    const related = definition.relations[relation.clause.entity](record);
    const found = related.some((item) => matchesClause(item, relation.clause, now));
    if (found === relation.negate) return false;
  }
  return true;
}

export function runQuery(source, devices, { now = Date.now() } = {}) {
  const clauses = typeof source === "string" ? parseQuery(source) : source;
  return devices.filter((device) => {
    let result = null;
    for (const { join, clause } of clauses) {
      const match = matchesClause(device, clause, now);
      result = join === null ? match : join === "and" ? result && match : result || match;
    }
    return result;
  });
}

export function groupValue(device, field) {
  const resolved = resolveField("Device", field);
  const [type, getter] = ENTITIES.Device.fields[resolved];
  const value = getter(device);
  if (type === "bool") return value === true ? "Yes" : value === false ? "No" : "Unknown";
  if (type === "date") {
    if (!value) return "Never";
    const days = (Date.now() - Date.parse(value)) / 86_400_000;
    return days <= 1 ? "≤ 1 day" : days <= 7 ? "≤ 7 days" : days <= 30 ? "≤ 30 days" : "> 30 days";
  }
  return value === null || value === undefined || value === "" ? "Unknown" : String(value);
}

export function queryReference() {
  return Object.fromEntries(Object.entries(ENTITIES).map(([name, entity]) => [name, {
    description: entity.description,
    fields: Object.entries(entity.fields).map(([field, [type, , description]]) => ({ field, type, description })),
    relations: Object.keys(entity.relations ?? {})
  }]));
}
