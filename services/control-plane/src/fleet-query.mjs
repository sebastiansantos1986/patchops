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
      Architecture: ["string", (d) => d.architecture || (/\bM\d|Apple silicon/i.test(d.model ?? "") ? "arm64" : /Intel/i.test(d.model ?? "") ? "x86_64" : ""), "arm64 (Apple silicon / ARM) or x86_64 (Intel / AMD)"],
      OSStatus: ["string", (d) => d.os_status, "current, update_available, older_release, below_minimum, unsupported or unknown"],
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
      DiscoveredBy: ["list", (d) => Object.keys(d.sources ?? {}).map((source) => SOURCE_NAMES[source] ?? source), "Which systems report the device: Intune, Jamf, CrowdStrike Falcon, PatchOps Agent"],
      CrowdStrikeHostType: ["string", (d) => d.crowdstrike?.product_type ?? null, "Falcon host type: Workstation, Server, Domain Controller"],
      IntuneLastSeenAt: ["date", (d) => d.sources?.intune?.last_check_in ?? null, "Last Intune sync"],
      JamfLastSeenAt: ["date", (d) => d.sources?.jamf?.last_check_in ?? null, "Last Jamf check-in"],
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
      ExtensionAttribute: (d) => d.extension_attributes ?? [],
      User: (d) => (d.user?.email || d.user?.name ? [{ name: d.user.name ?? "", email: d.user.email ?? "", groups: d.user_groups ?? [] }] : []),
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
    description: "An open vulnerability: OS CVEs from Apple and Microsoft's own security data (plus CISA KEV), and CVEs reported by CrowdStrike Spotlight.",
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
      FirstSeen: ["date", (v) => v.first_seen, "When Spotlight first saw it on this device"],
      Source: ["string", (v) => (v.sources ?? [v.source]).join(", "), "crowdstrike, apple and/or microsoft"],
      FixedIn: ["version", (v) => v.fixed_in ?? null, "OS version or build that fixes it (Apple / Microsoft feeds)"]
    }
  },
  User: {
    description: "The device's primary user (from Intune or Jamf).",
    fields: {
      Name: ["string", (u) => u.name, "Display name"],
      Email: ["string", (u) => u.email, "Email / user principal name"]
    },
    relations: { Group: (u) => (u.groups ?? []).map((name) => ({ name })) }
  },
  Group: {
    description: "A Microsoft Entra ID group the user belongs to (directly or nested). Needs Intune connected with group read permission.",
    fields: { Name: ["string", (g) => g.name, "Group display name"] }
  },
  ExtensionAttribute: {
    description: "A Jamf Pro extension attribute value on the Mac (e.g. installed Java versions).",
    fields: {
      Name: ["string", (a) => a.name, "Extension attribute name as defined in Jamf"],
      Value: ["string", (a) => a.value, "Reported value (multiple values joined with commas)"]
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
  user: { entityname: "Name", displayname: "Name", upn: "Email", userprincipalname: "Email", mail: "Email" },
  group: { entityname: "Name", displayname: "Name", groupname: "Name" },
  device: { crowdstrikefalconhosttype: "CrowdStrikeHostType", falconhosttype: "CrowdStrikeHostType", hosttype: "CrowdStrikeHostType", producttype: "CrowdStrikeHostType", crowdstrikefalconlastseenat: "CrowdStrikeLastSeenAt", falconlastseenat: "CrowdStrikeLastSeenAt", intunemanageddeviceownertype: "Ownership", ownertype: "Ownership", manageddeviceownertype: "Ownership", discoveredby: "DiscoveredBy", source: "DiscoveredBy", sources: "DiscoveredBy", intunelastseenat: "IntuneLastSeenAt", intunelastsyncdatetime: "IntuneLastSeenAt", jamflastseenat: "JamfLastSeenAt", jamflastcontacttime: "JamfLastSeenAt", entityname: "Hostname", hostname: "Hostname", crowdstrikefalconosdistribution: "OSRelease", falconspotlightostype: "Platform", ostype: "Platform", lastseen: "LastSeenAt", lastseenat: "LastSeenAt", name: "Hostname", devicename: "Hostname", serial: "SerialNumber", os: "OSName", osdistribution: "OSRelease", user: "User", username: "User", upn: "Email", falconlastseen: "CrowdStrikeLastSeenAt", crowdstrikelastseen: "CrowdStrikeLastSeenAt", sensorversion: "CrowdStrikeSensorVersion", agentversion: "CrowdStrikeSensorVersion", falconsensorversion: "CrowdStrikeSensorVersion", reducedfunctionalitymode: "CrowdStrikeRFM" },
  vulnerability: { id: "CVE", cveid: "CVE", severity: "Severity", cvss: "Score", basescore: "Score", exprtrating: "ExPRT", product: "Product", cisakev: "KEV", iskev: "KEV" },
  securitypatch: { kb: "UniquePatchId", patchid: "UniquePatchId", id: "UniquePatchId" },
  missingpatch: { kb: "UniquePatchId", patchid: "UniquePatchId", id: "UniquePatchId" },
  app: { application: "Name", displayname: "Name", entityname: "Name", softwarename: "Name", productname: "Name", bundleidentifier: "BundleId", vendor: "Publisher", manufacturer: "Publisher", softwareversion: "Version" },
  softwarerule: { rule: "Name", state: "Status" }
};
const SOURCE_NAMES = { intune: "Intune", jamf: "Jamf", crowdstrike: "CrowdStrike Falcon", agent: "PatchOps Agent" };
const ENTITY_ALIASES = { user: "User", users: "User", group: "Group", groups: "Group",  extensionattribute: "ExtensionAttribute", ea: "ExtensionAttribute",  vulnerability: "Vulnerability", vulnerabilities: "Vulnerability", vuln: "Vulnerability", cve: "Vulnerability", device: "Device", devices: "Device", app: "App", apps: "App", application: "App", software: "App", securitypatch: "SecurityPatch", patch: "SecurityPatch", patches: "SecurityPatch", missingpatch: "MissingPatch", softwarerule: "SoftwareRule", rule: "SoftwareRule", issue: "Issue", issues: "Issue" };

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

// Grammar (case-insensitive keywords):
//   query   := clause (("and" | "or") clause)*            whole queries combined
//   clause  := "e/" Entity expr
//   expr    := andExpr ("OR" andExpr)*
//   andExpr := term term*                                 terms side by side are AND-ed
//   term    := "f/" Field op value | ["!" | "not"] "r/" "(" clause ")" | "(" expr ")"
// Values: bare words, "quoted text" or lists in parentheses for in / contains_any.
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
  const CLAUSE_JOIN = /^(and|or)\s+e\//i;

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
    if (input[position] === '"' || input[position] === "'" || input[position] === "\u201c") {
      const close = input[position] === "\u201c" ? "\u201d" : input[position];
      const end = input.indexOf(close, position + 1);
      if (end === -1) throw new QueryError("Unclosed quote", position);
      const value = input.slice(position + 1, end);
      position = end + 1;
      return value;
    }
    const rest = input.slice(position);
    const stop = /\s+(?:f\/|!?r\/|not\s+r\/|(?:and|or)\s+e\/|or\s+(?=f\/|\(|!?r\/|not\s+r\/))|\)|\s+\((?=\s*(?:f\/|!?r\/|not\s+r\/))/i.exec(rest);
    const value = (stop ? rest.slice(0, stop.index) : rest).trim();
    position += stop ? stop.index : rest.length;
    if (!value) throw new QueryError("Missing value", position);
    return value;
  }

  function parseFilter(entity) {
    position += 2; // "f/"
    const fieldStart = (skip(), position);
    const fieldName = take(/^[A-Za-z_][\w.]*/, "Expected a field name after f/")[0];
    const field = resolveField(entity, fieldName, fieldStart);
    skip();
    const opMatch = OPERATORS.map((op) => ({ op, ok: op.match(/^\w/) ? new RegExp(`^${op}\\b`, "i").test(input.slice(position)) : input.startsWith(op, position) })).find((item) => item.ok);
    if (!opMatch) throw new QueryError(`Expected an operator after "${fieldName}" (=, !=, <, >, contains, contains_any, in, exists…)`, position);
    position += opMatch.op.length;
    const op = opMatch.op.toLowerCase();
    return { type: "filter", field, op, value: UNARY.has(op) ? null : parseValue() };
  }

  function parseTerm(entity) {
    if (peek(/^f\//i)) return parseFilter(entity);
    const relation = peek(/^(not\s+|!)?r\//i);
    if (relation) {
      position += relation[0].length;
      take(/^\(/, 'Expected "(" after r/');
      const inner = parseClause();
      if (!ENTITIES[entity].relations?.[inner.entity]) throw new QueryError(`${entity} has no related ${inner.entity}. Related entities: ${Object.keys(ENTITIES[entity].relations ?? {}).join(", ") || "none"}`, position);
      take(/^\)/, 'Expected ")" to close r/ (');
      return { type: "relation", negate: Boolean(relation[1]), clause: inner };
    }
    if (peek(/^\(/)) {
      const start = position;
      position += 1;
      const expr = parseExpr(entity);
      if (!expr) throw new QueryError("Empty parentheses", start);
      take(/^\)/, 'Expected ")" to close the group');
      return expr;
    }
    return null;
  }

  function parseAnd(entity) {
    const items = [];
    while (true) {
      if (peek(CLAUSE_JOIN) || peek(/^or\b/i) || peek(/^\)/)) break;
      skip();
      if (position >= input.length) break;
      const term = parseTerm(entity);
      if (!term) break;
      items.push(term);
    }
    return items.length === 0 ? null : items.length === 1 ? items[0] : { type: "and", items };
  }

  function parseExpr(entity) {
    const items = [];
    const first = parseAnd(entity);
    if (first) items.push(first);
    while (peek(/^or\b/i) && !peek(CLAUSE_JOIN)) {
      take(/^or\b/i, "");
      const next = parseAnd(entity);
      if (!next) throw new QueryError('Expected a condition after "OR"', position);
      items.push(next);
    }
    return items.length === 0 ? null : items.length === 1 ? items[0] : { type: "or", items };
  }

  function parseClause() {
    const start = (skip(), position);
    take(/^e\//i, 'Expected "e/" followed by an entity, e.g. "e/ Device"');
    const entityName = take(/^[A-Za-z_]+/, "Expected an entity name after e/")[0];
    const entity = resolveEntity(entityName, start);
    return { entity, expr: parseExpr(entity) };
  }

  const clauses = [{ join: null, clause: parseClause() }];
  while (peek(CLAUSE_JOIN)) {
    const join = take(/^(and|or)\b/i, "")[1].toLowerCase();
    clauses.push({ join, clause: parseClause() });
  }
  skip();
  if (position < input.length) throw new QueryError(`Unexpected text "${input.slice(position, position + 20)}"`, position);
  if (clauses.some(({ clause }) => clause.entity !== "Device")) throw new QueryError('Top-level queries must start with "e/ Device"', 0);
  return clauses;
}

// Parses a clause for a non-device entity, e.g. a software rule's detection
// "e/ Software ( f/ Name contains \"Forcepoint Agent\" f/ Version starts_with 30. )".
export function parseEntityClause(source, expectedEntity) {
  const wrapped = parseQuery(`e/ Device r/ ( ${source} )`);
  const clause = wrapped[0].clause.expr?.clause;
  if (!clause || (expectedEntity && clause.entity !== expectedEntity)) throw new QueryError(`Expected a condition on ${expectedEntity}`);
  return clause;
}

// ---------------- evaluator ----------------

const DURATION = /^(\d+(?:\.\d+)?)\s*(m|min|h|d|w|mo|y)$/i;
const UNIT_MS = { m: 60_000, min: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000, mo: 2_592_000_000, y: 31_536_000_000 };
const truthy = (value) => /^(true|yes|1|on)$/i.test(String(value));
const falsy = (value) => /^(false|no|0|off)$/i.test(String(value));
const norm = (value) => String(value ?? "").toLowerCase();
const PLATFORM_ALIASES = { win: "windows", windows: "windows", mac: "macos", macos: "macos", osx: "macos", "mac os": "macos" };

function compare(type, actual, op, expected, now) {
  // Multi-valued fields (e.g. DiscoveredBy): "=" means any value matches, "!=" none does.
  if (type === "list") {
    const items = Array.isArray(actual) ? actual : [];
    if (op === "exists") return items.length > 0;
    if (op === "not_exists") return items.length === 0;
    const negative = op === "!=" || op === "not_in" || op === "not_contains";
    const positiveOp = { "!=": "=", not_in: "in", not_contains: "contains" }[op] ?? op;
    const hit = items.some((item) => compare("string", item, positiveOp, expected, now));
    return negative ? !hit : hit;
  }
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

function matchesExpr(record, entity, node, now) {
  if (!node) return true;
  if (node.type === "and") return node.items.every((item) => matchesExpr(record, entity, item, now));
  if (node.type === "or") return node.items.some((item) => matchesExpr(record, entity, item, now));
  if (node.type === "filter") {
    const [type, getter] = ENTITIES[entity].fields[node.field];
    return compare(type, getter(record), node.op, node.value, now);
  }
  if (node.type === "relation") {
    const related = ENTITIES[entity].relations[node.clause.entity](record);
    const found = related.some((item) => matchesClause(item, node.clause, now));
    return found !== node.negate;
  }
  return false;
}

export function matchesClause(record, clause, now = Date.now()) {
  return matchesExpr(record, clause.entity, clause.expr, now);
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

const OPS_BY_TYPE = {
  string: ["=", "!=", "contains", "not_contains", "starts_with", "in", "exists", "not_exists"],
  version: ["=", "!=", "<", "<=", ">", ">=", "starts_with"],
  number: ["=", "!=", "<", "<=", ">", ">="],
  date: ["<", ">"],
  bool: ["="],
  list: ["=", "!=", "contains", "in"]
};
const SUGGESTIONS = {
  "Device.Platform": ["windows", "macos"], "Device.RiskLevel": ["critical", "high", "medium", "low", "healthy"],
  "Device.OSStatus": ["current", "update_available", "older_release", "below_minimum", "unsupported", "unknown"],
  "Device.Compliance": ["compliant", "noncompliant", "ingraceperiod"], "Device.Ownership": ["company", "personal"],
  "Device.DiscoveredBy": ["Intune", "Jamf", "CrowdStrike Falcon", "PatchOps Agent"], "Device.CrowdStrikeHostType": ["Workstation", "Server", "Domain Controller"],
  "Device.Architecture": ["arm64", "x86_64"], "Device.OSRelease": ["11", "10", "27", "26", "15"],
  "Vulnerability.Severity": ["critical", "high", "medium", "low"], "Vulnerability.ExploitStatus": ["Actively used", "Easily accessible", "Available", "Unproven"],
  "Vulnerability.Source": ["apple", "microsoft", "crowdstrike"], "MissingPatch.Method": ["build", "spotlight"], "SoftwareRule.Status": ["installed", "missing", "unknown"],
  "Issue.Severity": ["critical", "high", "medium", "low"]
};
const DATE_SUGGESTIONS = ["1d", "7d", "14d", "30d", "90d"];

export function queryReference() {
  return Object.fromEntries(Object.entries(ENTITIES).map(([name, entity]) => [name, {
    label: ENTITY_WORDS[name] ?? (name === "Device" ? "device" : name),
    description: entity.description,
    fields: Object.entries(entity.fields).map(([field, [type, , description]]) => ({
      field, type, description, label: FIELD_WORDS[field] ?? field.replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase(),
      ops: OPS_BY_TYPE[type] ?? OPS_BY_TYPE.string,
      suggestions: SUGGESTIONS[`${name}.${field}`] ?? (type === "date" ? DATE_SUGGESTIONS : type === "bool" ? ["true", "false"] : [])
    })),
    relations: Object.keys(entity.relations ?? {})
  }]));
}

// ---------------- plain-English descriptions ----------------
// Turns a query into a sentence anyone can read, e.g.
// "Windows workstations seen in the last 7 days that have software whose name contains
//  "Forcepoint Agent" and whose version starts with "30.", excluding users in group "GRP-…"".

const FIELD_WORDS = {
  Hostname: "name", SerialNumber: "serial number", OSName: "operating system", OSVersion: "OS version", OSRelease: "OS release", OSBuild: "Windows build",
  OSRevision: "Windows update revision", OSStatus: "OS status", User: "user", Email: "user email", LastSeenAt: "last seen", Encrypted: "disk encrypted",
  Compliance: "Intune compliance", RiskLevel: "risk level", RiskScore: "risk score", InIntune: "in Intune", InJamf: "in Jamf", HasAgent: "PatchOps agent installed",
  InCrowdStrike: "in CrowdStrike", CrowdStrikeReporting: "Falcon sensor reporting", CrowdStrikeLastSeenAt: "Falcon last seen", CrowdStrikeSensorVersion: "Falcon sensor version",
  CrowdStrikeHostType: "host type", CrowdStrikeRFM: "Falcon reduced functionality", DiscoveredBy: "seen by", IntuneLastSeenAt: "last Intune sync", JamfLastSeenAt: "last Jamf check-in",
  Ownership: "ownership", Architecture: "architecture", OpenCVEs: "open CVEs", CriticalCVEs: "critical CVEs", ExploitedCVEs: "exploited CVEs", HighestCVSS: "highest CVSS",
  Name: "name", Version: "version", Publisher: "publisher", BundleId: "bundle ID", UniquePatchId: "KB", CVE: "CVE", Severity: "severity", Status: "status", Value: "value"
};
const ENTITY_WORDS = { App: "software", SecurityPatch: "installed update", MissingPatch: "missing update", SoftwareRule: "software rule result", Vulnerability: "open vulnerability", Issue: "issue", ExtensionAttribute: "Jamf extension attribute", User: "user", Group: "group" };
const OP_WORDS = { "=": "is", "!=": "is not", "<": "is below", "<=": "is at most", ">": "is above", ">=": "is at least", contains: "contains", "~": "contains", not_contains: "does not contain", contains_any: "contains any of", contains_all: "contains all of", in: "is one of", not_in: "is none of", starts_with: "starts with", ends_with: "ends with", exists: "is set", not_exists: "is not set" };
const PLATFORM_WORDS = { windows: "Windows", macos: "macOS", mac: "macOS", win: "Windows" };

const quoteValue = (value) => (Array.isArray(value) ? value.map((item) => `“${item}”`).join(", ") : `“${value}”`);

function describeFilter(entity, node) {
  const { field, op, value } = node;
  const type = ENTITIES[entity].fields[field]?.[0];
  if (entity === "Device") {
    if (field === "Platform" && op === "=") return { adjective: PLATFORM_WORDS[String(value).toLowerCase()] ?? value };
    if (field === "CrowdStrikeHostType" && op === "=") return { noun: `${String(value).toLowerCase()}s` };
    if (field === "OSRelease" && op === "=") return { phrase: `on release ${value}` };
    if (type === "date" && /^\d/.test(String(value))) {
      const what = field === "LastSeenAt" ? "seen" : `${FIELD_WORDS[field] ?? field}`;
      const duration = String(value).replace(/(\d+)\s*d$/i, "$1 days").replace(/(\d+)\s*h$/i, "$1 hours").replace(/(\d+)\s*w$/i, "$1 weeks").replace(/(\d+)\s*m$/i, "$1 minutes").replace(/(\d+)\s*mo$/i, "$1 months");
      if (op === "<" || op === "<=") return { phrase: field === "LastSeenAt" ? `seen in the last ${duration}` : `with ${what} in the last ${duration}` };
      if (op === ">" || op === ">=") return { phrase: field === "LastSeenAt" ? `not seen for more than ${duration}` : `with ${what} more than ${duration} ago` };
    }
    if (type === "bool") return { phrase: `${/^(true|yes|1)$/i.test(String(value)) === (op === "=") ? "" : "not "}${FIELD_WORDS[field] ?? field}`.replace(/^not in /, "not in ") };
    if (field === "DiscoveredBy") return { phrase: `${op === "!=" || op === "not_in" ? "not " : ""}seen by ${Array.isArray(value) ? value.join(" or ") : value}` };
  }
  if (op === "exists" || op === "not_exists") return { phrase: `whose ${FIELD_WORDS[field] ?? field} ${OP_WORDS[op]}` };
  return { phrase: `whose ${FIELD_WORDS[field] ?? field} ${OP_WORDS[op] ?? op} ${quoteValue(value)}` };
}

function describeExpr(entity, node) {
  if (!node) return [];
  if (node.type === "and") return node.items.flatMap((item) => describeExpr(entity, item));
  if (node.type === "or") return [{ phrase: `(${node.items.map((item) => describeExpr(entity, item).map((part) => part.phrase ?? part.adjective ?? part.noun).join(" and ")).join(" or ")})` }];
  if (node.type === "filter") return [describeFilter(entity, node)];
  if (node.type === "relation") {
    const inner = node.clause;
    if (entity === "Device" && inner.entity === "User") {
      const groups = describeExpr("User", inner.expr).map((part) => part.phrase).join(" and ");
      return [{ phrase: `${node.negate ? "excluding devices whose user is" : "whose user is"} ${groups}` }];
    }
    if (entity === "User" && inner.entity === "Group") {
      const names = describeExpr("Group", inner.expr).map((part) => (/^whose name is “/.test(part.phrase) ? `group ${part.phrase.replace(/^whose name is /, "")}` : `a group ${part.phrase}`)).join(" and ");
      return [{ phrase: `${node.negate ? "not " : ""}in ${names}` }];
    }
    if (inner.entity === "SoftwareRule") {
      const filters = [];
      const collect = (item) => { if (!item) return; if (item.type === "filter") filters.push(item); else if (item.type === "and") item.items.forEach(collect); };
      collect(inner.expr);
      const name = filters.find((item) => item.field === "Name")?.value;
      const status = filters.find((item) => item.field === "Status")?.value;
      if (name) {
        const state = status ? ({ installed: "installed", missing: "missing", unknown: "without app data" }[String(status).toLowerCase()] ?? status) : "evaluated";
        return [{ phrase: node.negate ? `where ${name} is not ${state}` : `where ${name} is ${state}` }];
      }
    }
    const details = describeExpr(inner.entity, inner.expr).map((part) => part.phrase ?? part.adjective).join(" and ");
    const noun = ENTITY_WORDS[inner.entity] ?? inner.entity;
    return [{ phrase: `${node.negate ? "without" : "with"} ${noun === "software" ? "software" : `an ${noun}`.replace(/^an ([^aeiou])/, "a $1")}${details ? ` ${details}` : ""}` }];
  }
  return [];
}

export function describeClause(clause) {
  const parts = describeExpr(clause.entity, clause.expr);
  const adjectives = parts.filter((part) => part.adjective).map((part) => part.adjective);
  const nouns = parts.filter((part) => part.noun).map((part) => part.noun);
  const phrases = parts.filter((part) => part.phrase).map((part) => part.phrase);
  const subject = `${adjectives.join(" ")} ${nouns[0] ?? (clause.entity === "Device" ? "devices" : ENTITY_WORDS[clause.entity] ?? clause.entity)}`.trim();
  const text = [subject, ...phrases].join(", ");
  return /^macOS/.test(text) ? text : text.charAt(0).toUpperCase() + text.slice(1);
}

export function describeQuery(source) {
  try {
    const clauses = typeof source === "string" ? parseQuery(source) : source;
    return clauses.map(({ join, clause }, index) => `${index ? (join === "and" ? " and also " : " or ") : ""}${index ? describeClause(clause).charAt(0).toLowerCase() + describeClause(clause).slice(1) : describeClause(clause)}`).join("") + ".";
  } catch {
    return null;
  }
}

// Group names that queries filter on, so only those groups' members are fetched from Entra ID.
export function referencedGroups(sources) {
  const wanted = new Map();
  const visit = (entity, node) => {
    if (!node) return;
    if (node.type === "and" || node.type === "or") return node.items.forEach((item) => visit(entity, item));
    if (node.type === "relation") return visit(node.clause.entity, node.clause.expr);
    if (node.type === "filter" && entity === "Group" && node.field === "Name") {
      const op = ["contains", "contains_any", "~"].includes(node.op) ? "contains" : node.op === "starts_with" ? "starts_with" : ["=", "in"].includes(node.op) ? "=" : null;
      if (!op) return;
      for (const value of [node.value].flat()) if (String(value).trim()) wanted.set(`${op}|${String(value).toLowerCase()}`, { op, value: String(value) });
    }
  };
  for (const source of sources) {
    if (!source || !/group/i.test(source)) continue;
    try { for (const { clause } of parseQuery(source)) visit(clause.entity, clause.expr); } catch { /* invalid queries are reported elsewhere */ }
  }
  return [...wanted.values()].sort((a, b) => `${a.op}${a.value}`.localeCompare(`${b.op}${b.value}`));
}
