// Deterministic, clearly-labelled sample fleet used until real Intune / Jamf
// credentials are configured. Records use the same normalized shape the live
// connectors return, so the dashboard and risk engine exercise identical paths.

function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

const PEOPLE = [
  "Avery Brooks", "Jordan Lee", "Priya Natarajan", "Marcus Hill", "Sofia Alvarez", "Liam O'Connor", "Hana Kim", "Diego Ramos",
  "Chloe Martin", "Noah Patel", "Emma Schultz", "Ethan Wright", "Isabella Rossi", "Lucas Silva", "Mia Johansson", "Oliver Grant",
  "Zara Ahmed", "Caleb Turner", "Nina Petrova", "Samuel Okafor", "Grace Liu", "Henry Adams", "Leah Cohen", "Mateo Garcia",
  "Ava Thompson", "Ryan Murphy", "Elena Popescu", "Daniel Park", "Maya Singh", "Owen Fischer", "Julia Novak", "Aaron Mensah",
  "Ivy Chen", "Felix Wagner", "Layla Haddad", "Tyler Brooks", "Camila Torres", "Victor Dubois", "Ruby Evans", "Kai Nakamura",
  "Sara Lindqvist", "Ben Carter", "Amara Nwosu", "Leo Moretti", "Hannah Weiss", "Omar Farouk", "Clara Jensen", "Nathan Cole",
  "Yuki Tanaka", "Paige Reynolds", "Rafael Costa", "Tessa Byrne", "Arjun Mehta", "Lily Foster", "Jonas Berg", "Eva Horvat",
  "Miles Bennett", "Nora Quinn", "Theo Laurent", "Alina Kowalski", "Ian Douglas", "Bianca Ferreira", "Gavin Shaw", "Selin Kaya",
  "Hugo Martins", "Stella Price", "Kofi Asante", "Freya Holm", "Dylan Ross", "Mei Wong", "Adrian Vega", "Quinn Harper",
  "Elsa Lund", "Rohan Das", "Vera Ivanova", "Cole Jenkins", "Ines Duarte", "Max Becker", "Lina Saleh", "Pablo Ortiz"
];

const MAC_MODELS = ["MacBook Pro (14-inch, M3)", "MacBook Pro (16-inch, M4 Pro)", "MacBook Air (13-inch, M2)", "MacBook Air (15-inch, M3)", "Mac mini (M4)", "MacBook Pro (13-inch, 2020, Intel)"];
const WIN_MODELS = [["Dell", "Latitude 7450"], ["Lenovo", "ThinkPad T14 Gen 5"], ["HP", "EliteBook 840 G11"], ["Microsoft", "Surface Laptop 6"], ["Dell", "OptiPlex 7020"]];

// Sample OS releases (illustrative values for the demo fleet).
const MAC_OS = [["26.1", "25B78", 22], ["26.0.1", "25A362", 9], ["15.7.2", "24G325", 7], ["14.8.2", "23J126", 3], ["13.7.8", "22H730", 2]];
const WIN_OS = [["10.0.26100.7171", 20], ["10.0.26100.6899", 8], ["10.0.22631.6199", 5], ["10.0.19045.6456", 3]];

const MAC_APPS = [
  ["Google Chrome", "com.google.Chrome", "Google", ["142.0.7444.135", "142.0.7444.60", "141.0.7390.123", "138.0.7204.184"]],
  ["Slack", "com.tinyspeck.slackmacgap", "Slack Technologies", ["4.47.59", "4.46.101", "4.43.51"]],
  ["zoom.us", "us.zoom.xos", "Zoom", ["6.6.6", "6.6.2", "6.4.10", "6.1.11"]],
  ["Microsoft Teams", "com.microsoft.teams2", "Microsoft", ["25290.205.4069", "25275.2601.4002", "25212.2202.3801"]],
  ["Microsoft Word", "com.microsoft.Word", "Microsoft", ["16.103", "16.102", "16.99"]],
  ["Adobe Acrobat Reader", "com.adobe.Reader", "Adobe", ["25.001.20844", "25.001.20693", "24.005.20421"]],
  ["Firefox", "org.mozilla.firefox", "Mozilla", ["145.0", "144.0.2", "140.4.0"]],
  ["1Password", "com.1password.1password", "AgileBits", ["8.11.16", "8.11.14", "8.10.80"]],
  ["Visual Studio Code", "com.microsoft.VSCode", "Microsoft", ["1.106.2", "1.105.1", "1.101.2"]],
  ["Docker", "com.docker.docker", "Docker", ["4.51.0", "4.49.0", "4.42.1"]]
];
const WIN_APPS = [
  ["Google Chrome", "Google LLC", ["142.0.7444.135", "142.0.7444.60", "141.0.7390.123", "138.0.7204.184"]],
  ["Microsoft Edge", "Microsoft Corporation", ["142.0.3595.80", "142.0.3595.53", "141.0.3537.99"]],
  ["Zoom Workplace (64-bit)", "Zoom Communications, Inc.", ["6.6.6", "6.6.2", "6.4.10", "6.1.11"]],
  ["Microsoft Teams", "Microsoft Corporation", ["25290.205.4069", "25275.2601.4002", "25212.2202.3801"]],
  ["Microsoft 365 Apps for enterprise", "Microsoft Corporation", ["16.0.19328.20190", "16.0.19231.20216", "16.0.18925.20184"]],
  ["Adobe Acrobat Reader", "Adobe", ["25.001.20844", "25.001.20693", "24.005.20421"]],
  ["Slack", "Slack Technologies", ["4.47.59", "4.46.101", "4.43.51"]],
  ["Java 8 Update 471", "Oracle Corporation", ["8.0.4710.9", "8.0.4510.10"]],
  ["7-Zip 25.01 (x64)", "Igor Pavlov", ["25.01", "24.09", "23.01"]],
  ["Cisco Secure Client", "Cisco Systems, Inc.", ["5.1.12.146", "5.1.10.233", "5.0.05040"]]
];

// Security agents, so required / prohibited software rules have something to measure.
const MAC_AGENTS = [["Falcon", "com.crowdstrike.falcon.App", "CrowdStrike", "7.30.20103", 0.96], ["PrivilegeManagement", "com.beyondtrust.privilegemanagement", "BeyondTrust", "25.6.1", 0.93], ["Okta Verify", "com.okta.mobile.auth-service-extension", "Okta", "9.52.0", 0.9], ["Nessus Agent", "com.tenablesecurity.nessus.agent", "Tenable", "11.0.1", 0.22], ["CyberArk EPM", "com.cyberark.CyberArkEPM", "CyberArk", "25.9.0", 0.12], ["Forcepoint DLP Endpoint", "com.forcepoint.dlp.endpoint", "Forcepoint", "30.9.750", 0.8]];
const WIN_AGENTS = [["CrowdStrike Windows Sensor", "CrowdStrike, Inc.", "7.30.20105.0", 0.97], ["BeyondTrust Privilege Management for Windows", "BeyondTrust Corporation", "25.6.214.0", 0.92], ["Okta Verify", "Okta, Inc.", "6.6.1.0", 0.84], ["Nessus Agent (x64)", "Tenable, Inc.", "11.0.1.20015", 0.3], ["CyberArk Endpoint Privilege Manager Agent", "CyberArk", "25.9.0.1120", 0.18], ["Forcepoint Agent 30.9.750", "Forcepoint", "30.9.750", 0.7], ["Forcepoint Agent 29.4.12", "Forcepoint", "29.4.12", 0.12]];

// Clearly-labelled sample KBs that map onto the sample fleet's build numbers.
export const SAMPLE_TRACKED_PATCHES = [
  { kb: "KB5099701", title: "Sample: November cumulative update (24H2 / 25H2)", builds: ["26100.7171", "26200.7171"], severity: "high", released: "", sample: true },
  { kb: "KB5099702", title: "Sample: November cumulative update (23H2)", builds: ["22631.6200"], severity: "high", released: "", sample: true }
];

const SAMPLE_CVES = [
  { cve: "CVE-2099-0001", severity: "critical", score: 9.8, exprt: "critical", exploit: "Actively used", kev: true, product: "Sample Browser 141", remediation: ["Update Sample Browser to 142"], kbs: [], windows: true, mac: true, rate: 0.12 },
  { cve: "CVE-2099-0002", severity: "critical", score: 9.1, exprt: "high", exploit: "Available", kev: false, product: "Windows 11 24H2", remediation: ["Install KB5099701"], kbs: ["KB5099701"], windows: true, mac: false, rate: 0.25 },
  { cve: "CVE-2099-0003", severity: "high", score: 8.1, exprt: "medium", exploit: "Unproven", kev: false, product: "Sample PDF Reader 24", remediation: ["Update Sample PDF Reader"], kbs: [], windows: true, mac: true, rate: 0.3 },
  { cve: "CVE-2099-0004", severity: "high", score: 7.5, exprt: "high", exploit: "Easily accessible", kev: false, product: "macOS 26.0.1", remediation: ["Update macOS to 26.1"], kbs: [], windows: false, mac: true, rate: 0.28 },
  { cve: "CVE-2099-0005", severity: "medium", score: 5.4, exprt: "low", exploit: "Unproven", kev: false, product: "Sample Chat 4.43", remediation: ["Update Sample Chat"], kbs: [], windows: true, mac: true, rate: 0.35 },
  { cve: "CVE-2099-0006", severity: "low", score: 3.3, exprt: "low", exploit: "Unproven", kev: false, product: "Sample Zip 23", remediation: ["Update Sample Zip"], kbs: [], windows: true, mac: false, rate: 0.2 }
];

function sampleFalcon(base, index, lastSeen, now, random) {
  const stale = index % 13 === 5;
  const platformKey = base.platform === "windows" ? "windows" : "mac";
  const vulnerabilities = SAMPLE_CVES.filter((cve) => cve[platformKey] && random() < cve.rate)
    .map(({ windows: _w, mac: _m, rate: _r, ...cve }) => ({ ...cve, source: "crowdstrike", status: "open", description: "Sample vulnerability used to demonstrate the dashboard.", first_seen: hoursAgo(now, 24 * (3 + random() * 40)), aid: `cs-${index}`, hostname: base.hostname }));
  return {
    ...base, source: "crowdstrike", source_id: `cs-${index}`, os: { ...base.os }, os_approximate: true,
    last_check_in: stale ? hoursAgo(now, 24 * (9 + random() * 20)) : new Date(Math.min(now, Date.parse(lastSeen) + 3_600_000)).toISOString(),
    managed: true, compliance: "unknown", encrypted: null, security: {}, ownership: "", apps: null, vulnerabilities,
    raw: { device_id: `cs-${index}`, hostname: base.hostname, serial_number: base.serial_number, platform_name: base.platform === "windows" ? "Windows" : "Mac", os_version: base.os.name, agent_version: "7.30.20103", product_type_desc: "Workstation", status: "normal", reduced_functionality_mode: "no", system_manufacturer: base.manufacturer, system_product_name: base.model, tags: ["SensorGroupingTags/sample"], note: "Sample record. Connect CrowdStrike to see your real fields." },
    sensor: { version: random() < 0.8 ? "7.30.20103" : "7.28.19708", rfm: index % 29 === 7, status: index === 111 ? "contained" : "normal", contained: index === 111, product_type: "Workstation", tags: [] }
  };
}

function weighted(random, entries, weightIndex) {
  const total = entries.reduce((sum, entry) => sum + entry[weightIndex], 0);
  let roll = random() * total;
  for (const entry of entries) {
    roll -= entry[weightIndex];
    if (roll <= 0) return entry;
  }
  return entries.at(-1);
}

const pickVersion = (random, versions) => (random() < 0.86 ? versions[0] : versions[1 + Math.floor(random() * (versions.length - 1))]);
const hoursAgo = (now, hours) => new Date(now - hours * 3_600_000).toISOString();

export function sampleFleet({ now = Date.now(), seed = 4242 } = {}) {
  const random = seededRandom(seed);
  const records = [];
  const checkInHours = () => {
    const roll = random();
    if (roll < 0.78) return random() * 20;
    if (roll < 0.9) return 24 + random() * 24 * 9;
    if (roll < 0.96) return 24 * (15 + random() * 15);
    return 24 * (35 + random() * 40);
  };

  for (let index = 0; index < 44; index += 1) {
    const person = PEOPLE[index];
    const [first, last] = person.split(" ");
    const email = `${first}.${last}`.toLowerCase().replace(/[^a-z.]/g, "") + "@example.com";
    const serial = `C02${(index * 7919 + 104729).toString(36).toUpperCase().padStart(6, "X")}MD6T`.slice(0, 12);
    const hostname = `MAC-${first.toUpperCase()}${last[0]}`.replace(/[^A-Z0-9-]/g, "");
    const [version, build] = weighted(random, MAC_OS, 2);
    const model = MAC_MODELS[Math.floor(random() * MAC_MODELS.length)];
    const apps = MAC_APPS.filter(() => random() < 0.72).map(([name, bundle, publisher, versions]) => ({ name, version: pickVersion(random, versions), publisher, bundle_id: bundle }));
    for (const [name, bundle, publisher, version, rate] of MAC_AGENTS) if (random() < rate) apps.push({ name, version, publisher, bundle_id: bundle });
    const encrypted = random() > 0.07;
    const lastSeen = hoursAgo(now, checkInHours());
    const security = { sip: random() > 0.04, gatekeeper: random() > 0.06, firewall: random() > 0.22 };
    const inJamf = index !== 41 && index !== 43;
    const inIntune = index % 3 !== 2 || !inJamf;
    const hasAgent = index % 4 === 0;
    const base = { hostname, serial_number: serial, platform: "macos", model, manufacturer: "Apple", os: { name: "macOS", version, build }, user: { name: person, email }, sample: true };
    if (inJamf) {
      records.push({ ...base, source: "jamf", source_id: String(1000 + index), last_check_in: lastSeen, enrolled_at: hoursAgo(now, 24 * (60 + random() * 600)), managed: index !== 17, compliance: "unknown", encrypted, security, ownership: "", apps });
    }
    if (inIntune) {
      const compliant = encrypted && security.firewall && random() > 0.1;
      records.push({ ...base, source: "intune", source_id: `mac-${index}`, last_check_in: hoursAgo(now, Math.max(0, (now - Date.parse(lastSeen)) / 3_600_000 + random() * 6)), enrolled_at: null, managed: true, compliance: compliant ? "compliant" : random() < 0.3 ? "ingraceperiod" : "noncompliant", encrypted, security: { jailbroken: false }, ownership: "company", apps: null });
    }
    if (hasAgent) {
      records.push({ ...base, source: "agent", source_id: `dev_sample_${index}`, last_check_in: hoursAgo(now, random() * 2), managed: true, compliance: "unknown", encrypted: null, security: {}, ownership: "", apps });
    }
    if (apps.some((app) => app.name === "Falcon")) records.push(sampleFalcon(base, index, lastSeen, now, random));
  }

  for (let index = 0; index < 36; index += 1) {
    const person = PEOPLE[44 + index];
    const [first, last] = person.split(" ");
    const email = `${first}.${last}`.toLowerCase().replace(/[^a-z.]/g, "") + "@example.com";
    const [manufacturer, model] = WIN_MODELS[Math.floor(random() * WIN_MODELS.length)];
    const serial = `${manufacturer.slice(0, 2).toUpperCase()}${(index * 6151 + 92821).toString(36).toUpperCase().padStart(7, "0")}`;
    const hostname = `WIN-${(1000 + index * 37).toString()}${last[0]}`;
    const [version] = weighted(random, WIN_OS, 1);
    const build = Number(version.split(".")[2]);
    const apps = WIN_APPS.filter(() => random() < 0.7).map(([name, publisher, versions]) => ({ name, version: pickVersion(random, versions), publisher, bundle_id: "" }));
    for (const [name, publisher, version, rate] of WIN_AGENTS) if (random() < rate) apps.push({ name, version, publisher, bundle_id: "" });
    const ubr = Number(version.split(".")[3]);
    const reported = index % 3 === 0 ? { reported_kbs: [ubr >= 7171 ? "KB5099701" : ubr >= 6899 ? "KB5099601" : "KB5094001", "KB5098950", "KB5097800"], reported_kbs_at: hoursAgo(now, 6 + random() * 30) } : {};
    const encrypted = random() > 0.06;
    const lastSeen = hoursAgo(now, checkInHours());
    const inIntune = index !== 33 && index !== 35;
    const hasAgent = index % 4 === 1 || !inIntune;
    const base = { hostname, serial_number: serial, platform: "windows", model, manufacturer, os: { name: build >= 22000 ? "Windows 11" : "Windows 10", version, build: "" }, user: { name: person, email }, sample: true };
    if (inIntune) {
      const compliant = encrypted && build >= 22000 && random() > 0.12;
      records.push({ ...base, source: "intune", source_id: `win-${index}`, last_check_in: lastSeen, enrolled_at: hoursAgo(now, 24 * (30 + random() * 500)), managed: true, compliance: compliant ? "compliant" : random() < 0.25 ? "ingraceperiod" : "noncompliant", encrypted, security: { jailbroken: false }, ownership: index === 20 ? "personal" : "company", apps, ...reported });
    }
    if (apps.some((app) => app.name === "CrowdStrike Windows Sensor")) records.push(sampleFalcon(base, 100 + index, lastSeen, now, random));
    if (hasAgent) {
      records.push({ ...base, source: "agent", source_id: `dev_sample_w${index}`, last_check_in: hoursAgo(now, random() * 3), managed: true, compliance: "unknown", encrypted: inIntune ? null : random() > 0.5, security: {}, ownership: "", apps });
    }
  }
  return records;
}
