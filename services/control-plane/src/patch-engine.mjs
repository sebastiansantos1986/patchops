const clean = (value) => String(value ?? "").trim();

export function softwareIdentity(platform, software) {
  const normalizedPlatform = clean(platform).toLowerCase();
  const identifier = normalizedPlatform === "macos"
    ? clean(software.bundle_identifier || software.name)
    : clean(software.product_code || software.bundle_identifier || software.name);
  return `${normalizedPlatform}:${identifier.toLowerCase()}`;
}

export function compareVersions(left, right) {
  const tokenize = (value) => clean(value).toLowerCase().match(/\d+|[a-z]+/g) ?? [];
  const a = tokenize(left);
  const b = tokenize(right);
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = a[index] ?? "0";
    const rightPart = b[index] ?? "0";
    const leftNumber = /^\d+$/.test(leftPart) ? Number(leftPart) : null;
    const rightNumber = /^\d+$/.test(rightPart) ? Number(rightPart) : null;
    if (leftNumber !== null && rightNumber !== null && leftNumber !== rightNumber) return leftNumber < rightNumber ? -1 : 1;
    if (leftNumber === null || rightNumber === null) {
      const order = leftPart.localeCompare(rightPart);
      if (order) return order < 0 ? -1 : 1;
    }
  }
  return 0;
}

export function assessDevice(device, catalog) {
  const catalogByIdentity = new Map(catalog.map((entry) => [entry.identity, entry]));
  const software = (device.software ?? []).map((application) => {
    const identity = softwareIdentity(device.platform, application);
    const baseline = catalogByIdentity.get(identity);
    if (!baseline) return { ...application, identity, patch_status: "unmanaged", approved_version: null };
    const comparison = compareVersions(application.version, baseline.approved_version);
    return {
      ...application,
      identity,
      catalog_id: baseline.id,
      approved_version: baseline.approved_version,
      severity: baseline.severity,
      patch_status: comparison < 0 ? "outdated" : "compliant"
    };
  });
  const outdated = software.filter(({ patch_status }) => patch_status === "outdated");
  return {
    ...device,
    software,
    patch_summary: {
      installed: software.length,
      managed: software.filter(({ patch_status }) => patch_status !== "unmanaged").length,
      outdated: outdated.length,
      compliant: software.filter(({ patch_status }) => patch_status === "compliant").length,
      highest_severity: outdated.some(({ severity }) => severity === "critical") ? "critical" : outdated.some(({ severity }) => severity === "high") ? "high" : outdated.length ? "medium" : "none"
    }
  };
}
