import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const encode = (value) => Buffer.from(value).toString("base64url");
const sign = (value, secret) => createHmac("sha256", secret).update(value).digest("base64url");

export function safeEqual(left, right) {
  const a = Buffer.from(String(left ?? ""));
  const b = Buffer.from(String(right ?? ""));
  return a.length === b.length && timingSafeEqual(a, b);
}

export function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  return `scrypt$${salt}$${scryptSync(String(password), salt, 64).toString("hex")}`;
}

export function verifyPassword(password, encodedHash) {
  try {
    const [algorithm, salt, expected] = String(encodedHash ?? "").split("$");
    if (algorithm !== "scrypt" || !salt || !expected) return false;
    return safeEqual(scryptSync(String(password ?? ""), salt, 64).toString("hex"), expected);
  } catch {
    return false;
  }
}

export function createDashboardSession(secret, user = { username: "admin", role: "owner" }, lifetimeSeconds = 8 * 60 * 60) {
  const payload = encode(JSON.stringify({ scope: "dashboard", sub: user.id ?? "bootstrap-owner", username: user.username, role: user.role, exp: Math.floor(Date.now() / 1000) + lifetimeSeconds }));
  return `${payload}.${sign(payload, secret)}`;
}

export function verifyDashboardSession(token, secret) {
  try {
    const [payload, signature, extra] = String(token ?? "").split(".");
    if (!payload || !signature || extra || !safeEqual(signature, sign(payload, secret))) return null;
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return decoded.scope === "dashboard" && decoded.username && decoded.role && Number(decoded.exp) > Math.floor(Date.now() / 1000) ? decoded : null;
  } catch {
    return null;
  }
}

export function bearerToken(request) {
  const [scheme, token] = String(request.headers.authorization ?? "").split(" ");
  return scheme?.toLowerCase() === "bearer" ? token : null;
}
