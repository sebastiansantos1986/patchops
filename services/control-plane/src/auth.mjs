import { createHmac, timingSafeEqual } from "node:crypto";

const encode = (value) => Buffer.from(value).toString("base64url");
const sign = (value, secret) => createHmac("sha256", secret).update(value).digest("base64url");

export function safeEqual(left, right) {
  const a = Buffer.from(String(left ?? ""));
  const b = Buffer.from(String(right ?? ""));
  return a.length === b.length && timingSafeEqual(a, b);
}

export function createDashboardSession(secret, lifetimeSeconds = 8 * 60 * 60) {
  const payload = encode(JSON.stringify({ role: "dashboard", exp: Math.floor(Date.now() / 1000) + lifetimeSeconds }));
  return `${payload}.${sign(payload, secret)}`;
}

export function verifyDashboardSession(token, secret) {
  try {
    const [payload, signature, extra] = String(token ?? "").split(".");
    if (!payload || !signature || extra || !safeEqual(signature, sign(payload, secret))) return false;
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return decoded.role === "dashboard" && Number(decoded.exp) > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

export function bearerToken(request) {
  const [scheme, token] = String(request.headers.authorization ?? "").split(" ");
  return scheme?.toLowerCase() === "bearer" ? token : null;
}
