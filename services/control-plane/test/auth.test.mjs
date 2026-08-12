import assert from "node:assert/strict";
import { test } from "node:test";
import { createDashboardSession, hashPassword, safeEqual, verifyDashboardSession, verifyPassword } from "../src/auth.mjs";

test("dashboard sessions are signed, scoped, and expire", () => {
  const user = { id: "usr_1", username: "reviewer", role: "reviewer" };
  const token = createDashboardSession("correct-secret", user, 60);
  assert.equal(verifyDashboardSession(token, "correct-secret").username, "reviewer");
  assert.equal(verifyDashboardSession(token, "wrong-secret"), null);
  assert.equal(verifyDashboardSession(createDashboardSession("correct-secret", user, -1), "correct-secret"), null);
});

test("console passwords use salted scrypt hashes", () => {
  const hash = hashPassword("a-long-test-password");
  assert.equal(verifyPassword("a-long-test-password", hash), true);
  assert.equal(verifyPassword("wrong-password", hash), false);
  assert.notEqual(hash, hashPassword("a-long-test-password"));
});

test("constant-time comparison handles missing and unequal values", () => {
  assert.equal(safeEqual("same", "same"), true);
  assert.equal(safeEqual("short", "longer"), false);
  assert.equal(safeEqual(undefined, "secret"), false);
});
