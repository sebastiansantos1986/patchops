import assert from "node:assert/strict";
import { test } from "node:test";
import { createDashboardSession, safeEqual, verifyDashboardSession } from "../src/auth.mjs";

test("dashboard sessions are signed, scoped, and expire", () => {
  const token = createDashboardSession("correct-secret", 60);
  assert.equal(verifyDashboardSession(token, "correct-secret"), true);
  assert.equal(verifyDashboardSession(token, "wrong-secret"), false);
  assert.equal(verifyDashboardSession(createDashboardSession("correct-secret", -1), "correct-secret"), false);
});

test("constant-time comparison handles missing and unequal values", () => {
  assert.equal(safeEqual("same", "same"), true);
  assert.equal(safeEqual("short", "longer"), false);
  assert.equal(safeEqual(undefined, "secret"), false);
});
