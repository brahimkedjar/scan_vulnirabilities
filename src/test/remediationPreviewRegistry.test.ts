import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { RemediationPlan } from "../remediation/apply/RemediationPlan";
import { RemediationPreviewRegistry } from "../remediation/apply/RemediationPreviewRegistry";

const plan = Object.freeze({ id: "plan", recommendationKey: "rec" }) as RemediationPlan;

void test("preview tokens are opaque, one-use, and expire", () => {
  let now = 1_000;
  const registry = new RemediationPreviewRegistry({
    clock: () => now,
    maximumAgeMs: 1_000,
  });
  const issued = registry.issue(plan);
  assert.match(issued.token, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(registry.peek("forged"), undefined);
  assert.equal(registry.consume(issued.token)?.plan, plan);
  assert.equal(registry.consume(issued.token), undefined);

  const expiring = registry.issue(plan);
  now += 1_000;
  assert.equal(registry.peek(expiring.token), undefined);
});

void test("preview invalidation revokes every outstanding authority", () => {
  const registry = new RemediationPreviewRegistry();
  const first = registry.issue(plan);
  const second = registry.issue(plan);
  registry.invalidateAll();
  assert.equal(registry.peek(first.token), undefined);
  assert.equal(registry.peek(second.token), undefined);
});
