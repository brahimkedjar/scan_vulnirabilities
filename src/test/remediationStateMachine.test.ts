import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  RemediationStateError,
  RemediationStateMachine,
  RemediationStateRegistry,
} from "../remediation/apply/RemediationStateMachine";

const PLAN_HASH = "a".repeat(64);
const APPROVAL_HASH = "b".repeat(64);

function machine(): RemediationStateMachine {
  let now = 1_000;
  return new RemediationStateMachine({
    remediationId: "remediation-id",
    recommendationKey: "workspace/π:package",
    planHash: PLAN_HASH,
    clock: () => now++,
  });
}

void test("state machine enforces the complete approved apply lifecycle", () => {
  const state = machine();
  state.transition("awaitingApproval", { reason: "approval-requested" });
  state.transition("approved", {
    reason: "user-approved",
    approvalHash: APPROVAL_HASH,
  });
  state.transition("validating", { reason: "validation-started" });
  state.transition("applying", { reason: "apply-started" });
  state.transition("verifying", {
    reason: "verification-started",
    transactionId: "transaction-1",
  });
  const result = state.transition("applied", {
    reason: "verification-succeeded",
    transactionId: "transaction-1",
  });

  assert.equal(result.state, "applied");
  assert.equal(result.approvalHash, APPROVAL_HASH);
  assert.equal(result.transactionId, "transaction-1");
  assert.deepEqual(
    result.transitions.map((entry) => entry.to),
    [
      "preview",
      "awaitingApproval",
      "approved",
      "validating",
      "applying",
      "verifying",
      "applied",
    ],
  );
  assert.ok(result.transitions.slice(2).every(
    (entry) => entry.approvalHash === APPROVAL_HASH,
  ));
  assert.throws(
    () => state.transition("stale", { reason: "authority-changed" }),
    RemediationStateError,
  );
});

void test("preview cannot skip approval, validation, apply, and verification", () => {
  const state = machine();
  assert.throws(
    () =>
      state.transition("applied", {
        reason: "verification-succeeded",
        transactionId: "forged",
      }),
    /invalid remediation transition preview -> applied/u,
  );
  assert.equal(state.getSnapshot().state, "preview");
  assert.equal(state.getSnapshot().transitions.length, 1);
});

void test("failure can roll back only with an exact transaction identity", () => {
  const state = machine();
  state.transition("awaitingApproval", { reason: "approval-requested" });
  state.transition("approved", {
    reason: "user-approved",
    approvalHash: APPROVAL_HASH,
  });
  state.transition("validating", { reason: "validation-started" });
  state.transition("applying", { reason: "apply-started" });
  state.transition("failed", {
    reason: "operation-failed",
    transactionId: "transaction-1",
    errorCode: "WRITE_FAILED",
  });
  assert.throws(
    () =>
      state.transition("rolledBack", {
        reason: "rollback-verified",
        transactionId: "transaction-2",
      }),
    /transaction ID changed/u,
  );
  assert.equal(
    state.transition("rolledBack", {
      reason: "rollback-verified",
      transactionId: "transaction-1",
    }).state,
    "rolledBack",
  );
});

void test("authority hooks make open approvals stale and preserve provenance", () => {
  const registry = new RemediationStateRegistry();
  registry.create({
    remediationId: "proposal",
    recommendationKey: "recommendation",
    planHash: PLAN_HASH,
  });
  registry.transition("proposal", "awaitingApproval", {
    reason: "approval-requested",
  });
  registry.transition("proposal", "approved", {
    reason: "user-approved",
    approvalHash: APPROVAL_HASH,
  });
  const stale = registry.invalidate("proposal", "git");
  assert.equal(stale?.state, "stale");
  assert.equal(stale?.transitions.at(-1)?.reason, "authority-changed");
  assert.equal(stale?.transitions.at(-1)?.authoritySource, "git");
  assert.equal(registry.invalidate("proposal", "git"), undefined);
});

void test("unsupported and manual-review proposals are terminal", () => {
  const unsupported = machine();
  assert.equal(
    unsupported.transition("unsupported", {
      reason: "capability-unsupported",
    }).state,
    "unsupported",
  );
  const manual = machine();
  assert.equal(
    manual.transition("manualReviewRequired", {
      reason: "manual-review-required",
    }).state,
    "manualReviewRequired",
  );
  const manualAction = machine();
  assert.equal(
    manualAction.transition("manualActionRequired", {
      reason: "manual-action-required",
    }).state,
    "manualActionRequired",
  );
});

void test("post-scan terminal states require the verified transaction identity", () => {
  for (const [stateName, reason] of [
    ["verifiedFixed", "verified-fixed"],
    ["stillVulnerable", "still-vulnerable"],
    ["incompleteCoverage", "incomplete-coverage"],
    ["providerUnavailable", "provider-unavailable"],
  ] as const) {
    const state = machine();
    state.transition("awaitingApproval", { reason: "approval-requested" });
    state.transition("approved", {
      reason: "user-approved",
      approvalHash: APPROVAL_HASH,
    });
    state.transition("validating", { reason: "validation-started" });
    state.transition("applying", { reason: "apply-started" });
    state.transition("verifying", {
      reason: "verification-started",
      transactionId: "transaction-1",
    });
    assert.equal(
      state.transition(stateName, {
        reason,
        transactionId: "transaction-1",
      }).state,
      stateName,
    );
  }
});

void test("bounded registry evicts only terminal history", () => {
  const registry = new RemediationStateRegistry({ maximumRecords: 2 });
  registry.create({
    remediationId: "open",
    recommendationKey: "one",
    planHash: PLAN_HASH,
  });
  registry.create({
    remediationId: "terminal",
    recommendationKey: "two",
    planHash: PLAN_HASH,
  });
  registry.transition("terminal", "rejected", { reason: "user-rejected" });
  registry.create({
    remediationId: "new",
    recommendationKey: "three",
    planHash: PLAN_HASH,
  });
  assert.equal(registry.get("terminal"), undefined);
  assert.deepEqual(registry.getAll().map((entry) => entry.remediationId), [
    "new",
    "open",
  ]);
});

void test("malformed hashes, identifiers, clocks, and mismatched reasons fail closed", () => {
  assert.throws(
    () =>
      new RemediationStateMachine({
        remediationId: "bad\nlog",
        recommendationKey: "key",
        planHash: PLAN_HASH,
      }),
    /remediationId is invalid/u,
  );
  assert.throws(
    () =>
      new RemediationStateMachine({
        remediationId: "id",
        recommendationKey: "key",
        planHash: "forged",
      }),
    /planHash is invalid/u,
  );
  const state = machine();
  assert.throws(
    () => state.transition("awaitingApproval", { reason: "user-approved" }),
    /invalid remediation transition/u,
  );
  assert.throws(
    () =>
      state.transition("awaitingApproval", {
        reason: "approval-requested",
        authoritySource: "git",
      }),
    /authority source/u,
  );
});
