import { strict as assert } from "node:assert";
import { test } from "node:test";

import type * as vscode from "vscode";

import type { Dependency } from "../models/Dependency";
import { ApplyError } from "../remediation/apply/ApplyError";
import type { FileChange } from "../remediation/apply/FileChange";
import type { RemediationPlan } from "../remediation/apply/RemediationPlan";
import {
  createRemediationApprovalBinding,
  RemediationApprovalRegistry,
  remediationPlanHash,
  remediationRecommendationHash,
} from "../remediation/apply/RemediationApproval";
import type { RemediationRecommendation } from "../remediation/RemediationModels";

const ROOT = "C:\\workspace\\project";
const MANIFEST = `${ROOT}\\package.json`;
const LOCKFILE = `${ROOT}\\package-lock.json`;
const PREVIEW_ID = "A".repeat(43);
const BEFORE_MANIFEST = "a".repeat(64);
const AFTER_MANIFEST = "b".repeat(64);
const BEFORE_LOCK = "c".repeat(64);
const AFTER_LOCK = "d".repeat(64);

function uri(path: string): vscode.Uri {
  return {
    scheme: "file",
    fsPath: path,
    path: path.replaceAll("\\", "/"),
    toString: () => `file:///${path.replaceAll("\\", "/")}`,
  } as vscode.Uri;
}

function recommendation(
  overrides: Partial<RemediationRecommendation> = {},
): RemediationRecommendation {
  const dependency: Dependency = {
    name: "lodash",
    manifestName: "lodash",
    ecosystem: "npm",
    requestedVersion: "^4.17.20",
    installedVersion: "4.17.20",
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
    manifestPath: MANIFEST,
    lockfilePath: LOCKFILE,
    packageManager: "npm",
    projectPath: ROOT,
    workspacePath: ROOT,
    dependencyPath: ["fixture", "lodash@4.17.20"],
  };
  return {
    recommendationKey: "opaque-recommendation-key",
    vulnerabilityId: "GHSA-test",
    vulnerabilityIds: ["GHSA-test", "CVE-2026-0001"],
    dependency,
    currentVersion: "4.17.20",
    recommendedVersion: "4.17.21",
    fixedVersions: ["4.17.21"],
    strategy: "upgrade-direct",
    confidence: "high",
    dependencyPath: dependency.dependencyPath ?? [],
    directDependency: true,
    breakingChangeRisk: "low",
    reason: "Provider-listed exact remediation.",
    evidence: [{ source: "osv", description: "Exact fixed version." }],
    ...overrides,
  };
}

function files(): readonly FileChange[] {
  return Object.freeze([
    Object.freeze({
      uri: uri(MANIFEST),
      operation: "modify" as const,
      beforeHash: BEFORE_MANIFEST,
      afterHash: AFTER_MANIFEST,
      description: "Update the direct dependency declaration.",
    }),
    Object.freeze({
      uri: uri(LOCKFILE),
      operation: "modify" as const,
      beforeHash: BEFORE_LOCK,
      afterHash: AFTER_LOCK,
      description: "Reuse the proven package-lock resolution.",
    }),
  ]);
}

function plan(
  rec: RemediationRecommendation = recommendation(),
  changedFiles: readonly FileChange[] = files(),
): RemediationPlan {
  return Object.freeze({
    id: "P".repeat(43),
    recommendationKey: rec.recommendationKey,
    recommendation: rec,
    capability: "safe",
    files: changedFiles,
    warnings: Object.freeze([]),
    validationSteps: Object.freeze([
      Object.freeze({
        kind: "file-format" as const,
        description: "Validate bounded JSON.",
        required: true,
      }),
    ]),
    expectedOutcome: Object.freeze({
      packageName: rec.dependency.name,
      fromVersion: rec.currentVersion,
      ...(rec.recommendedVersion === undefined
        ? {}
        : { toVersion: rec.recommendedVersion }),
      targetedVulnerabilityIds: Object.freeze([...rec.vulnerabilityIds]),
      expectedAddressed: rec.vulnerabilityIds.length,
      requiresCompleteCoverage: true,
    }),
    reasonCode: "safe-npm-existing-resolution",
    registryProvenanceFingerprint: "e".repeat(64),
    scanGeneration: "scan-generation-1",
  });
}

void test("approval binds the exact workspace, dependency, evidence, and file hashes", () => {
  const proposal = plan();
  const binding = createRemediationApprovalBinding(
    proposal,
    PREVIEW_ID,
    PREVIEW_ID,
  );
  assert.equal(binding.workspacePath, ROOT);
  assert.equal(binding.packageName, "lodash");
  assert.equal(binding.currentVersion, "4.17.20");
  assert.equal(binding.targetVersion, "4.17.21");
  assert.deepEqual(binding.vulnerabilityIds, ["CVE-2026-0001", "GHSA-test"]);
  assert.deepEqual(
    binding.files.map((entry) => [entry.beforeHash, entry.afterHash]),
    [
      [BEFORE_MANIFEST, AFTER_MANIFEST],
      [BEFORE_LOCK, AFTER_LOCK],
    ],
  );
  assert.match(binding.recommendationHash, /^[a-f0-9]{64}$/u);
  assert.match(binding.planHash, /^[a-f0-9]{64}$/u);
  assert.ok(Object.isFrozen(binding));
  assert.ok(Object.isFrozen(binding.files));
  assert.ok(Object.isFrozen(binding.files[0]));
});

void test("recommendation and plan hashes are deterministic and material", () => {
  const original = plan();
  assert.equal(remediationPlanHash(original), remediationPlanHash(plan()));
  assert.equal(
    remediationRecommendationHash(original.recommendation),
    remediationRecommendationHash(recommendation()),
  );
  const changedEvidence = recommendation({
    reason: "Different provider evidence.",
  });
  assert.notEqual(
    remediationRecommendationHash(original.recommendation),
    remediationRecommendationHash(changedEvidence),
  );
  assert.notEqual(remediationPlanHash(original), remediationPlanHash(plan(changedEvidence)));
});

void test("approval is opaque, expiring, one-use, and generation-revocable", () => {
  let now = 1_000;
  const registry = new RemediationApprovalRegistry({
    clock: () => now,
    maximumAgeMs: 1_000,
  });
  const issued = registry.issue(plan(), PREVIEW_ID, PREVIEW_ID);
  assert.match(issued.id, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(registry.validate(PREVIEW_ID, PREVIEW_ID, plan()).valid, true);
  assert.equal(registry.consume(PREVIEW_ID, PREVIEW_ID, plan()).valid, true);
  assert.deepEqual(registry.consume(PREVIEW_ID, PREVIEW_ID, plan()), {
    valid: false,
    reason: "not-found",
  });

  registry.issue(plan(), PREVIEW_ID, PREVIEW_ID);
  registry.invalidateAll();
  assert.deepEqual(registry.validate(PREVIEW_ID, PREVIEW_ID, plan()), {
    valid: false,
    reason: "not-found",
  });

  registry.issue(plan(), PREVIEW_ID, PREVIEW_ID);
  now += 1_000;
  assert.deepEqual(registry.validate(PREVIEW_ID, PREVIEW_ID, plan()), {
    valid: false,
    reason: "expired",
  });
});

void test("any approved identity, content, recommendation, or generation change is stale", () => {
  const variants: readonly RemediationPlan[] = [
    plan(recommendation({ currentVersion: "4.17.19" })),
    plan(recommendation({ recommendedVersion: "4.17.22", fixedVersions: ["4.17.22"] })),
    plan(recommendation({ vulnerabilityIds: ["GHSA-forged"] })),
    plan(recommendation({
      dependency: { ...recommendation().dependency, workspacePath: "C:\\other" },
    })),
    plan(recommendation({ reason: "Changed evidence." })),
    Object.freeze({ ...plan(), scanGeneration: "scan-generation-2" }),
    plan(recommendation(), Object.freeze([
      Object.freeze({ ...files()[0], beforeHash: "f".repeat(64) }) as FileChange,
      files()[1] as FileChange,
    ])),
  ];
  for (const variant of variants) {
    const registry = new RemediationApprovalRegistry();
    registry.issue(plan(), PREVIEW_ID, PREVIEW_ID);
    assert.deepEqual(registry.validate(PREVIEW_ID, PREVIEW_ID, variant), {
      valid: false,
      reason: "mismatch",
    });
  }
});

void test("approval refuses preview-only, transitive, malformed, and wrong-target plans", () => {
  const attempts: readonly RemediationPlan[] = [
    Object.freeze({ ...plan(), capability: "preview-only" }),
    plan(recommendation({
      strategy: "upgrade-transitive",
      directDependency: false,
      dependency: {
        ...recommendation().dependency,
        dependencyType: "transitive",
      },
    })),
    plan(recommendation(), Object.freeze([files()[0] as FileChange])),
    plan(recommendation(), Object.freeze([
      Object.freeze({
        ...(files()[0] as FileChange),
        operation: "create" as const,
      }),
      files()[1] as FileChange,
    ])),
  ];
  for (const attempt of attempts) {
    const registry = new RemediationApprovalRegistry();
    assert.throws(
      () => registry.issue(attempt, PREVIEW_ID, PREVIEW_ID),
      ApplyError,
    );
  }
  const registry = new RemediationApprovalRegistry();
  assert.deepEqual(registry.validate("forged", PREVIEW_ID, plan()), {
    valid: false,
    reason: "invalid-token",
  });
});

void test("hashing supports unsupported no-target proposals without granting approval", () => {
  const withoutRecommendedVersion = { ...recommendation() };
  delete withoutRecommendedVersion.recommendedVersion;
  const noTarget: RemediationRecommendation = Object.freeze({
    ...withoutRecommendedVersion,
    fixedVersions: [],
    strategy: "no-fixed-version",
  });
  const unsupported = Object.freeze({
    ...plan(noTarget, Object.freeze([])),
    capability: "unsupported" as const,
    reasonCode: "no-exact-target" as const,
  });
  assert.match(remediationPlanHash(unsupported), /^[a-f0-9]{64}$/u);
  assert.throws(
    () =>
      new RemediationApprovalRegistry().issue(
        unsupported,
        PREVIEW_ID,
        PREVIEW_ID,
      ),
    /cannot be applied automatically/u,
  );
});
