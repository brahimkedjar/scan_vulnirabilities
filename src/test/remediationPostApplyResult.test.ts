import assert from "node:assert/strict";
import test from "node:test";

import type * as vscode from "vscode";

import type { Dependency } from "../models/Dependency";
import type { ScanResult } from "../models/ScanResult";
import type { RemediationRecommendation } from "../remediation/RemediationModels";
import type { RemediationPlan } from "../remediation/apply/RemediationPlan";
import {
  classifyPostApplyScan,
  createRemediationPostApplyResult,
} from "../remediation/apply/RemediationPostApplyResult";

const HASH = "a".repeat(64);

function uri(path: string): vscode.Uri {
  return {
    scheme: "file",
    path,
    fsPath: path,
    toString: () => `file://${path}`,
  } as vscode.Uri;
}

function dependency(version: string): Dependency {
  return {
    name: "lodash",
    ecosystem: "npm",
    requestedVersion: "^4.17.20",
    manifestName: "lodash",
    installedVersion: version,
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
    manifestPath: "/workspace/package.json",
    lockfilePath: "/workspace/package-lock.json",
    packageManager: "npm",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    dependencyPath: ["app", "lodash"],
  };
}

function plan(): RemediationPlan {
  const recommendation: RemediationRecommendation = {
    recommendationKey: "recommendation",
    vulnerabilityId: "GHSA-test",
    vulnerabilityIds: ["GHSA-test"],
    dependency: dependency("4.17.20"),
    currentVersion: "4.17.20",
    recommendedVersion: "4.17.21",
    fixedVersions: ["4.17.21"],
    strategy: "upgrade-direct",
    confidence: "high",
    dependencyPath: ["app", "lodash"],
    directDependency: true,
    breakingChangeRisk: "low",
    reason: "Provider-proven target",
    evidence: [],
  };
  return {
    id: "b".repeat(64),
    recommendationKey: recommendation.recommendationKey,
    recommendation,
    capability: "safe",
    files: [
      {
        uri: uri("/workspace/package.json"),
        operation: "modify",
        beforeHash: HASH,
        afterHash: "c".repeat(64),
        description: "manifest",
      },
    ],
    warnings: [],
    validationSteps: [],
    expectedOutcome: {
      packageName: "lodash",
      fromVersion: "4.17.20",
      toVersion: "4.17.21",
      targetedVulnerabilityIds: ["GHSA-test"],
      expectedAddressed: 1,
      requiresCompleteCoverage: true,
    },
    reasonCode: "safe-npm-existing-resolution",
  };
}

function result(
  options: {
    provider?: "available" | "partial" | "unavailable";
    vulnerable?: boolean;
    resolved?: boolean;
  } = {},
): ScanResult {
  const provider = options.provider ?? "available";
  const resolved = options.resolved ?? true;
  return {
    workspacePath: "/workspace",
    scannedAt: "2026-08-12T00:00:00.000Z",
    durationMs: 1,
    packageManagers: ["npm"],
    dependenciesScanned: resolved ? 1 : 0,
    vulnerableDependencies: options.vulnerable === true ? 1 : 0,
    vulnerabilities:
      options.vulnerable === true
        ? [
            {
              id: "GHSA-test",
              aliases: [],
              packageName: "lodash",
              ecosystem: "npm",
              installedVersion: "4.17.21",
              severity: "HIGH",
              summary: "test",
              fixedVersions: [],
              remediationCandidates: [],
              references: [],
              source: "OSV",
            },
          ]
        : [],
    dependencies: resolved ? [dependency("4.17.21")] : [],
    errors: resolved ? [] : [{ code: "DEPENDENCY_UNRESOLVED", message: "gap" }],
    providerResults: [
      {
        provider: "OSV",
        status: provider,
        dependenciesEligible: 1,
        dependenciesSubmitted: 1,
        successful: provider === "available" ? 1 : 0,
        failed: provider === "available" ? 0 : 1,
        cacheHits: 0,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: options.vulnerable === true ? 1 : 0,
      },
    ],
    ecosystemCoverage: [
      {
        ecosystem: "npm",
        packageManagers: ["npm"],
        discovered: 1,
        resolved: resolved ? 1 : 0,
        checked: provider === "available" && resolved ? 1 : 0,
        vulnerable: options.vulnerable === true ? 1 : 0,
        unresolved: resolved ? 0 : 1,
        unsupported: 0,
      },
    ],
    cancelled: false,
  };
}

void test("classifies only complete exact-target evidence as FIXED", () => {
  assert.equal(classifyPostApplyScan([result()], plan()).status, "FIXED");
  assert.equal(
    classifyPostApplyScan([result({ vulnerable: true })], plan()).status,
    "STILL_VULNERABLE",
  );
  assert.equal(
    classifyPostApplyScan([result({ resolved: false })], plan()).status,
    "INCOMPLETE_COVERAGE",
  );
  assert.equal(
    classifyPostApplyScan([result({ provider: "unavailable" })], plan()).status,
    "PROVIDER_UNAVAILABLE",
  );
});

void test("creates an immutable content-free post-apply result", () => {
  const postScan = classifyPostApplyScan([result()], plan());
  const value = createRemediationPostApplyResult({
    remediationId: "remediation-1",
    timestamp: "2026-08-12T00:00:00.000Z",
    approvalHash: "d".repeat(64),
    transactionId: "transaction-1",
    plan: plan(),
    postScanResult: postScan,
  });
  assert.equal(value.finalStatus, "applied");
  assert.equal(value.verificationResult, "FIXED");
  assert.deepEqual(value.beforeHashes, [HASH]);
  assert.deepEqual(value.afterHashes, ["c".repeat(64)]);
  assert.equal(Object.isFrozen(value), true);
  assert.equal(Object.isFrozen(value.filesModified), true);
  assert.equal("beforeContent" in value.filesModified[0]!, false);
});

void test("rollback status always overrides a post-scan success claim", () => {
  const postScan = classifyPostApplyScan([result()], plan());
  const value = createRemediationPostApplyResult({
    remediationId: "remediation-1",
    timestamp: "2026-08-12T00:00:00.000Z",
    approvalHash: "d".repeat(64),
    transactionId: "transaction-1",
    plan: plan(),
    postScanResult: postScan,
    rollback: { attempted: true, restoredFiles: 1, verified: false },
  });
  assert.equal(value.finalStatus, "rollbackUnverified");
  assert.equal(value.rollbackStatus, "unverified");
});
