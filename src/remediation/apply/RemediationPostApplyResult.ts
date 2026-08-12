import type { Dependency } from "../../models/Dependency";
import type { ScanResult } from "../../models/ScanResult";
import { classifyScanCoverage } from "../../services/ScanResultStore";
import type { RollbackResult, ScanCounts } from "./ApplyResult";
import type { RemediationPlan } from "./RemediationPlan";

export type PostApplyVerificationStatus =
  | "FIXED"
  | "STILL_VULNERABLE"
  | "INCOMPLETE_COVERAGE"
  | "PROVIDER_UNAVAILABLE"
  | "UNKNOWN";

export type RemediationFinalStatus =
  | "applied"
  | "failed"
  | "rolledBack"
  | "rollbackUnverified";

export interface RemediationModifiedFileResult {
  readonly uri: string;
  readonly beforeHash: string;
  readonly afterHash: string;
}

export interface PostApplyScanSummary {
  readonly status: PostApplyVerificationStatus;
  readonly coverageComplete: boolean;
  readonly targetVersionResolved: boolean;
  readonly targetedVulnerabilitiesRemaining: number;
  readonly counts: ScanCounts;
}

export interface RemediationPostApplyResult {
  readonly remediationId: string;
  readonly timestamp: string;
  readonly workspace: string;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly oldVersion: string;
  readonly newVersion: string;
  readonly vulnerabilityIds: readonly string[];
  readonly filesModified: readonly RemediationModifiedFileResult[];
  readonly beforeHashes: readonly string[];
  readonly afterHashes: readonly string[];
  readonly approvalHash: string;
  readonly planHash: string;
  readonly transactionId: string;
  readonly verificationResult: PostApplyVerificationStatus;
  readonly rollbackStatus: "not-required" | "verified" | "unverified";
  readonly postScanResult: PostApplyScanSummary;
  readonly finalStatus: RemediationFinalStatus;
}

export interface RemediationPostApplyResultInput {
  readonly remediationId: string;
  readonly timestamp: string;
  readonly approvalHash: string;
  readonly transactionId: string;
  readonly plan: RemediationPlan;
  readonly postScanResult: PostApplyScanSummary;
  readonly rollback?: RollbackResult;
}

function sameTargetOrigin(candidate: Dependency, expected: Dependency): boolean {
  return (
    candidate.name === expected.name &&
    candidate.manifestName === expected.manifestName &&
    candidate.dependencyType === expected.dependencyType &&
    candidate.projectPath === expected.projectPath &&
    candidate.workspacePath === expected.workspacePath &&
    candidate.manifestPath === expected.manifestPath &&
    candidate.lockfilePath === expected.lockfilePath &&
    candidate.packageManager === expected.packageManager
  );
}

function scanCounts(results: readonly ScanResult[]): ScanCounts {
  const vulnerabilities = results.flatMap((result) => result.vulnerabilities);
  const count = (severity: string): number =>
    vulnerabilities.filter((item) => item.severity === severity).length;
  return Object.freeze({
    dependencies: results.reduce(
      (total, result) => total + result.dependenciesScanned,
      0,
    ),
    vulnerabilities: vulnerabilities.length,
    critical: count("CRITICAL"),
    high: count("HIGH"),
    medium: count("MEDIUM"),
    low: count("LOW"),
    unknown: count("UNKNOWN"),
  });
}

function providerUnavailable(results: readonly ScanResult[]): boolean {
  const providers = results.flatMap((result) => result.providerResults);
  return (
    providers.length === 0 ||
    providers.every(
      (provider) =>
        provider.status === "unavailable" || provider.successful === 0,
    )
  );
}

/**
 * Classifies only a fresh, unfiltered post-write scan. Absence of a finding is
 * FIXED evidence only when the exact target occurrence resolved and the entire
 * scan/provider coverage is complete.
 */
export function classifyPostApplyScan(
  results: readonly ScanResult[],
  plan: RemediationPlan,
): PostApplyScanSummary {
  const targetVersion = plan.expectedOutcome.toVersion;
  const ids = new Set(plan.expectedOutcome.targetedVulnerabilityIds);
  const targetDependencies =
    targetVersion === undefined
      ? []
      : results.flatMap((result) =>
          result.dependencies.filter(
            (dependency) =>
              sameTargetOrigin(dependency, plan.recommendation.dependency) &&
              dependency.installedVersion === targetVersion &&
              dependency.resolutionStatus !== "unresolved" &&
              dependency.resolutionStatus !== "unsupported",
          ),
        );
  const targetedVulnerabilitiesRemaining =
    targetVersion === undefined
      ? 0
      : results.reduce(
          (total, result) =>
            total +
            result.vulnerabilities.filter(
              (vulnerability) =>
                ids.has(vulnerability.id) &&
                vulnerability.ecosystem ===
                  plan.recommendation.dependency.ecosystem &&
                vulnerability.packageName === plan.expectedOutcome.packageName &&
                vulnerability.installedVersion === targetVersion,
            ).length,
          0,
        );
  const coverageComplete = classifyScanCoverage(results) === "complete";
  let status: PostApplyVerificationStatus;
  if (providerUnavailable(results)) {
    status = "PROVIDER_UNAVAILABLE";
  } else if (!coverageComplete) {
    status = "INCOMPLETE_COVERAGE";
  } else if (targetDependencies.length !== 1 || targetVersion === undefined) {
    status = "UNKNOWN";
  } else if (targetedVulnerabilitiesRemaining > 0) {
    status = "STILL_VULNERABLE";
  } else {
    status = "FIXED";
  }
  return Object.freeze({
    status,
    coverageComplete,
    targetVersionResolved: targetDependencies.length === 1,
    targetedVulnerabilitiesRemaining,
    counts: scanCounts(results),
  });
}

function requireSafeHash(value: string, label: string): string {
  if (!/^[A-Za-z0-9_-]{32,128}$/u.test(value)) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

/** Creates the bounded immutable, content-free record required after apply. */
export function createRemediationPostApplyResult(
  input: RemediationPostApplyResultInput,
): RemediationPostApplyResult {
  const target = input.plan.expectedOutcome.toVersion;
  if (target === undefined || !Number.isFinite(Date.parse(input.timestamp))) {
    throw new TypeError("A post-apply result requires an exact target and timestamp");
  }
  const files = input.plan.files.map((file) => {
    if (file.afterHash === undefined) {
      throw new TypeError("A modified file is missing its after hash");
    }
    return Object.freeze({
      uri: file.uri.toString(),
      beforeHash: requireSafeHash(file.beforeHash, "beforeHash"),
      afterHash: requireSafeHash(file.afterHash, "afterHash"),
    });
  });
  const rollbackStatus =
    input.rollback === undefined || !input.rollback.attempted
      ? "not-required"
      : input.rollback.verified
        ? "verified"
        : "unverified";
  const finalStatus: RemediationFinalStatus =
    rollbackStatus === "verified"
      ? "rolledBack"
      : rollbackStatus === "unverified"
        ? "rollbackUnverified"
        : input.postScanResult.status === "FIXED"
          ? "applied"
          : "failed";
  return Object.freeze({
    remediationId: input.remediationId.slice(0, 128),
    timestamp: input.timestamp,
    workspace: (input.plan.recommendation.dependency.workspacePath ?? "").slice(
      0,
      65_536,
    ),
    ecosystem: input.plan.recommendation.dependency.ecosystem.slice(0, 64),
    packageName: input.plan.expectedOutcome.packageName.slice(0, 512),
    oldVersion: input.plan.expectedOutcome.fromVersion.slice(0, 256),
    newVersion: target.slice(0, 256),
    vulnerabilityIds: Object.freeze([
      ...input.plan.expectedOutcome.targetedVulnerabilityIds,
    ]),
    filesModified: Object.freeze(files),
    beforeHashes: Object.freeze(files.map((file) => file.beforeHash)),
    afterHashes: Object.freeze(files.map((file) => file.afterHash)),
    approvalHash: requireSafeHash(input.approvalHash, "approvalHash"),
    planHash: requireSafeHash(input.plan.id, "planHash"),
    transactionId: input.transactionId.slice(0, 128),
    verificationResult: input.postScanResult.status,
    rollbackStatus,
    postScanResult: Object.freeze({
      ...input.postScanResult,
      counts: Object.freeze({ ...input.postScanResult.counts }),
    }),
    finalStatus,
  });
}
