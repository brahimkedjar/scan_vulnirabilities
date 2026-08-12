import type * as vscode from "vscode";

import type { ScanResult } from "../../models/ScanResult";
import { classifyScanCoverage } from "../../services/ScanResultStore";
import { ApplyError, publicApplyError } from "./ApplyError";
import type {
  ApplyResult,
  BeforeAfterComparison,
  RemediationHistoryRecord,
  RemediationVerification,
  ScanCounts,
} from "./ApplyResult";
import type { FileChange } from "./FileChange";
import type { FileSnapshot, RemediationFileInspection } from "./FileSnapshot";
import { sha256 } from "./FileSnapshot";
import { RemediationHistory } from "./RemediationHistory";
import type { RemediationPlan } from "./RemediationPlan";
import {
  type RemediationFileSystem,
  RemediationRollback,
} from "./RemediationRollback";
import {
  MAX_FILES_PER_REMEDIATION,
  MAX_REMEDIATION_FILE_BYTES,
  MAX_REMEDIATION_TOTAL_BYTES,
  RemediationTransaction,
} from "./RemediationTransaction";
import { RemediationValidator } from "./RemediationValidator";

export interface RemediationApplyGuard {
  isWorkspaceTrusted(): boolean | Promise<boolean>;
  isScanInProgress(): boolean;
  isTargetInsideWorkspace(uri: vscode.Uri): boolean | Promise<boolean>;
  hasUnsavedChanges(uri: vscode.Uri): boolean | Promise<boolean>;
  /** Read-only SCM advisory. True blocks apply; absence never authorizes it. */
  hasUnexpectedGitChanges?(
    uri: vscode.Uri,
  ): boolean | Promise<boolean>;
}

export interface RecommendationVerifier {
  verifyRecommendation(
    plan: RemediationPlan,
    signal?: AbortSignal,
  ): boolean | Promise<boolean>;
  verifyRegistryProvenance?(
    plan: RemediationPlan,
    signal?: AbortSignal,
  ): boolean | Promise<boolean>;
}

export interface RemediationScanVerifier {
  getBeforeResults(plan: RemediationPlan): readonly ScanResult[];
  rescan(plan: RemediationPlan, signal?: AbortSignal): Promise<readonly ScanResult[]>;
}

export interface RemediationExecuteOptions {
  /** Must be true only after the dedicated Apply Fix confirmation. */
  readonly approved: boolean;
  readonly signal?: AbortSignal;
}

export interface RemediationExecutorDependencies {
  readonly fileSystem: RemediationFileSystem;
  readonly guard: RemediationApplyGuard;
  readonly recommendationVerifier: RecommendationVerifier;
  readonly scanVerifier: RemediationScanVerifier;
  readonly validator?: RemediationValidator;
  readonly rollback?: RemediationRollback;
  readonly history?: RemediationHistory;
}

interface PreparedTarget {
  readonly change: FileChange;
  readonly snapshot: FileSnapshot;
  readonly afterBytes: Uint8Array;
  readonly afterHash: string;
}

const UTF8_ENCODER = new TextEncoder();

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new ApplyError("CANCELLED");
  }
}

function safeRegularFile(inspection: RemediationFileInspection): boolean {
  return inspection.kind === "file" && !inspection.reparsePoint;
}

function sameInspectionIdentity(
  first: RemediationFileInspection,
  second: RemediationFileInspection,
): boolean {
  return (
    first.identity.value === second.identity.value &&
    first.canonicalPath === second.canonicalPath
  );
}

function scanCounts(results: readonly ScanResult[]): ScanCounts {
  const vulnerabilities = results.flatMap((result) => result.vulnerabilities);
  const severity = (value: string): number =>
    vulnerabilities.filter((item) => item.severity === value).length;
  return Object.freeze({
    dependencies: results.reduce(
      (total, result) => total + result.dependenciesScanned,
      0,
    ),
    vulnerabilities: vulnerabilities.length,
    critical: severity("CRITICAL"),
    high: severity("HIGH"),
    medium: severity("MEDIUM"),
    low: severity("LOW"),
    unknown: severity("UNKNOWN"),
  });
}

function targetedCount(
  results: readonly ScanResult[],
  plan: RemediationPlan,
): number {
  const ids = new Set(plan.expectedOutcome.targetedVulnerabilityIds);
  const expected = plan.recommendation.dependency;
  return results.reduce((total, result) => {
    const versions = new Set(
      result.dependencies
        .filter((dependency) => sameDependencyOccurrence(dependency, expected))
        .map((dependency) => dependency.installedVersion),
    );
    return (
      total +
      result.vulnerabilities.filter(
        (vulnerability) =>
          ids.has(vulnerability.id) &&
          vulnerability.packageName === plan.expectedOutcome.packageName &&
          versions.has(vulnerability.installedVersion),
      ).length
    );
  }, 0);
}

function sameDependencyOccurrence(
  candidate: ScanResult["dependencies"][number],
  expected: ScanResult["dependencies"][number],
): boolean {
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

function compareScans(
  before: readonly ScanResult[],
  after: readonly ScanResult[],
  plan: RemediationPlan,
): BeforeAfterComparison {
  const targetedBefore = targetedCount(before, plan);
  const targetedAfter = targetedCount(after, plan);
  return Object.freeze({
    before: scanCounts(before),
    after: scanCounts(after),
    targetedBefore,
    targetedAfter,
    resolved: Math.max(0, targetedBefore - targetedAfter),
    remaining: targetedAfter,
    coverageComplete: classifyScanCoverage(after) === "complete",
  });
}

function resultMessage(comparison: BeforeAfterComparison): string {
  if (comparison.remaining === 0) {
    return `${comparison.resolved.toString()} targeted vulnerabilities resolved.`;
  }
  return `Partial remediation: ${comparison.resolved.toString()} resolved, ${comparison.remaining.toString()} remain.`;
}

function hasResolvedTargetVersion(
  results: readonly ScanResult[],
  plan: RemediationPlan,
): boolean {
  const target = plan.expectedOutcome.toVersion;
  if (target === undefined) {
    return false;
  }
  return (
    results.reduce(
      (count, result) =>
        count +
        result.dependencies.filter(
      (dependency) =>
        sameDependencyOccurrence(
          dependency,
          plan.recommendation.dependency,
        ) &&
        dependency.installedVersion === target &&
        dependency.resolutionStatus !== "unresolved" &&
        dependency.resolutionStatus !== "unsupported",
        ).length,
      0,
    ) === 1
  );
}

function dependencySnapshot(
  results: readonly ScanResult[],
  plan: RemediationPlan,
): readonly string[] {
  return results
    .flatMap((result) =>
      result.dependencies
        .filter(
          (dependency) =>
            !sameDependencyOccurrence(
              dependency,
              plan.recommendation.dependency,
            ),
        )
        .map((dependency) =>
          JSON.stringify([
            result.workspacePath,
            dependency.ecosystem,
            dependency.name,
            dependency.manifestName ?? "",
            dependency.requestedVersion,
            dependency.installedVersion,
            dependency.resolutionStatus ?? "resolved",
            dependency.dependencyType,
            dependency.environment,
            dependency.declaredEnvironment ?? "",
            dependency.workspacePath ?? "",
            dependency.projectPath ?? "",
            dependency.manifestPath ?? "",
            dependency.lockfilePath ?? "",
            dependency.packageManager ?? "",
            dependency.dependencyPath ?? [],
          ]),
        ),
    )
    .sort();
}

function dependencyGraphUnchanged(
  before: readonly ScanResult[],
  after: readonly ScanResult[],
  plan: RemediationPlan,
): boolean {
  const previous = dependencySnapshot(before, plan);
  const next = dependencySnapshot(after, plan);
  return (
    previous.length === next.length &&
    previous.every((value, index) => value === next[index])
  );
}

function hasDuplicateUris(files: readonly FileChange[]): boolean {
  return new Set(files.map((change) => change.uri.toString())).size !== files.length;
}

/**
 * Single-process transactional executor. It contains no shell, package-manager,
 * registry, or arbitrary-project-code execution path.
 */
export class RemediationExecutor {
  private static active = false;
  private readonly validator: RemediationValidator;
  private readonly rollback: RemediationRollback;
  private readonly history: RemediationHistory;

  public constructor(private readonly dependencies: RemediationExecutorDependencies) {
    this.validator = dependencies.validator ?? new RemediationValidator();
    this.rollback =
      dependencies.rollback ?? new RemediationRollback(dependencies.fileSystem);
    this.history = dependencies.history ?? new RemediationHistory();
  }

  public getHistory(): readonly RemediationHistoryRecord[] {
    return this.history.getAll();
  }

  public async execute(
    plan: RemediationPlan,
    options: RemediationExecuteOptions,
  ): Promise<ApplyResult> {
    if (RemediationExecutor.active) {
      return this.finish(plan, {
        planId: plan.id,
        status: "refused",
        changedFiles: 0,
        errorCode: "CONCURRENT_REMEDIATION",
        message: "Another remediation operation is already in progress.",
      });
    }
    RemediationExecutor.active = true;
    let transaction: RemediationTransaction | undefined;
    try {
      this.validateEntry(plan, options);
      await this.validateGuards(plan, options.signal);
      const before = this.dependencies.scanVerifier.getBeforeResults(plan);
      if (
        classifyScanCoverage(before) !== "complete" ||
        !before.some((result) =>
          result.dependencies.some(
            (dependency) =>
              sameDependencyOccurrence(
                dependency,
                plan.recommendation.dependency,
              ) &&
              dependency.installedVersion === plan.expectedOutcome.fromVersion,
          ),
        ) ||
        targetedCount(before, plan) === 0
      ) {
        throw new ApplyError("STALE_RECOMMENDATION");
      }
      const prepared = await this.prepareTargets(plan, options.signal);
      for (const target of prepared) {
        this.validator.validate(target.change.uri, target.afterBytes, plan);
      }
      transaction = new RemediationTransaction(
        plan,
        prepared.map((target) => target.snapshot),
      );
      for (const target of prepared) {
        throwIfCancelled(options.signal);
        await this.validateGuards(plan, options.signal);
        await this.revalidateTarget(target);
        this.validator.validate(target.change.uri, target.afterBytes, plan);
        let afterWriteInspection: RemediationFileInspection;
        try {
          afterWriteInspection =
            await this.dependencies.fileSystem.replaceFileAtomic(
              target.change.uri,
              target.afterBytes,
              target.snapshot.inspection.identity,
              target.snapshot.hash,
            );
        } catch (error: unknown) {
          const recoveredInspection = await this.recoverUnreportedOwnedWrite(
            transaction,
            target,
          );
          if (!recoveredInspection) {
            throw new ApplyError(
              "ROLLBACK_FAILED",
              "A file replacement failed at an indeterminate point. Please inspect the affected file.",
              { cause: error },
            );
          }
          throw error;
        }
        transaction.recordOwnedWrite(
          target.change.uri,
          target.afterHash,
          afterWriteInspection,
        );
        const afterWriteBytes = await this.dependencies.fileSystem.readFile(
          target.change.uri,
        );
        if (
          !safeRegularFile(afterWriteInspection) ||
          sha256(afterWriteBytes) !== target.afterHash
        ) {
          throw new ApplyError("WRITE_FAILED");
        }
        this.validator.validate(target.change.uri, afterWriteBytes, plan);
      }

      throwIfCancelled(options.signal);
      let after: readonly ScanResult[];
      try {
        after = await this.dependencies.scanVerifier.rescan(plan, options.signal);
      } catch (error: unknown) {
        throwIfCancelled(options.signal);
        throw new ApplyError("RESCAN_FAILED", undefined, { cause: error });
      }
      throwIfCancelled(options.signal);
      // Revalidate workspace/config/recommendation authority after the
      // potentially long provider round trip and before committing writes.
      await this.validateGuards(plan, options.signal);
      await this.rehashOwnedOutputs(transaction);
      const comparison = compareScans(before, after, plan);
      if (!comparison.coverageComplete) {
        throw new ApplyError("INCOMPLETE_COVERAGE");
      }
      if (!dependencyGraphUnchanged(before, after, plan)) {
        throw new ApplyError(
          "VALIDATION_FAILED",
          "The validation scan detected an unexpected dependency graph change.",
        );
      }
      if (!hasResolvedTargetVersion(after, plan)) {
        throw new ApplyError("TARGET_REMAINS", "The target version was not resolved by the validation scan.");
      }
      if (comparison.remaining !== 0) {
        throw new ApplyError(
          "TARGET_REMAINS",
          "The targeted vulnerability remains after the validation scan.",
        );
      }
      const verification: RemediationVerification = Object.freeze({
        results: Object.freeze([...after]),
        comparison,
        explanation: resultMessage(comparison),
      });
      transaction.commit();
      return this.finish(plan, {
        planId: plan.id,
        transactionId: transaction.id,
        status: "success",
        changedFiles: transaction.changedFiles,
        verification,
        message: verification.explanation,
      });
    } catch (error: unknown) {
      const applyError = publicApplyError(error);
      let rollback =
        transaction === undefined
          ? undefined
          : await this.rollback.rollback(transaction);
      if (
        applyError.code === "ROLLBACK_FAILED" &&
        transaction !== undefined &&
        rollback?.attempted === false
      ) {
        // A contract-violating adapter may have committed but then become
        // unreadable before ownership could be recovered. Never describe an
        // empty ledger as a verified rollback in that indeterminate state.
        rollback = Object.freeze({
          attempted: true,
          restoredFiles: 0,
          verified: false,
          criticalWarning: applyError.message,
        });
      }
      const refusedCodes = new Set([
        "APPROVAL_REQUIRED",
        "CAPABILITY_NOT_SAFE",
        "WORKSPACE_UNTRUSTED",
        "WORKSPACE_BOUNDARY",
        "UNSAFE_URI",
        "UNSAFE_FILE_TYPE",
        "READ_ONLY_FILE",
        "ATOMIC_REPLACE_UNAVAILABLE",
        "UNSAVED_CHANGES",
        "GIT_STATE_CHANGED",
        "FILES_CHANGED",
        "STALE_RECOMMENDATION",
        "REGISTRY_PROVENANCE_CHANGED",
        "SCAN_IN_PROGRESS",
        "RESOURCE_LIMIT",
        "INVALID_METADATA",
      ]);
      const status =
        applyError.code === "CANCELLED"
          ? "cancelled"
          : transaction === undefined && refusedCodes.has(applyError.code)
            ? "refused"
            : "failed";
      return this.finish(plan, {
        planId: plan.id,
        ...(transaction === undefined ? {} : { transactionId: transaction.id }),
        status,
        changedFiles: transaction?.changedFiles ?? 0,
        ...(rollback === undefined ? {} : { rollback }),
        errorCode:
          rollback?.verified === false ? "ROLLBACK_FAILED" : applyError.code,
        message:
          rollback?.verified === false && rollback.criticalWarning !== undefined
            ? rollback.criticalWarning
            : applyError.message,
      });
    } finally {
      RemediationExecutor.active = false;
    }
  }

  private finish(plan: RemediationPlan, result: ApplyResult): ApplyResult {
    const frozen = Object.freeze(result);
    try {
      this.history.record(plan, frozen);
    } catch {
      // Session history is observability only and cannot change apply safety.
    }
    return frozen;
  }

  private validateEntry(
    plan: RemediationPlan,
    options: RemediationExecuteOptions,
  ): void {
    if (!options.approved) {
      throw new ApplyError("APPROVAL_REQUIRED");
    }
    if (plan.capability !== "safe") {
      throw new ApplyError("CAPABILITY_NOT_SAFE");
    }
    if (plan.files.some((change) => change.uri.scheme !== "file")) {
      throw new ApplyError("UNSAFE_URI");
    }
    if (
      plan.files.length === 0 ||
      plan.files.length > MAX_FILES_PER_REMEDIATION ||
      hasDuplicateUris(plan.files) ||
      plan.files.some(
        (change) =>
          change.operation !== "modify" ||
          change.afterContent === undefined ||
          change.afterHash === undefined,
      )
    ) {
      throw new ApplyError("RESOURCE_LIMIT");
    }
    throwIfCancelled(options.signal);
  }

  private async validateGuards(
    plan: RemediationPlan,
    signal: AbortSignal | undefined,
  ): Promise<void> {
    throwIfCancelled(signal);
    if (!(await this.dependencies.guard.isWorkspaceTrusted())) {
      throw new ApplyError("WORKSPACE_UNTRUSTED");
    }
    if (this.dependencies.guard.isScanInProgress()) {
      throw new ApplyError("SCAN_IN_PROGRESS");
    }
    if (
      !(await this.dependencies.recommendationVerifier.verifyRecommendation(
        plan,
        signal,
      ))
    ) {
      throw new ApplyError("STALE_RECOMMENDATION");
    }
    if (plan.registryProvenanceFingerprint !== undefined) {
      const verify =
        this.dependencies.recommendationVerifier.verifyRegistryProvenance;
      if (verify === undefined || !(await verify(plan, signal))) {
        throw new ApplyError("REGISTRY_PROVENANCE_CHANGED");
      }
    }
    for (const change of plan.files) {
      if (!(await this.dependencies.guard.isTargetInsideWorkspace(change.uri))) {
        throw new ApplyError("WORKSPACE_BOUNDARY");
      }
      if (await this.dependencies.guard.hasUnsavedChanges(change.uri)) {
        throw new ApplyError("UNSAVED_CHANGES");
      }
      if (
        (await this.dependencies.guard.hasUnexpectedGitChanges?.(change.uri)) ===
        true
      ) {
        throw new ApplyError("GIT_STATE_CHANGED");
      }
      if (
        (await this.dependencies.fileSystem.canGuaranteeAtomicReplace(
          change.uri,
        )) !== true
      ) {
        throw new ApplyError("ATOMIC_REPLACE_UNAVAILABLE");
      }
    }
    throwIfCancelled(signal);
  }

  private async prepareTargets(
    plan: RemediationPlan,
    signal: AbortSignal | undefined,
  ): Promise<readonly PreparedTarget[]> {
    const targets: PreparedTarget[] = [];
    let totalBytes = 0;
    for (const change of plan.files) {
      throwIfCancelled(signal);
      const inspectionBeforeRead = await this.dependencies.fileSystem.inspect(
        change.uri,
      );
      if (!safeRegularFile(inspectionBeforeRead)) {
        throw new ApplyError("UNSAFE_FILE_TYPE");
      }
      if (!inspectionBeforeRead.writable) {
        throw new ApplyError("READ_ONLY_FILE");
      }
      if (inspectionBeforeRead.size > MAX_REMEDIATION_FILE_BYTES) {
        throw new ApplyError("RESOURCE_LIMIT");
      }
      const bytes = await this.dependencies.fileSystem.readFile(change.uri);
      const inspectionAfterRead = await this.dependencies.fileSystem.inspect(
        change.uri,
      );
      if (
        !safeRegularFile(inspectionAfterRead) ||
        !sameInspectionIdentity(inspectionBeforeRead, inspectionAfterRead) ||
        bytes.byteLength !== inspectionAfterRead.size
      ) {
        throw new ApplyError("FILES_CHANGED");
      }
      const hash = sha256(bytes);
      if (hash !== change.beforeHash) {
        throw new ApplyError("FILES_CHANGED");
      }
      const afterContent = change.afterContent;
      const expectedAfterHash = change.afterHash;
      if (afterContent === undefined || expectedAfterHash === undefined) {
        throw new ApplyError("INVALID_METADATA");
      }
      const afterBytes = UTF8_ENCODER.encode(afterContent);
      if (
        afterBytes.byteLength > MAX_REMEDIATION_FILE_BYTES ||
        sha256(afterBytes) !== expectedAfterHash
      ) {
        throw new ApplyError("INVALID_METADATA");
      }
      totalBytes += bytes.byteLength + afterBytes.byteLength;
      if (totalBytes > MAX_REMEDIATION_TOTAL_BYTES) {
        throw new ApplyError("RESOURCE_LIMIT");
      }
      targets.push({
        change,
        snapshot: Object.freeze({
          uri: change.uri,
          bytes: new Uint8Array(bytes),
          hash,
          inspection: inspectionAfterRead,
        }),
        afterBytes,
        afterHash: expectedAfterHash,
      });
    }
    return Object.freeze(targets);
  }

  private async revalidateTarget(target: PreparedTarget): Promise<void> {
    const inspection = await this.dependencies.fileSystem.inspect(
      target.change.uri,
    );
    if (
      !safeRegularFile(inspection) ||
      !inspection.writable ||
      !sameInspectionIdentity(target.snapshot.inspection, inspection)
    ) {
      throw new ApplyError("FILES_CHANGED");
    }
    const bytes = await this.dependencies.fileSystem.readFile(target.change.uri);
    const afterRead = await this.dependencies.fileSystem.inspect(target.change.uri);
    if (
      !sameInspectionIdentity(inspection, afterRead) ||
      sha256(bytes) !== target.snapshot.hash
    ) {
      throw new ApplyError("FILES_CHANGED");
    }
  }

  private async rehashOwnedOutputs(
    transaction: RemediationTransaction,
  ): Promise<void> {
    for (const write of transaction.ownedWritesInReverse()) {
      const inspection = await this.dependencies.fileSystem.inspect(write.uri);
      if (
        !safeRegularFile(inspection) ||
        !sameInspectionIdentity(write.writtenInspection, inspection)
      ) {
        throw new ApplyError("FILES_CHANGED");
      }
      const bytes = await this.dependencies.fileSystem.readFile(write.uri);
      const afterRead = await this.dependencies.fileSystem.inspect(write.uri);
      if (
        !sameInspectionIdentity(inspection, afterRead) ||
        sha256(bytes) !== write.writtenHash
      ) {
        throw new ApplyError("FILES_CHANGED");
      }
    }
  }

  private async recoverUnreportedOwnedWrite(
    transaction: RemediationTransaction,
    target: PreparedTarget,
  ): Promise<boolean> {
    try {
      const inspection = await this.dependencies.fileSystem.inspect(
        target.change.uri,
      );
      const bytes = await this.dependencies.fileSystem.readFile(target.change.uri);
      const afterRead = await this.dependencies.fileSystem.inspect(
        target.change.uri,
      );
      if (
        safeRegularFile(inspection) &&
        sameInspectionIdentity(inspection, afterRead) &&
        sha256(bytes) === target.afterHash
      ) {
        transaction.recordOwnedWrite(
          target.change.uri,
          target.afterHash,
          afterRead,
        );
        return true;
      }
      if (
        safeRegularFile(inspection) &&
        sameInspectionIdentity(inspection, afterRead) &&
        sha256(bytes) === target.snapshot.hash
      ) {
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }
}
