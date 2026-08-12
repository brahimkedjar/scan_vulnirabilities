import {
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { resolve } from "node:path";
import { valid } from "semver";

import { dependencyManifestPath } from "../../models/Dependency";
import type { RemediationRecommendation } from "../RemediationModels";
import { ApplyError } from "./ApplyError";
import type { FileChangeOperation } from "./FileChange";
import type { RemediationPlan } from "./RemediationPlan";

const SHA256 = /^[a-f0-9]{64}$/u;
const OPAQUE_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const UNSAFE_TEXT =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u;
const MAXIMUM_TEXT_LENGTH = 32_768;
const MAXIMUM_IDS = 128;
const MAXIMUM_EVIDENCE = 128;
const MAXIMUM_VALIDATION_STEPS = 16;
const MAXIMUM_APPROVALS = 32;
const MAXIMUM_CANONICAL_BYTES = 256 * 1024;
export const MAXIMUM_APPROVAL_AGE_MS = 5 * 60 * 1_000;

export interface RemediationApprovalFileBinding {
  readonly uri: string;
  readonly operation: FileChangeOperation;
  readonly beforeHash: string;
  readonly afterHash: string;
}

export interface RemediationApprovalBinding {
  readonly schemaVersion: 1;
  readonly remediationId: string;
  readonly previewId: string;
  readonly workspacePath: string;
  readonly projectPath: string;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly manifestName: string;
  readonly packageManager: string;
  readonly currentVersion: string;
  readonly targetVersion: string;
  readonly manifestPath: string;
  readonly lockfilePath: string;
  readonly vulnerabilityIds: readonly string[];
  readonly recommendationHash: string;
  readonly planHash: string;
  readonly files: readonly RemediationApprovalFileBinding[];
}

export interface RemediationApprovalRecord {
  readonly id: string;
  readonly approvalHash: string;
  readonly binding: RemediationApprovalBinding;
  readonly generation: number;
  readonly approvedAt: string;
  readonly expiresAt: string;
}

export type RemediationApprovalFailure =
  | "invalid-token"
  | "not-found"
  | "expired"
  | "mismatch";

export type RemediationApprovalValidation =
  | {
      readonly valid: true;
      readonly record: RemediationApprovalRecord;
    }
  | {
      readonly valid: false;
      readonly reason: RemediationApprovalFailure;
    };

export interface RemediationApprovalRegistryOptions {
  readonly clock?: () => number;
  readonly maximumAgeMs?: number;
}

function boundedText(value: string | undefined, label: string): string {
  if (
    value === undefined ||
    value.length === 0 ||
    value.length > MAXIMUM_TEXT_LENGTH ||
    UNSAFE_TEXT.test(value)
  ) {
    throw new ApplyError("INVALID_METADATA", `${label} is invalid`);
  }
  return value;
}

function optionalBoundedText(value: string | undefined, label: string): string {
  if (value === undefined || value.length === 0) return "";
  return boundedText(value, label);
}

function requireHash(value: string | undefined, label: string): string {
  if (value === undefined || !SHA256.test(value)) {
    throw new ApplyError("INVALID_METADATA", `${label} is invalid`);
  }
  return value;
}

function sortedUnique(
  values: readonly string[],
  label: string,
  allowEmpty = false,
): readonly string[] {
  if ((!allowEmpty && values.length === 0) || values.length > MAXIMUM_IDS) {
    throw new ApplyError("INVALID_METADATA", `${label} is invalid`);
  }
  const normalized = values.map((value) => boundedText(value, label)).sort();
  if (new Set(normalized).size !== normalized.length) {
    throw new ApplyError("INVALID_METADATA", `${label} contains duplicates`);
  }
  return Object.freeze(normalized);
}

function canonicalHash(value: unknown): string {
  const canonical = JSON.stringify(value);
  if (Buffer.byteLength(canonical, "utf8") > MAXIMUM_CANONICAL_BYTES) {
    throw new ApplyError("RESOURCE_LIMIT");
  }
  return createHash("sha256").update(canonical).digest("hex");
}

function normalizedPath(value: string): string {
  const absolute = resolve(value);
  return process.platform === "win32" ? absolute.toLowerCase() : absolute;
}

function sameStringSet(
  left: readonly string[],
  right: readonly string[],
): boolean {
  const sortedRight = [...right].sort();
  return (
    left.length === right.length &&
    [...left].sort().every((value, index) => value === sortedRight[index])
  );
}

function boundedLength(
  values: readonly unknown[],
  maximum: number,
  label: string,
): void {
  if (values.length > maximum) {
    throw new ApplyError("RESOURCE_LIMIT", `${label} exceeds the safety limit`);
  }
}

function fileBindings(plan: RemediationPlan): readonly RemediationApprovalFileBinding[] {
  if (plan.files.length > 8) {
    throw new ApplyError("RESOURCE_LIMIT");
  }
  const seen = new Set<string>();
  const bindings = plan.files.map((file) => {
    const uri = boundedText(file.uri.toString(), "target URI");
    if (
      file.uri.scheme !== "file" ||
      seen.has(uri) ||
      file.operation !== "modify"
    ) {
      throw new ApplyError("INVALID_METADATA");
    }
    seen.add(uri);
    return Object.freeze({
      uri,
      operation: file.operation,
      beforeHash: requireHash(file.beforeHash, "before hash"),
      afterHash:
        file.afterHash === undefined
          ? ""
          : requireHash(file.afterHash, "after hash"),
    });
  });
  return Object.freeze(bindings);
}

function recommendationIdentity(
  recommendation: RemediationRecommendation,
): Readonly<Record<string, unknown>> {
  const dependency = recommendation.dependency;
  boundedLength(dependency.dependencyPath ?? [], MAXIMUM_IDS, "dependency path");
  boundedLength(recommendation.evidence, MAXIMUM_EVIDENCE, "evidence");
  return Object.freeze({
    recommendationKey: boundedText(
      recommendation.recommendationKey,
      "recommendation key",
    ),
    vulnerabilityIds: sortedUnique(
      recommendation.vulnerabilityIds,
      "vulnerability ID",
    ),
    dependency: Object.freeze({
      workspacePath: optionalBoundedText(dependency.workspacePath, "workspace path"),
      projectPath: optionalBoundedText(dependency.projectPath, "project path"),
      manifestPath: optionalBoundedText(
        dependencyManifestPath(dependency),
        "manifest path",
      ),
      lockfilePath: optionalBoundedText(dependency.lockfilePath, "lockfile path"),
      packageManager: optionalBoundedText(
        dependency.packageManager,
        "package manager",
      ),
      ecosystem: boundedText(dependency.ecosystem, "ecosystem"),
      name: boundedText(dependency.name, "package name"),
      manifestName: boundedText(
        dependency.manifestName ?? dependency.name,
        "manifest name",
      ),
      requestedVersion: optionalBoundedText(
        dependency.requestedVersion,
        "requested version",
      ),
      installedVersion: optionalBoundedText(
        dependency.installedVersion,
        "installed version",
      ),
      resolutionStatus: dependency.resolutionStatus ?? "resolved",
      dependencyType: dependency.dependencyType,
      environment: dependency.environment,
      declaredEnvironment: dependency.declaredEnvironment ?? "",
      dependencyPath: Object.freeze(
        (dependency.dependencyPath ?? []).map((segment) =>
          boundedText(segment, "dependency path"),
        ),
      ),
    }),
    currentVersion: optionalBoundedText(
      recommendation.currentVersion,
      "current version",
    ),
    targetVersion: optionalBoundedText(
      recommendation.recommendedVersion,
      "target version",
    ),
    fixedVersions: sortedUnique(
      recommendation.fixedVersions,
      "fixed version",
      true,
    ),
    strategy: recommendation.strategy,
    confidence: recommendation.confidence,
    directDependency: recommendation.directDependency,
    breakingChangeRisk: recommendation.breakingChangeRisk,
    reason: boundedText(recommendation.reason, "recommendation reason"),
    evidence: Object.freeze(
      recommendation.evidence.map((entry) =>
        Object.freeze({
          source: entry.source,
          description: boundedText(entry.description, "evidence"),
        }),
      ),
    ),
  });
}

export function remediationRecommendationHash(
  recommendation: RemediationRecommendation,
): string {
  return canonicalHash(recommendationIdentity(recommendation));
}

export function remediationPlanHash(plan: RemediationPlan): string {
  boundedLength(plan.warnings, MAXIMUM_IDS, "warnings");
  boundedLength(
    plan.validationSteps,
    MAXIMUM_VALIDATION_STEPS,
    "validation steps",
  );
  const recommendationHash = remediationRecommendationHash(plan.recommendation);
  const files = fileBindings(plan);
  return canonicalHash({
    schemaVersion: 1,
    planId: boundedText(plan.id, "plan ID"),
    recommendationHash,
    recommendationKey: boundedText(
      plan.recommendationKey,
      "recommendation key",
    ),
    capability: plan.capability,
    reasonCode: plan.reasonCode,
    scanGeneration:
      plan.scanGeneration === undefined
        ? ""
        : boundedText(plan.scanGeneration, "scan generation"),
    registryProvenanceFingerprint:
      plan.registryProvenanceFingerprint === undefined
        ? ""
        : requireHash(
            plan.registryProvenanceFingerprint,
            "registry provenance fingerprint",
          ),
    files,
    warnings: Object.freeze(
      plan.warnings.map((warning) => boundedText(warning, "warning")),
    ),
    validationSteps: Object.freeze(
      plan.validationSteps.map((step) =>
        Object.freeze({
          kind: step.kind,
          description: boundedText(step.description, "validation step"),
          required: step.required,
        }),
      ),
    ),
    expectedOutcome: Object.freeze({
      packageName: boundedText(
        plan.expectedOutcome.packageName,
        "expected package name",
      ),
      fromVersion: boundedText(
        plan.expectedOutcome.fromVersion,
        "expected current version",
      ),
      toVersion: optionalBoundedText(
        plan.expectedOutcome.toVersion,
        "expected target version",
      ),
      targetedVulnerabilityIds: sortedUnique(
        plan.expectedOutcome.targetedVulnerabilityIds,
        "expected vulnerability ID",
      ),
      expectedAddressed: plan.expectedOutcome.expectedAddressed,
      requiresCompleteCoverage: plan.expectedOutcome.requiresCompleteCoverage,
    }),
  });
}

function validateSafeNpmPlan(plan: RemediationPlan): void {
  const recommendation = plan.recommendation;
  const dependency = recommendation.dependency;
  const manifestPath = boundedText(
    dependencyManifestPath(dependency),
    "manifest path",
  );
  const lockfilePath = boundedText(dependency.lockfilePath, "lockfile path");
  if (
    plan.capability !== "safe" ||
    plan.reasonCode !== "safe-npm-existing-resolution" ||
    recommendation.strategy !== "upgrade-direct" ||
    !recommendation.directDependency ||
    dependency.dependencyType !== "direct" ||
    dependency.ecosystem !== "npm" ||
    dependency.packageManager !== "npm" ||
    dependency.resolutionStatus === "unresolved" ||
    dependency.resolutionStatus === "unsupported" ||
    dependency.installedVersion !== recommendation.currentVersion ||
    (dependency.manifestName ?? dependency.name) !== dependency.name ||
    recommendation.recommendedVersion === undefined ||
    dependency.workspacePath === undefined ||
    dependency.projectPath === undefined ||
    dependency.requestedVersion === undefined ||
    dependency.lockfilePath === undefined ||
    dependency.packageManager === undefined ||
    plan.files.some((file) => file.afterHash === undefined) ||
    valid(recommendation.currentVersion) === null ||
    valid(recommendation.recommendedVersion) === null ||
    !/^(?:[~^])?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u.test(
      dependency.requestedVersion,
    ) ||
    plan.recommendationKey !== recommendation.recommendationKey ||
    !recommendation.fixedVersions.includes(recommendation.recommendedVersion) ||
    plan.expectedOutcome.fromVersion !== recommendation.currentVersion ||
    plan.expectedOutcome.toVersion !== recommendation.recommendedVersion ||
    plan.expectedOutcome.packageName !== dependency.name ||
    plan.expectedOutcome.expectedAddressed !== recommendation.vulnerabilityIds.length ||
    !plan.expectedOutcome.requiresCompleteCoverage ||
    plan.scanGeneration === undefined ||
    plan.registryProvenanceFingerprint === undefined ||
    !sameStringSet(
      plan.expectedOutcome.targetedVulnerabilityIds,
      recommendation.vulnerabilityIds,
    )
  ) {
    throw new ApplyError("CAPABILITY_NOT_SAFE");
  }
  const targets = new Set(
    plan.files.map((file) => normalizedPath(file.uri.fsPath)),
  );
  if (
    targets.size !== 2 ||
    !targets.has(normalizedPath(manifestPath)) ||
    !targets.has(normalizedPath(lockfilePath))
  ) {
    throw new ApplyError("WORKSPACE_BOUNDARY");
  }
}

export function createRemediationApprovalBinding(
  plan: RemediationPlan,
  previewId: string,
  remediationId: string,
): RemediationApprovalBinding {
  validateSafeNpmPlan(plan);
  const recommendation = plan.recommendation;
  const dependency = recommendation.dependency;
  const vulnerabilityIds = sortedUnique(
    recommendation.vulnerabilityIds,
    "vulnerability ID",
  );
  const binding = Object.freeze({
    schemaVersion: 1 as const,
    remediationId: boundedText(remediationId, "remediation ID"),
    previewId: boundedText(previewId, "preview ID"),
    workspacePath: boundedText(dependency.workspacePath, "workspace path"),
    projectPath: boundedText(dependency.projectPath, "project path"),
    ecosystem: boundedText(dependency.ecosystem, "ecosystem"),
    packageName: boundedText(dependency.name, "package name"),
    manifestName: boundedText(
      dependency.manifestName ?? dependency.name,
      "manifest name",
    ),
    packageManager: boundedText(
      dependency.packageManager,
      "package manager",
    ),
    currentVersion: boundedText(
      recommendation.currentVersion,
      "current version",
    ),
    targetVersion: boundedText(
      recommendation.recommendedVersion,
      "target version",
    ),
    manifestPath: boundedText(
      dependencyManifestPath(dependency),
      "manifest path",
    ),
    lockfilePath: boundedText(dependency.lockfilePath, "lockfile path"),
    vulnerabilityIds,
    recommendationHash: remediationRecommendationHash(recommendation),
    planHash: remediationPlanHash(plan),
    files: fileBindings(plan),
  });
  canonicalHash(binding);
  return binding;
}

export function remediationApprovalHash(
  binding: RemediationApprovalBinding,
): string {
  return canonicalHash(binding);
}

function hashesEqual(left: string, right: string): boolean {
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function validClockValue(value: number): number {
  if (!Number.isFinite(value)) {
    throw new ApplyError("UNEXPECTED", "remediation approval clock is invalid");
  }
  return value;
}

/** Session-only, opaque, one-use authority bound to one exact plan preview. */
export class RemediationApprovalRegistry {
  private readonly records = new Map<string, RemediationApprovalRecord>();
  private readonly approvalByPreview = new Map<string, string>();
  private readonly clock: () => number;
  private readonly maximumAgeMs: number;
  private generation = 0;

  public constructor(options: RemediationApprovalRegistryOptions = {}) {
    this.clock = options.clock ?? Date.now;
    const age = options.maximumAgeMs ?? MAXIMUM_APPROVAL_AGE_MS;
    if (
      !Number.isSafeInteger(age) ||
      age < 1_000 ||
      age > MAXIMUM_APPROVAL_AGE_MS
    ) {
      throw new RangeError("maximumAgeMs must be between 1000 and 300000");
    }
    this.maximumAgeMs = age;
  }

  public issue(
    plan: RemediationPlan,
    previewId: string,
    remediationId: string,
  ): RemediationApprovalRecord {
    if (!OPAQUE_TOKEN.test(previewId)) {
      throw new ApplyError("PREVIEW_REQUIRED");
    }
    this.pruneExpired();
    const existingId = this.approvalByPreview.get(previewId);
    if (existingId !== undefined) {
      this.delete(existingId);
    }
    while (this.records.size >= MAXIMUM_APPROVALS) {
      const oldest = this.records.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.delete(oldest);
    }
    const binding = createRemediationApprovalBinding(
      plan,
      previewId,
      remediationId,
    );
    const approvedAt = validClockValue(this.clock());
    const id = randomBytes(32).toString("base64url");
    const record = Object.freeze({
      id,
      approvalHash: remediationApprovalHash(binding),
      binding,
      generation: this.generation,
      approvedAt: new Date(approvedAt).toISOString(),
      expiresAt: new Date(approvedAt + this.maximumAgeMs).toISOString(),
    });
    this.records.set(id, record);
    this.approvalByPreview.set(previewId, id);
    return record;
  }

  public validate(
    previewId: string,
    remediationId: string,
    plan: RemediationPlan,
  ): RemediationApprovalValidation {
    if (!OPAQUE_TOKEN.test(previewId)) {
      return Object.freeze({ valid: false, reason: "invalid-token" });
    }
    const approvalId = this.approvalByPreview.get(previewId);
    if (approvalId === undefined) {
      return Object.freeze({ valid: false, reason: "not-found" });
    }
    const record = this.records.get(approvalId);
    if (record === undefined || record.generation !== this.generation) {
      this.delete(approvalId);
      return Object.freeze({ valid: false, reason: "not-found" });
    }
    if (Date.parse(record.expiresAt) <= validClockValue(this.clock())) {
      this.delete(approvalId);
      return Object.freeze({ valid: false, reason: "expired" });
    }
    let current: RemediationApprovalBinding;
    try {
      current = createRemediationApprovalBinding(
        plan,
        previewId,
        remediationId,
      );
    } catch {
      this.delete(approvalId);
      return Object.freeze({ valid: false, reason: "mismatch" });
    }
    if (
      !hashesEqual(record.approvalHash, remediationApprovalHash(current)) ||
      !hashesEqual(record.binding.planHash, current.planHash) ||
      !hashesEqual(
        record.binding.recommendationHash,
        current.recommendationHash,
      )
    ) {
      this.delete(approvalId);
      return Object.freeze({ valid: false, reason: "mismatch" });
    }
    return Object.freeze({ valid: true, record });
  }

  public consume(
    previewId: string,
    remediationId: string,
    plan: RemediationPlan,
  ): RemediationApprovalValidation {
    const validation = this.validate(previewId, remediationId, plan);
    if (validation.valid) {
      this.delete(validation.record.id);
    }
    return validation;
  }

  public invalidateAll(): void {
    this.generation += 1;
    this.records.clear();
    this.approvalByPreview.clear();
  }

  public dispose(): void {
    this.invalidateAll();
  }

  private pruneExpired(): void {
    const now = validClockValue(this.clock());
    for (const [id, record] of this.records) {
      if (
        record.generation !== this.generation ||
        Date.parse(record.expiresAt) <= now
      ) {
        this.delete(id);
      }
    }
  }

  private delete(id: string): void {
    const record = this.records.get(id);
    if (record !== undefined) {
      this.approvalByPreview.delete(record.binding.previewId);
    }
    this.records.delete(id);
  }
}
