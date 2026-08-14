import { compare as compareSemver, valid as validSemver } from "semver";

import {
  deepFreezeJson,
  sha256CanonicalJson,
  type JsonValue,
} from "../security/BoundedJson";
import {
  verifySecurityBaseline,
  type SecurityBaseline,
} from "./SecurityBaseline";
import {
  type SecuritySnapshot,
  type SnapshotAnalysisSummary,
  type SnapshotComponent,
  type SnapshotCoverageStatus,
  type SnapshotVulnerability,
  verifySecuritySnapshot,
} from "./SecuritySnapshot";

export const SECURITY_DIFF_SCHEMA = "dependency-auditor/security-diff" as const;
export const SECURITY_DIFF_SCHEMA_VERSION = 1 as const;

export type VersionChangeDirection =
  | "upgrade"
  | "downgrade"
  | "mixed"
  | "unknown";

export interface SnapshotVersionChange {
  readonly key: string;
  readonly ecosystem: string;
  readonly name: string;
  readonly beforeVersions: readonly (string | null)[];
  readonly afterVersions: readonly (string | null)[];
  readonly direction: VersionChangeDirection;
}

export interface SnapshotComponentEvidenceChange {
  readonly componentKey: string;
  readonly beforeEvidenceHash: string;
  readonly afterEvidenceHash: string;
}

export interface SnapshotVulnerabilityChange {
  readonly identityKey: string;
  readonly before: readonly SnapshotVulnerability[];
  readonly after: readonly SnapshotVulnerability[];
}

export type SnapshotAnalysisChangeStatus =
  | "UNCHANGED"
  | "CHANGED"
  | "UNKNOWN";

export interface SnapshotAnalysisChange {
  readonly status: SnapshotAnalysisChangeStatus;
  readonly beforeState: SecuritySnapshot["analysis"][
    | "licenses"
    | "provenance"
    | "reachability"];
  readonly afterState: SecuritySnapshot["analysis"][
    | "licenses"
    | "provenance"
    | "reachability"];
  readonly beforeEvidenceHash?: string;
  readonly afterEvidenceHash?: string;
}

export type SecurityDiffUnknownReason =
  | "WORKSPACE_IDENTITY_CHANGED"
  | "BASELINE_INVENTORY_INCOMPLETE"
  | "CURRENT_INVENTORY_INCOMPLETE"
  | "BASELINE_VULNERABILITY_COVERAGE_INCOMPLETE"
  | "CURRENT_VULNERABILITY_COVERAGE_INCOMPLETE";

export interface SecuritySnapshotDiff {
  readonly schema: typeof SECURITY_DIFF_SCHEMA;
  readonly schemaVersion: typeof SECURITY_DIFF_SCHEMA_VERSION;
  readonly beforeDigest: string;
  readonly afterDigest: string;
  readonly complete: boolean;
  readonly coverage: Readonly<{
    before: SnapshotCoverageStatus;
    after: SnapshotCoverageStatus;
  }>;
  readonly dependencies: Readonly<{
    readonly added: readonly SnapshotComponent[];
    readonly unknownAdditions: readonly SnapshotComponent[];
    readonly removed: readonly SnapshotComponent[];
    readonly versionChanges: readonly SnapshotVersionChange[];
    readonly unknownRemovals: readonly SnapshotComponent[];
    readonly unknownVersionChanges: readonly SnapshotVersionChange[];
    readonly evidenceChanges: readonly SnapshotComponentEvidenceChange[];
  }>;
  readonly vulnerabilities: Readonly<{
    readonly added: readonly SnapshotVulnerability[];
    readonly unknownPreviouslyUnobserved: readonly SnapshotVulnerability[];
    readonly resolved: readonly SnapshotVulnerability[];
    readonly changed: readonly SnapshotVulnerabilityChange[];
    readonly newKnownExploited: readonly SnapshotVulnerability[];
    readonly unknownNewKnownExploited: readonly SnapshotVulnerability[];
    readonly unknownNoLongerObserved: readonly SnapshotVulnerability[];
  }>;
  readonly analysis: Readonly<{
    readonly licenses: SnapshotAnalysisChange;
    readonly provenance: SnapshotAnalysisChange;
    readonly reachability: SnapshotAnalysisChange;
  }>;
  readonly unknownReasons: readonly SecurityDiffUnknownReason[];
}

export interface SecuritySnapshotDiffOptions {
  readonly signal?: AbortSignal;
  readonly maximumChanges?: number;
}

export class SecurityHistoryError extends Error {
  public constructor(
    public readonly code:
      | "CANCELLED"
      | "INVALID_INPUT"
      | "LIMIT_EXCEEDED"
      | "INTEGRITY_MISMATCH",
    message: string,
  ) {
    super(message);
    this.name = "SecurityHistoryError";
  }
}

const MAXIMUM_CHANGES = 500_000;

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function json(value: unknown): JsonValue {
  return value as JsonValue;
}

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new SecurityHistoryError(
      "CANCELLED",
      "Security snapshot comparison was cancelled",
    );
  }
}

function maximumChanges(value: number | undefined): number {
  const selected = value ?? MAXIMUM_CHANGES;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > MAXIMUM_CHANGES
  ) {
    throw new SecurityHistoryError(
      "LIMIT_EXCEEDED",
      "maximumChanges is outside the supported safety range",
    );
  }
  return selected;
}

function packageKey(component: SnapshotComponent): string {
  return JSON.stringify([component.ecosystem, component.name]);
}

function compareComponent(
  left: SnapshotComponent,
  right: SnapshotComponent,
): number {
  return compareText(left.key, right.key);
}

function compareVulnerability(
  left: SnapshotVulnerability,
  right: SnapshotVulnerability,
): number {
  return compareText(left.key, right.key);
}

function versions(components: readonly SnapshotComponent[]): readonly (string | null)[] {
  return Object.freeze(
    [...new Set(components.map((component) => component.version))].sort(
      (left, right) => {
        if (left === right) {
          return 0;
        }
        if (left === null) {
          return -1;
        }
        if (right === null) {
          return 1;
        }
        return compareText(left, right);
      },
    ),
  );
}

function versionDirection(
  before: readonly (string | null)[],
  after: readonly (string | null)[],
): VersionChangeDirection {
  const beforeVersion = before[0];
  const afterVersion = after[0];
  if (
    before.length === 0 ||
    after.length === 0 ||
    beforeVersion === undefined ||
    afterVersion === undefined ||
    before.some(
      (version) =>
        version === null || validSemver(version, { loose: false }) === null,
    ) ||
    after.some(
      (version) =>
        version === null || validSemver(version, { loose: false }) === null,
    )
  ) {
    return "unknown";
  }
  const comparisons = before.flatMap((oldVersion) =>
    after.map((newVersion) =>
      compareSemver(oldVersion as string, newVersion as string, {
        loose: false,
      }),
    ),
  );
  if (comparisons.every((comparison) => comparison < 0)) {
    return "upgrade";
  }
  if (comparisons.every((comparison) => comparison > 0)) {
    return "downgrade";
  }
  return "mixed";
}

function groupComponents(
  components: readonly SnapshotComponent[],
): ReadonlyMap<string, readonly SnapshotComponent[]> {
  const mutable = new Map<string, SnapshotComponent[]>();
  for (const component of components) {
    const key = packageKey(component);
    const values = mutable.get(key) ?? [];
    values.push(component);
    mutable.set(key, values);
  }
  const result = new Map<string, readonly SnapshotComponent[]>();
  for (const [key, values] of mutable) {
    values.sort(compareComponent);
    result.set(key, Object.freeze(values));
  }
  return result;
}

function groupVulnerabilities(
  vulnerabilities: readonly SnapshotVulnerability[],
): ReadonlyMap<string, readonly SnapshotVulnerability[]> {
  const mutable = new Map<string, SnapshotVulnerability[]>();
  for (const vulnerability of vulnerabilities) {
    const values = mutable.get(vulnerability.identityKey) ?? [];
    values.push(vulnerability);
    mutable.set(vulnerability.identityKey, values);
  }
  const result = new Map<string, readonly SnapshotVulnerability[]>();
  for (const [key, values] of mutable) {
    values.sort(compareVulnerability);
    result.set(key, Object.freeze(values));
  }
  return result;
}

function sameKeys(
  left: readonly { readonly key: string }[],
  right: readonly { readonly key: string }[],
): boolean {
  return (
    left.length === right.length &&
    left.every((entry, index) => entry.key === right[index]?.key)
  );
}

function sameComponentEvidence(
  left: readonly SnapshotComponent[],
  right: readonly SnapshotComponent[],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (entry, index) =>
        entry.key === right[index]?.key &&
        entry.evidenceHash === right[index]?.evidenceHash,
    )
  );
}

function createVersionChange(
  key: string,
  before: readonly SnapshotComponent[],
  after: readonly SnapshotComponent[],
): SnapshotVersionChange {
  const identity = after[0] ?? before[0];
  if (identity === undefined) {
    throw new SecurityHistoryError(
      "INVALID_INPUT",
      "Version-change identity is missing",
    );
  }
  const beforeVersions = versions(before);
  const afterVersions = versions(after);
  return Object.freeze({
    key: sha256CanonicalJson(json([key, beforeVersions, afterVersions])),
    ecosystem: identity.ecosystem,
    name: identity.name,
    beforeVersions,
    afterVersions,
    direction: versionDirection(beforeVersions, afterVersions),
  });
}

function analysisChange(
  beforeState: SecuritySnapshot["analysis"][
    | "licenses"
    | "provenance"
    | "reachability"],
  afterState: SecuritySnapshot["analysis"][
    | "licenses"
    | "provenance"
    | "reachability"],
  beforeSummary: SnapshotAnalysisSummary | undefined,
  afterSummary: SnapshotAnalysisSummary | undefined,
): SnapshotAnalysisChange {
  const comparable =
    beforeState === "complete" &&
    afterState === "complete" &&
    beforeSummary !== undefined &&
    afterSummary !== undefined;
  return Object.freeze({
    status: comparable
      ? beforeSummary.evidenceHash === afterSummary.evidenceHash
        ? "UNCHANGED"
        : "CHANGED"
      : "UNKNOWN",
    beforeState,
    afterState,
    ...(beforeSummary === undefined
      ? {}
      : { beforeEvidenceHash: beforeSummary.evidenceHash }),
    ...(afterSummary === undefined
      ? {}
      : { afterEvidenceHash: afterSummary.evidenceHash }),
  });
}

export function diffSecuritySnapshots(
  before: SecuritySnapshot,
  after: SecuritySnapshot,
  options: SecuritySnapshotDiffOptions = {},
): SecuritySnapshotDiff {
  throwIfCancelled(options.signal);
  if (!verifySecuritySnapshot(before) || !verifySecuritySnapshot(after)) {
    throw new SecurityHistoryError(
      "INTEGRITY_MISMATCH",
      "Security snapshot integrity verification failed",
    );
  }
  const limit = maximumChanges(options.maximumChanges);
  const sameWorkspace =
    before.workspace.identityHash === after.workspace.identityHash;
  const beforeInventoryComplete =
    before.coverage.dependencyInventory === "complete";
  const afterInventoryComplete =
    sameWorkspace && after.coverage.dependencyInventory === "complete";
  const beforeVulnerabilitiesComplete =
    before.coverage.vulnerabilityAnalysis === "complete";
  const afterVulnerabilitiesComplete =
    sameWorkspace && after.coverage.vulnerabilityAnalysis === "complete";

  const unknownReasons = new Set<SecurityDiffUnknownReason>();
  if (!sameWorkspace) {
    unknownReasons.add("WORKSPACE_IDENTITY_CHANGED");
  }
  if (!beforeInventoryComplete) {
    unknownReasons.add("BASELINE_INVENTORY_INCOMPLETE");
  }
  if (!afterInventoryComplete) {
    unknownReasons.add("CURRENT_INVENTORY_INCOMPLETE");
  }
  if (!beforeVulnerabilitiesComplete) {
    unknownReasons.add("BASELINE_VULNERABILITY_COVERAGE_INCOMPLETE");
  }
  if (!afterVulnerabilitiesComplete) {
    unknownReasons.add("CURRENT_VULNERABILITY_COVERAGE_INCOMPLETE");
  }

  const beforeComponents = groupComponents(before.dependencies);
  const afterComponents = groupComponents(after.dependencies);
  const packageKeys = [...new Set([...beforeComponents.keys(), ...afterComponents.keys()])].sort();
  const added: SnapshotComponent[] = [];
  const unknownAdditions: SnapshotComponent[] = [];
  const removed: SnapshotComponent[] = [];
  const unknownRemovals: SnapshotComponent[] = [];
  const versionChanges: SnapshotVersionChange[] = [];
  const unknownVersionChanges: SnapshotVersionChange[] = [];
  const evidenceChanges: SnapshotComponentEvidenceChange[] = [];
  let changeCount = 0;
  for (let index = 0; index < packageKeys.length; index += 1) {
    if ((index & 255) === 0) {
      throwIfCancelled(options.signal);
    }
    const key = packageKeys[index];
    if (key === undefined) {
      continue;
    }
    const oldValues = beforeComponents.get(key) ?? [];
    const newValues = afterComponents.get(key) ?? [];
    if (oldValues.length === 0) {
      (sameWorkspace && beforeInventoryComplete
        ? added
        : unknownAdditions
      ).push(...newValues);
      changeCount += newValues.length;
    } else if (newValues.length === 0) {
      (afterInventoryComplete ? removed : unknownRemovals).push(...oldValues);
      changeCount += oldValues.length;
    } else if (!sameKeys(oldValues, newValues)) {
      const change = createVersionChange(key, oldValues, newValues);
      (beforeInventoryComplete && afterInventoryComplete
        ? versionChanges
        : unknownVersionChanges
      ).push(change);
      changeCount += 1;
    } else if (!sameComponentEvidence(oldValues, newValues)) {
      for (let valueIndex = 0; valueIndex < oldValues.length; valueIndex += 1) {
        const oldValue = oldValues[valueIndex];
        const newValue = newValues[valueIndex];
        if (
          oldValue !== undefined &&
          newValue !== undefined &&
          oldValue.evidenceHash !== newValue.evidenceHash
        ) {
          evidenceChanges.push(
            Object.freeze({
              componentKey: oldValue.key,
              beforeEvidenceHash: oldValue.evidenceHash,
              afterEvidenceHash: newValue.evidenceHash,
            }),
          );
          changeCount += 1;
        }
      }
    }
    if (changeCount > limit) {
      throw new SecurityHistoryError(
        "LIMIT_EXCEEDED",
        "Security dependency diff exceeds the configured change limit",
      );
    }
  }

  const beforeFindings = groupVulnerabilities(before.vulnerabilities);
  const afterFindings = groupVulnerabilities(after.vulnerabilities);
  const findingKeys = [...new Set([...beforeFindings.keys(), ...afterFindings.keys()])].sort();
  const addedVulnerabilities: SnapshotVulnerability[] = [];
  const unknownPreviouslyUnobserved: SnapshotVulnerability[] = [];
  const resolved: SnapshotVulnerability[] = [];
  const unknownNoLongerObserved: SnapshotVulnerability[] = [];
  const changed: SnapshotVulnerabilityChange[] = [];
  const newKnownExploited: SnapshotVulnerability[] = [];
  const unknownNewKnownExploited: SnapshotVulnerability[] = [];
  for (let index = 0; index < findingKeys.length; index += 1) {
    if ((index & 255) === 0) {
      throwIfCancelled(options.signal);
    }
    const key = findingKeys[index];
    if (key === undefined) {
      continue;
    }
    const oldValues = beforeFindings.get(key) ?? [];
    const newValues = afterFindings.get(key) ?? [];
    if (oldValues.length === 0) {
      (sameWorkspace && beforeVulnerabilitiesComplete
        ? addedVulnerabilities
        : unknownPreviouslyUnobserved
      ).push(...newValues);
    } else if (newValues.length === 0) {
      (afterVulnerabilitiesComplete ? resolved : unknownNoLongerObserved).push(
        ...oldValues,
      );
    } else if (!sameKeys(oldValues, newValues)) {
      changed.push(
        Object.freeze({
          identityKey: key,
          before: oldValues,
          after: newValues,
        }),
      );
    }
    const wasKnown = oldValues.some(
      (finding) => finding.knownExploitation === "known-exploited",
    );
    if (!wasKnown) {
      (sameWorkspace && beforeVulnerabilitiesComplete
        ? newKnownExploited
        : unknownNewKnownExploited
      ).push(
        ...newValues.filter(
          (finding) => finding.knownExploitation === "known-exploited",
        ),
      );
    }
    changeCount +=
      oldValues.length === 0
        ? newValues.length
        : newValues.length === 0
          ? oldValues.length
          : sameKeys(oldValues, newValues)
            ? 0
            : 1;
    if (changeCount > limit) {
      throw new SecurityHistoryError(
        "LIMIT_EXCEEDED",
        "Security vulnerability diff exceeds the configured change limit",
      );
    }
  }

  added.sort(compareComponent);
  unknownAdditions.sort(compareComponent);
  removed.sort(compareComponent);
  unknownRemovals.sort(compareComponent);
  versionChanges.sort((left, right) => compareText(left.key, right.key));
  unknownVersionChanges.sort((left, right) =>
    compareText(left.key, right.key),
  );
  evidenceChanges.sort((left, right) =>
    compareText(left.componentKey, right.componentKey),
  );
  addedVulnerabilities.sort(compareVulnerability);
  unknownPreviouslyUnobserved.sort(compareVulnerability);
  resolved.sort(compareVulnerability);
  unknownNoLongerObserved.sort(compareVulnerability);
  changed.sort((left, right) =>
    compareText(left.identityKey, right.identityKey),
  );
  newKnownExploited.sort(compareVulnerability);
  unknownNewKnownExploited.sort(compareVulnerability);
  const result: SecuritySnapshotDiff = {
    schema: SECURITY_DIFF_SCHEMA,
    schemaVersion: SECURITY_DIFF_SCHEMA_VERSION,
    beforeDigest: before.integrity.digest,
    afterDigest: after.integrity.digest,
    complete:
      sameWorkspace &&
      beforeInventoryComplete &&
      afterInventoryComplete &&
      beforeVulnerabilitiesComplete &&
      afterVulnerabilitiesComplete,
    coverage: Object.freeze({
      before: before.coverage.status,
      after: after.coverage.status,
    }),
    dependencies: Object.freeze({
      added: Object.freeze(added),
      unknownAdditions: Object.freeze(unknownAdditions),
      removed: Object.freeze(removed),
      versionChanges: Object.freeze(versionChanges),
      unknownRemovals: Object.freeze(unknownRemovals),
      unknownVersionChanges: Object.freeze(unknownVersionChanges),
      evidenceChanges: Object.freeze(evidenceChanges),
    }),
    vulnerabilities: Object.freeze({
      added: Object.freeze(addedVulnerabilities),
      unknownPreviouslyUnobserved: Object.freeze(
        unknownPreviouslyUnobserved,
      ),
      resolved: Object.freeze(resolved),
      changed: Object.freeze(changed),
      newKnownExploited: Object.freeze(newKnownExploited),
      unknownNewKnownExploited: Object.freeze(unknownNewKnownExploited),
      unknownNoLongerObserved: Object.freeze(unknownNoLongerObserved),
    }),
    analysis: Object.freeze({
      licenses: analysisChange(
        before.analysis.licenses,
        after.analysis.licenses,
        before.analysis.licenseSummary,
        after.analysis.licenseSummary,
      ),
      provenance: analysisChange(
        before.analysis.provenance,
        after.analysis.provenance,
        before.analysis.provenanceSummary,
        after.analysis.provenanceSummary,
      ),
      reachability: analysisChange(
        before.analysis.reachability,
        after.analysis.reachability,
        before.analysis.reachabilitySummary,
        after.analysis.reachabilitySummary,
      ),
    }),
    unknownReasons: Object.freeze([...unknownReasons].sort()),
  };
  throwIfCancelled(options.signal);
  return deepFreezeJson(json(result)) as unknown as SecuritySnapshotDiff;
}

export function compareSecurityBaseline(
  baseline: SecurityBaseline,
  current: SecuritySnapshot,
  options: SecuritySnapshotDiffOptions = {},
): SecuritySnapshotDiff {
  // The nested snapshot verifier prevents an in-memory baseline object from
  // silently suppressing a changed occurrence.
  if (
    baseline.schema !== "dependency-auditor/security-baseline" ||
    baseline.schemaVersion !== 1 ||
    !verifySecurityBaseline(baseline)
  ) {
    throw new SecurityHistoryError(
      "INTEGRITY_MISMATCH",
      "Security baseline integrity verification failed",
    );
  }
  return diffSecuritySnapshots(baseline.snapshot, current, options);
}
