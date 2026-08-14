import {
  canonicalJson,
  deepFreezeJson,
  sha256CanonicalJson,
  type JsonValue,
} from "../security/BoundedJson";
import {
  IMPORTED_CYCLONE_DX_SCHEMA,
  IMPORTED_CYCLONE_DX_SCHEMA_VERSION,
  verifyImportedCycloneDxBom,
  type CycloneDxConflict,
  type CycloneDxCoverageReason,
  type ImportedCycloneDxBom,
  type ImportedCycloneDxComponent,
  type ImportedCycloneDxRelationship,
  type ImportedCycloneDxVulnerability,
  type ImportedEvidenceCompleteness,
} from "./CycloneDxImport";

export const CYCLONE_DX_DIFF_SCHEMA =
  "dependency-auditor/cyclonedx-diff" as const;
export const CYCLONE_DX_DIFF_SCHEMA_VERSION = 1 as const;

export interface CycloneDxVersionChange {
  readonly key: string;
  readonly type: string;
  readonly group?: string;
  readonly name: string;
  readonly beforeVersions: readonly (string | null)[];
  readonly afterVersions: readonly (string | null)[];
}

export interface CycloneDxVulnerabilityChange {
  readonly identityKey: string;
  readonly before: readonly ImportedCycloneDxVulnerability[];
  readonly after: readonly ImportedCycloneDxVulnerability[];
}

export type CycloneDxDiffUnknownReason =
  | "BASELINE_INVENTORY_INCOMPLETE"
  | "CURRENT_INVENTORY_INCOMPLETE"
  | "BASELINE_VULNERABILITY_COVERAGE_INCOMPLETE"
  | "CURRENT_VULNERABILITY_COVERAGE_INCOMPLETE"
  | "BASELINE_CONFLICTS"
  | "CURRENT_CONFLICTS";

export interface CycloneDxBomDiff {
  readonly schema: typeof CYCLONE_DX_DIFF_SCHEMA;
  readonly schemaVersion: typeof CYCLONE_DX_DIFF_SCHEMA_VERSION;
  readonly beforeDigest: string;
  readonly afterDigest: string;
  readonly complete: boolean;
  readonly components: Readonly<{
    readonly added: readonly ImportedCycloneDxComponent[];
    readonly unknownAdditions: readonly ImportedCycloneDxComponent[];
    readonly removed: readonly ImportedCycloneDxComponent[];
    readonly versionChanges: readonly CycloneDxVersionChange[];
    readonly unknownRemovals: readonly ImportedCycloneDxComponent[];
    readonly unknownVersionChanges: readonly CycloneDxVersionChange[];
  }>;
  readonly vulnerabilities: Readonly<{
    readonly added: readonly ImportedCycloneDxVulnerability[];
    readonly unknownPreviouslyUnobserved: readonly ImportedCycloneDxVulnerability[];
    readonly resolved: readonly ImportedCycloneDxVulnerability[];
    readonly changed: readonly CycloneDxVulnerabilityChange[];
    readonly unknownNoLongerObserved: readonly ImportedCycloneDxVulnerability[];
  }>;
  readonly unknownReasons: readonly CycloneDxDiffUnknownReason[];
}

export interface CycloneDxOperationOptions {
  readonly signal?: AbortSignal;
  readonly maximumChanges?: number;
}

export interface CycloneDxMergeOptions {
  readonly signal?: AbortSignal;
  readonly maximumBoms?: number;
  readonly maximumComponents?: number;
  readonly maximumRelationships?: number;
  readonly maximumVulnerabilities?: number;
  readonly maximumConflicts?: number;
}

export class CycloneDxOperationError extends Error {
  public constructor(
    public readonly code: "CANCELLED" | "INVALID_INPUT" | "LIMIT_EXCEEDED",
    message: string,
  ) {
    super(message);
    this.name = "CycloneDxOperationError";
  }
}

/** Deterministic normalized JSON for diff/merge CLI and API consumers. */
export function serializeImportedCycloneDxBom(
  bom: ImportedCycloneDxBom,
): string {
  validateBom(bom);
  return `${canonicalJson(json(bom))}\n`;
}

/** Deterministic normalized JSON for diff CLI and API consumers. */
export function serializeCycloneDxBomDiff(diff: CycloneDxBomDiff): string {
  return `${canonicalJson(json(diff))}\n`;
}

const MAXIMUM_CHANGES = 500_000;
const MAXIMUM_BOMS = 256;
const MAXIMUM_COMPONENTS = 500_000;
const MAXIMUM_RELATIONSHIPS = 500_000;
const MAXIMUM_VULNERABILITIES = 500_000;
const MAXIMUM_CONFLICTS = 250_000;

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function json(value: unknown): JsonValue {
  return value as JsonValue;
}

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new CycloneDxOperationError(
      "CANCELLED",
      "CycloneDX operation was cancelled",
    );
  }
}

function limit(
  value: number | undefined,
  fallback: number,
  maximum: number,
  name: string,
): number {
  const selected = value ?? fallback;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > maximum
  ) {
    throw new CycloneDxOperationError(
      "LIMIT_EXCEEDED",
      `${name} is outside the supported safety range`,
    );
  }
  return selected;
}

function validateBom(bom: ImportedCycloneDxBom): void {
  if (!verifyImportedCycloneDxBom(bom)) {
    throw new CycloneDxOperationError(
      "INVALID_INPUT",
      "Normalized CycloneDX BOM is invalid",
    );
  }
}

function componentPackageKey(component: ImportedCycloneDxComponent): string {
  return canonicalJson(
    json([component.type, component.group ?? "", component.name]),
  );
}

function compareComponent(
  left: ImportedCycloneDxComponent,
  right: ImportedCycloneDxComponent,
): number {
  return compareText(left.key, right.key);
}

function compareFinding(
  left: ImportedCycloneDxVulnerability,
  right: ImportedCycloneDxVulnerability,
): number {
  return compareText(left.key, right.key);
}

function groupComponents(
  components: readonly ImportedCycloneDxComponent[],
): ReadonlyMap<string, readonly ImportedCycloneDxComponent[]> {
  const values = new Map<string, ImportedCycloneDxComponent[]>();
  for (const component of components) {
    const key = componentPackageKey(component);
    const entries = values.get(key) ?? [];
    entries.push(component);
    values.set(key, entries);
  }
  const result = new Map<string, readonly ImportedCycloneDxComponent[]>();
  for (const [key, entries] of values) {
    entries.sort(compareComponent);
    result.set(key, Object.freeze(entries));
  }
  return result;
}

function groupFindings(
  findings: readonly ImportedCycloneDxVulnerability[],
): ReadonlyMap<string, readonly ImportedCycloneDxVulnerability[]> {
  const values = new Map<string, ImportedCycloneDxVulnerability[]>();
  for (const finding of findings) {
    const entries = values.get(finding.identityKey) ?? [];
    entries.push(finding);
    values.set(finding.identityKey, entries);
  }
  const result = new Map<string, readonly ImportedCycloneDxVulnerability[]>();
  for (const [key, entries] of values) {
    entries.sort(compareFinding);
    result.set(key, Object.freeze(entries));
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

function versions(
  components: readonly ImportedCycloneDxComponent[],
): readonly (string | null)[] {
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

function versionChange(
  packageKey: string,
  before: readonly ImportedCycloneDxComponent[],
  after: readonly ImportedCycloneDxComponent[],
): CycloneDxVersionChange {
  const identity = after[0] ?? before[0];
  if (identity === undefined) {
    throw new CycloneDxOperationError(
      "INVALID_INPUT",
      "CycloneDX version-change identity is missing",
    );
  }
  const beforeVersions = versions(before);
  const afterVersions = versions(after);
  return Object.freeze({
    key: sha256CanonicalJson(json([packageKey, beforeVersions, afterVersions])),
    type: identity.type,
    ...(identity.group === undefined ? {} : { group: identity.group }),
    name: identity.name,
    beforeVersions,
    afterVersions,
  });
}

export function diffCycloneDxBoms(
  before: ImportedCycloneDxBom,
  after: ImportedCycloneDxBom,
  options: CycloneDxOperationOptions = {},
): CycloneDxBomDiff {
  throwIfCancelled(options.signal);
  validateBom(before);
  validateBom(after);
  const maximum = limit(
    options.maximumChanges,
    MAXIMUM_CHANGES,
    MAXIMUM_CHANGES,
    "maximumChanges",
  );
  const beforeInventoryComplete =
    before.coverage.inventory === "complete" && before.conflicts.length === 0;
  const afterInventoryComplete =
    after.coverage.inventory === "complete" && after.conflicts.length === 0;
  const beforeVulnerabilitiesComplete =
    before.coverage.vulnerabilityAnalysis === "complete" &&
    before.conflicts.length === 0;
  const afterVulnerabilitiesComplete =
    after.coverage.vulnerabilityAnalysis === "complete" &&
    after.conflicts.length === 0;
  const unknownReasons = new Set<CycloneDxDiffUnknownReason>();
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
  if (before.conflicts.length > 0) {
    unknownReasons.add("BASELINE_CONFLICTS");
  }
  if (after.conflicts.length > 0) {
    unknownReasons.add("CURRENT_CONFLICTS");
  }

  let changes = 0;
  const oldComponents = groupComponents(before.components);
  const newComponents = groupComponents(after.components);
  const packageKeys = [...new Set([...oldComponents.keys(), ...newComponents.keys()])].sort();
  const added: ImportedCycloneDxComponent[] = [];
  const unknownAdditions: ImportedCycloneDxComponent[] = [];
  const removed: ImportedCycloneDxComponent[] = [];
  const unknownRemovals: ImportedCycloneDxComponent[] = [];
  const versionChanges: CycloneDxVersionChange[] = [];
  const unknownVersionChanges: CycloneDxVersionChange[] = [];
  for (let index = 0; index < packageKeys.length; index += 1) {
    if ((index & 255) === 0) {
      throwIfCancelled(options.signal);
    }
    const key = packageKeys[index];
    if (key === undefined) {
      continue;
    }
    const oldValues = oldComponents.get(key) ?? [];
    const newValues = newComponents.get(key) ?? [];
    if (oldValues.length === 0) {
      (beforeInventoryComplete ? added : unknownAdditions).push(...newValues);
      changes += newValues.length;
    } else if (newValues.length === 0) {
      (afterInventoryComplete ? removed : unknownRemovals).push(...oldValues);
      changes += oldValues.length;
    } else if (!sameKeys(oldValues, newValues)) {
      const changed = versionChange(key, oldValues, newValues);
      (beforeInventoryComplete && afterInventoryComplete
        ? versionChanges
        : unknownVersionChanges
      ).push(changed);
      changes += 1;
    }
    if (changes > maximum) {
      throw new CycloneDxOperationError(
        "LIMIT_EXCEEDED",
        "CycloneDX component diff exceeds the configured change limit",
      );
    }
  }

  const oldFindings = groupFindings(before.vulnerabilities);
  const newFindings = groupFindings(after.vulnerabilities);
  const findingKeys = [...new Set([...oldFindings.keys(), ...newFindings.keys()])].sort();
  const addedFindings: ImportedCycloneDxVulnerability[] = [];
  const unknownPreviouslyUnobserved: ImportedCycloneDxVulnerability[] = [];
  const resolved: ImportedCycloneDxVulnerability[] = [];
  const unknownNoLongerObserved: ImportedCycloneDxVulnerability[] = [];
  const changed: CycloneDxVulnerabilityChange[] = [];
  for (let index = 0; index < findingKeys.length; index += 1) {
    if ((index & 255) === 0) {
      throwIfCancelled(options.signal);
    }
    const key = findingKeys[index];
    if (key === undefined) {
      continue;
    }
    const oldValues = oldFindings.get(key) ?? [];
    const newValues = newFindings.get(key) ?? [];
    if (oldValues.length === 0) {
      (beforeVulnerabilitiesComplete
        ? addedFindings
        : unknownPreviouslyUnobserved
      ).push(...newValues);
      changes += newValues.length;
    } else if (newValues.length === 0) {
      (afterVulnerabilitiesComplete ? resolved : unknownNoLongerObserved).push(
        ...oldValues,
      );
      changes += oldValues.length;
    } else if (!sameKeys(oldValues, newValues)) {
      changed.push(
        Object.freeze({
          identityKey: key,
          before: oldValues,
          after: newValues,
        }),
      );
      changes += 1;
    }
    if (changes > maximum) {
      throw new CycloneDxOperationError(
        "LIMIT_EXCEEDED",
        "CycloneDX vulnerability diff exceeds the configured change limit",
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
  addedFindings.sort(compareFinding);
  unknownPreviouslyUnobserved.sort(compareFinding);
  resolved.sort(compareFinding);
  unknownNoLongerObserved.sort(compareFinding);
  changed.sort((left, right) =>
    compareText(left.identityKey, right.identityKey),
  );
  const result: CycloneDxBomDiff = {
    schema: CYCLONE_DX_DIFF_SCHEMA,
    schemaVersion: CYCLONE_DX_DIFF_SCHEMA_VERSION,
    beforeDigest: before.source.digest,
    afterDigest: after.source.digest,
    complete:
      beforeInventoryComplete &&
      afterInventoryComplete &&
      beforeVulnerabilitiesComplete &&
      afterVulnerabilitiesComplete,
    components: Object.freeze({
      added: Object.freeze(added),
      unknownAdditions: Object.freeze(unknownAdditions),
      removed: Object.freeze(removed),
      versionChanges: Object.freeze(versionChanges),
      unknownRemovals: Object.freeze(unknownRemovals),
      unknownVersionChanges: Object.freeze(unknownVersionChanges),
    }),
    vulnerabilities: Object.freeze({
      added: Object.freeze(addedFindings),
      unknownPreviouslyUnobserved: Object.freeze(
        unknownPreviouslyUnobserved,
      ),
      resolved: Object.freeze(resolved),
      changed: Object.freeze(changed),
      unknownNoLongerObserved: Object.freeze(unknownNoLongerObserved),
    }),
    unknownReasons: Object.freeze([...unknownReasons].sort()),
  };
  throwIfCancelled(options.signal);
  return deepFreezeJson(json(result)) as unknown as CycloneDxBomDiff;
}

function mergedCompleteness(
  values: readonly ImportedEvidenceCompleteness[],
): ImportedEvidenceCompleteness {
  if (values.every((value) => value === "complete")) {
    return "complete";
  }
  if (values.some((value) => value === "partial")) {
    return "partial";
  }
  return "unknown";
}

function addConflict(
  conflicts: Map<string, CycloneDxConflict>,
  conflict: CycloneDxConflict,
  maximum: number,
): void {
  const key = `${conflict.code}:${conflict.subjectHash}`;
  if (!conflicts.has(key)) {
    if (conflicts.size >= maximum) {
      throw new CycloneDxOperationError(
        "LIMIT_EXCEEDED",
        "Merged CycloneDX conflicts exceed the configured limit",
      );
    }
    conflicts.set(key, conflict);
  }
}

export function mergeCycloneDxBoms(
  boms: readonly ImportedCycloneDxBom[],
  options: CycloneDxMergeOptions = {},
): ImportedCycloneDxBom {
  throwIfCancelled(options.signal);
  const maximumBoms = limit(
    options.maximumBoms,
    MAXIMUM_BOMS,
    MAXIMUM_BOMS,
    "maximumBoms",
  );
  const maximumComponents = limit(
    options.maximumComponents,
    MAXIMUM_COMPONENTS,
    MAXIMUM_COMPONENTS,
    "maximumComponents",
  );
  const maximumRelationships = limit(
    options.maximumRelationships,
    MAXIMUM_RELATIONSHIPS,
    MAXIMUM_RELATIONSHIPS,
    "maximumRelationships",
  );
  const maximumVulnerabilities = limit(
    options.maximumVulnerabilities,
    MAXIMUM_VULNERABILITIES,
    MAXIMUM_VULNERABILITIES,
    "maximumVulnerabilities",
  );
  const maximumConflicts = limit(
    options.maximumConflicts,
    MAXIMUM_CONFLICTS,
    MAXIMUM_CONFLICTS,
    "maximumConflicts",
  );
  if (!Array.isArray(boms) || boms.length === 0 || boms.length > maximumBoms) {
    throw new CycloneDxOperationError(
      boms.length > maximumBoms ? "LIMIT_EXCEEDED" : "INVALID_INPUT",
      "CycloneDX merge requires a bounded non-empty BOM collection",
    );
  }
  const ordered = [...boms].sort((left, right) =>
    compareText(left.source.digest, right.source.digest),
  );
  for (const bom of ordered) {
    validateBom(bom);
  }
  const componentEvidence = new Map<
    string,
    Map<string, ImportedCycloneDxComponent>
  >();
  const relationships = new Map<string, Set<string>>();
  const findings = new Map<string, ImportedCycloneDxVulnerability>();
  const identityEvidence = new Map<string, Set<string>>();
  const conflicts = new Map<string, CycloneDxConflict>();
  const reasons = new Set<CycloneDxCoverageReason>();
  for (let index = 0; index < ordered.length; index += 1) {
    if ((index & 15) === 0) {
      throwIfCancelled(options.signal);
    }
    const bom = ordered[index];
    if (bom === undefined) {
      continue;
    }
    for (const component of bom.components) {
      const candidates = componentEvidence.get(component.key) ?? new Map();
      candidates.set(canonicalJson(json(component)), component);
      componentEvidence.set(component.key, candidates);
      if (componentEvidence.size > maximumComponents) {
        throw new CycloneDxOperationError(
          "LIMIT_EXCEEDED",
          "Merged CycloneDX components exceed the configured limit",
        );
      }
    }
    for (const relationship of bom.relationships) {
      const targets = relationships.get(relationship.componentKey) ?? new Set();
      for (const target of relationship.dependsOn) {
        targets.add(target);
      }
      relationships.set(relationship.componentKey, targets);
      if (relationships.size > maximumRelationships) {
        throw new CycloneDxOperationError(
          "LIMIT_EXCEEDED",
          "Merged CycloneDX relationships exceed the configured limit",
        );
      }
    }
    for (const finding of bom.vulnerabilities) {
      findings.set(finding.key, finding);
      const evidence = identityEvidence.get(finding.identityKey) ?? new Set();
      evidence.add(finding.evidenceHash);
      identityEvidence.set(finding.identityKey, evidence);
      if (findings.size > maximumVulnerabilities) {
        throw new CycloneDxOperationError(
          "LIMIT_EXCEEDED",
          "Merged CycloneDX vulnerabilities exceed the configured limit",
        );
      }
    }
    for (const conflict of bom.conflicts) {
      addConflict(conflicts, conflict, maximumConflicts);
    }
    for (const reason of bom.coverage.reasons) {
      reasons.add(reason);
    }
  }
  const components: ImportedCycloneDxComponent[] = [];
  for (const [key, candidates] of [...componentEvidence.entries()].sort(
    ([left], [right]) => compareText(left, right),
  )) {
    const selected = [...candidates.entries()].sort(([left], [right]) =>
      compareText(left, right),
    )[0]?.[1];
    if (selected !== undefined) {
      components.push(selected);
    }
    if (candidates.size > 1) {
      addConflict(
        conflicts,
        Object.freeze({
          code: "COMPONENT_EVIDENCE_CONFLICT" as const,
          subjectHash: sha256CanonicalJson(json(key)),
        }),
        maximumConflicts,
      );
    }
  }
  for (const [identity, evidence] of identityEvidence) {
    if (evidence.size > 1) {
      addConflict(
        conflicts,
        Object.freeze({
          code: "VULNERABILITY_EVIDENCE_CONFLICT" as const,
          subjectHash: sha256CanonicalJson(json(identity)),
        }),
        maximumConflicts,
      );
    }
  }
  if (conflicts.size > 0) {
    reasons.add("REFERENCE_CONFLICT");
  }
  const inventoryValues = ordered.map((bom) => bom.coverage.inventory);
  const vulnerabilityValues = ordered.map(
    (bom) => bom.coverage.vulnerabilityAnalysis,
  );
  const graphValues = ordered.map((bom) => bom.coverage.dependencyGraph);
  let inventory = mergedCompleteness(inventoryValues);
  let vulnerabilityAnalysis = mergedCompleteness(vulnerabilityValues);
  let dependencyGraph = mergedCompleteness(graphValues);
  if (conflicts.size > 0) {
    if (inventory === "complete") {
      inventory = "partial";
    }
    if (vulnerabilityAnalysis === "complete") {
      vulnerabilityAnalysis = "partial";
    }
    if (dependencyGraph === "complete") {
      dependencyGraph = "partial";
    }
  }
  const specVersion = ordered
    .map((bom) => bom.source.specVersion)
    .sort((left, right) => compareText(right, left))[0];
  if (specVersion === undefined) {
    throw new CycloneDxOperationError("INVALID_INPUT", "CycloneDX merge has no source version");
  }
  const result: ImportedCycloneDxBom = {
    schema: IMPORTED_CYCLONE_DX_SCHEMA,
    schemaVersion: IMPORTED_CYCLONE_DX_SCHEMA_VERSION,
    source: Object.freeze({
      format: "CycloneDX" as const,
      specVersion,
      digest: sha256CanonicalJson(
        json([
          "merged-cyclonedx-v1",
          ordered.map((bom) => bom.source.digest),
        ]),
      ),
    }),
    components: Object.freeze(components),
    relationships: Object.freeze(
      [...relationships.entries()]
        .sort(([left], [right]) => compareText(left, right))
        .map(([componentKey, dependsOn]) =>
          Object.freeze({
            componentKey,
            dependsOn: Object.freeze([...dependsOn].sort()),
          }) satisfies ImportedCycloneDxRelationship,
        ),
    ),
    vulnerabilities: Object.freeze(
      [...findings.values()].sort(compareFinding),
    ),
    coverage: Object.freeze({
      inventory,
      vulnerabilityAnalysis,
      dependencyGraph,
      reasons: Object.freeze([...reasons].sort()),
    }),
    conflicts: Object.freeze(
      [...conflicts.values()].sort((left, right) =>
        compareText(
          `${left.code}:${left.subjectHash}`,
          `${right.code}:${right.subjectHash}`,
        ),
      ),
    ),
  };
  throwIfCancelled(options.signal);
  if (!verifyImportedCycloneDxBom(result)) {
    throw new CycloneDxOperationError(
      "INVALID_INPUT",
      "Merged CycloneDX model failed integrity validation",
    );
  }
  return deepFreezeJson(json(result)) as unknown as ImportedCycloneDxBom;
}
