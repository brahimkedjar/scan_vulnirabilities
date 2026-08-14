import {
  BoundedJsonError,
  canonicalJson,
  deepFreezeJson,
  parseBoundedJson,
  sha256CanonicalJson,
  type BoundedJsonLimits,
  type JsonValue,
} from "../security/BoundedJson";

export const IMPORTED_CYCLONE_DX_SCHEMA =
  "dependency-auditor/imported-cyclonedx" as const;
export const IMPORTED_CYCLONE_DX_SCHEMA_VERSION = 1 as const;

export type ImportedEvidenceCompleteness =
  | "complete"
  | "partial"
  | "unknown";

export interface ImportedCycloneDxComponent {
  readonly key: string;
  readonly type: string;
  readonly group?: string;
  readonly name: string;
  readonly version: string | null;
  /** Package URL without qualifiers or subpath. */
  readonly purl?: string;
}

export interface ImportedCycloneDxRelationship {
  readonly componentKey: string;
  readonly dependsOn: readonly string[];
}

export interface ImportedCycloneDxRating {
  readonly severity?: "critical" | "high" | "medium" | "low" | "unknown";
  readonly score?: number;
  readonly source?: string;
}

export interface ImportedCycloneDxVulnerability {
  readonly key: string;
  readonly identityKey: string;
  readonly evidenceHash: string;
  readonly id: string;
  readonly source: string;
  readonly affectedComponentKeys: readonly string[];
  readonly ratings: readonly ImportedCycloneDxRating[];
}

export type CycloneDxConflictCode =
  | "COMPONENT_EVIDENCE_CONFLICT"
  | "DUPLICATE_COMPONENT_REFERENCE"
  | "UNKNOWN_RELATIONSHIP_REFERENCE"
  | "UNKNOWN_AFFECTED_COMPONENT_REFERENCE"
  | "VULNERABILITY_EVIDENCE_CONFLICT";

export interface CycloneDxConflict {
  readonly code: CycloneDxConflictCode;
  /** SHA-256 only; untrusted raw references are never retained. */
  readonly subjectHash: string;
}

export type CycloneDxCoverageReason =
  | "COMPOSITION_NOT_DECLARED"
  | "COMPOSITION_INCOMPLETE"
  | "COMPONENTS_NOT_DECLARED"
  | "VULNERABILITIES_NOT_DECLARED"
  | "RELATIONSHIPS_NOT_DECLARED"
  | "REFERENCE_CONFLICT"
  | "PATH_EVIDENCE_OMITTED";

export interface ImportedCycloneDxBom {
  readonly schema: typeof IMPORTED_CYCLONE_DX_SCHEMA;
  readonly schemaVersion: typeof IMPORTED_CYCLONE_DX_SCHEMA_VERSION;
  readonly source: Readonly<{
    format: "CycloneDX";
    specVersion: "1.4" | "1.5" | "1.6";
    digest: string;
  }>;
  readonly components: readonly ImportedCycloneDxComponent[];
  readonly relationships: readonly ImportedCycloneDxRelationship[];
  readonly vulnerabilities: readonly ImportedCycloneDxVulnerability[];
  readonly coverage: Readonly<{
    inventory: ImportedEvidenceCompleteness;
    vulnerabilityAnalysis: ImportedEvidenceCompleteness;
    dependencyGraph: ImportedEvidenceCompleteness;
    reasons: readonly CycloneDxCoverageReason[];
  }>;
  readonly conflicts: readonly CycloneDxConflict[];
}

export interface CycloneDxImportLimits {
  readonly maximumComponents: number;
  readonly maximumRelationships: number;
  readonly maximumRelationshipTargets: number;
  readonly maximumVulnerabilities: number;
  readonly maximumAffectedComponents: number;
  readonly maximumRatings: number;
  readonly maximumConflicts: number;
  readonly maximumPathLength: number;
}

export interface CycloneDxImportOptions {
  readonly signal?: AbortSignal;
  readonly limits?: Partial<CycloneDxImportLimits>;
  readonly jsonLimits?: Partial<BoundedJsonLimits>;
}

export type CycloneDxImportErrorCode =
  | "CANCELLED"
  | "INVALID_INPUT"
  | "LIMIT_EXCEEDED";

export class CycloneDxImportError extends Error {
  public constructor(
    public readonly code: CycloneDxImportErrorCode,
    message: string,
    options: { readonly cause?: unknown } = {},
  ) {
    super(message, options);
    this.name = "CycloneDxImportError";
  }
}

export const CYCLONE_DX_IMPORT_LIMITS: Readonly<CycloneDxImportLimits> =
  Object.freeze({
    maximumComponents: 250_000,
    maximumRelationships: 250_000,
    maximumRelationshipTargets: 500_000,
    maximumVulnerabilities: 250_000,
    maximumAffectedComponents: 500_000,
    maximumRatings: 64,
    maximumConflicts: 100_000,
    maximumPathLength: 4_096,
  });

const LIMIT_KEYS = Object.freeze([
  "maximumComponents",
  "maximumRelationships",
  "maximumRelationshipTargets",
  "maximumVulnerabilities",
  "maximumAffectedComponents",
  "maximumRatings",
  "maximumConflicts",
  "maximumPathLength",
] as const satisfies readonly (keyof CycloneDxImportLimits)[]);
const UNSAFE =
  /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const ABSOLUTE_OR_URI =
  /^(?:[A-Za-z]:[\\/]|[\\/]|[A-Za-z][A-Za-z0-9+.-]*:)/u;
const MAXIMUM_TOKEN = 2_048;
const SPEC_VERSIONS: ReadonlySet<string> = new Set(["1.4", "1.5", "1.6"]);
const SEVERITIES: ReadonlySet<string> = new Set([
  "critical",
  "high",
  "medium",
  "low",
  "unknown",
]);

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function json(value: unknown): JsonValue {
  return value as JsonValue;
}

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new CycloneDxImportError(
      "CANCELLED",
      "CycloneDX import was cancelled",
    );
  }
}

function resolveLimits(
  requested: Partial<CycloneDxImportLimits> | undefined,
): CycloneDxImportLimits {
  const resolved = { ...CYCLONE_DX_IMPORT_LIMITS };
  for (const key of LIMIT_KEYS) {
    const value = requested?.[key];
    if (value === undefined) {
      continue;
    }
    if (
      !Number.isSafeInteger(value) ||
      value < 1 ||
      value > CYCLONE_DX_IMPORT_LIMITS[key]
    ) {
      throw new CycloneDxImportError(
        "LIMIT_EXCEEDED",
        `${key} is outside the supported safety range`,
      );
    }
    resolved[key] = value;
  }
  return Object.freeze(resolved);
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new CycloneDxImportError(
      "INVALID_INPUT",
      `${name} must be an object`,
    );
  }
  return value as Record<string, unknown>;
}

function token(
  value: unknown,
  name: string,
  maximumLength = MAXIMUM_TOKEN,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    value.trim() !== value ||
    UNSAFE.test(value)
  ) {
    throw new CycloneDxImportError("INVALID_INPUT", `${name} is invalid`);
  }
  return value;
}

function optionalToken(
  value: unknown,
  name: string,
  maximumLength = MAXIMUM_TOKEN,
): string | undefined {
  return value === undefined ? undefined : token(value, name, maximumLength);
}

function array(
  value: unknown,
  name: string,
  maximum: number,
  required: boolean,
): readonly unknown[] | undefined {
  if (value === undefined && !required) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new CycloneDxImportError(
      "INVALID_INPUT",
      `${name} must be an array`,
    );
  }
  if (value.length > maximum) {
    throw new CycloneDxImportError(
      "LIMIT_EXCEEDED",
      `${name} exceeds the safety limit`,
    );
  }
  return value;
}

function sanitizedPurl(value: unknown): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const selected = token(value, "component purl", MAXIMUM_TOKEN);
  if (!selected.startsWith("pkg:") || /\s/u.test(selected)) {
    throw new CycloneDxImportError("INVALID_INPUT", "Component purl is invalid");
  }
  const qualifier = selected.indexOf("?");
  const subpath = selected.indexOf("#");
  const boundary = [qualifier, subpath]
    .filter((index) => index >= 0)
    .sort((left, right) => left - right)[0];
  const base = boundary === undefined ? selected : selected.slice(0, boundary);
  if (base.length <= 4 || base.includes("@/")) {
    throw new CycloneDxImportError("INVALID_INPUT", "Component purl is invalid");
  }
  return base;
}

function sourceRef(value: unknown, name: string): string | undefined {
  return value === undefined ? undefined : token(value, name, 4_096);
}

function componentEvidenceKey(component: Omit<ImportedCycloneDxComponent, "key">): string {
  return canonicalJson(json(component));
}

function componentIdentityKey(component: {
  readonly type: string;
  readonly group?: string;
  readonly name: string;
  readonly version: string | null;
  readonly purl?: string;
}): string {
  return sha256CanonicalJson(
    component.purl === undefined
      ? json([
          "fields",
          component.type,
          component.group ?? "",
          component.name,
          component.version,
        ])
      : json(["purl", component.purl]),
  );
}

interface ParsedComponent {
  readonly component: ImportedCycloneDxComponent;
  readonly reference?: string;
}

function inspectOmittedOccurrences(
  raw: Record<string, unknown>,
  limits: CycloneDxImportLimits,
  reasons: Set<CycloneDxCoverageReason>,
): void {
  if (raw.evidence === undefined) {
    return;
  }
  const evidence = record(raw.evidence, "component evidence");
  const occurrences = array(
    evidence.occurrences,
    "component occurrences",
    limits.maximumRelationshipTargets,
    false,
  );
  if (occurrences === undefined) {
    return;
  }
  for (const occurrenceValue of occurrences) {
    const occurrence = record(occurrenceValue, "component occurrence");
    if (occurrence.location === undefined) {
      continue;
    }
    const location = token(
      occurrence.location,
      "component occurrence location",
      limits.maximumPathLength,
    );
    // All external path evidence is deliberately omitted. The checks below
    // ensure traversal and absolute-path strings are never normalized into
    // the host-neutral model.
    if (
      ABSOLUTE_OR_URI.test(location) ||
      location.replaceAll("\\", "/").split("/").includes("..")
    ) {
      reasons.add("PATH_EVIDENCE_OMITTED");
    } else {
      reasons.add("PATH_EVIDENCE_OMITTED");
    }
  }
}

function parseComponent(
  value: unknown,
  limits: CycloneDxImportLimits,
  reasons: Set<CycloneDxCoverageReason>,
): ParsedComponent {
  const raw = record(value, "CycloneDX component");
  const type = token(raw.type ?? "library", "component type", 64);
  const group = optionalToken(raw.group, "component group", 512);
  const name = token(raw.name, "component name", 512);
  const version =
    raw.version === undefined || raw.version === null
      ? null
      : token(raw.version, "component version", 256);
  const purl = sanitizedPurl(raw.purl);
  inspectOmittedOccurrences(raw, limits, reasons);
  const base = {
    type,
    ...(group === undefined ? {} : { group }),
    name,
    version,
    ...(purl === undefined ? {} : { purl }),
  };
  const reference =
    raw["bom-ref"] === undefined
      ? undefined
      : sourceRef(raw["bom-ref"], "component bom-ref");
  return {
    component: Object.freeze({
      key: componentIdentityKey(base),
      ...base,
    }),
    ...(reference === undefined ? {} : { reference }),
  };
}

function addConflict(
  conflicts: Map<string, CycloneDxConflict>,
  code: CycloneDxConflictCode,
  subject: string,
  maximum: number,
): void {
  const subjectHash = sha256CanonicalJson(json(subject));
  const key = `${code}:${subjectHash}`;
  if (!conflicts.has(key)) {
    if (conflicts.size >= maximum) {
      throw new CycloneDxImportError(
        "LIMIT_EXCEEDED",
        "CycloneDX conflicts exceed the safety limit",
      );
    }
    conflicts.set(key, Object.freeze({ code, subjectHash }));
  }
}

interface ComponentIndex {
  readonly components: readonly ImportedCycloneDxComponent[];
  readonly references: ReadonlyMap<string, ReadonlySet<string>>;
}

function buildComponents(
  rawComponents: readonly unknown[],
  limits: CycloneDxImportLimits,
  reasons: Set<CycloneDxCoverageReason>,
  conflicts: Map<string, CycloneDxConflict>,
  signal: AbortSignal | undefined,
): ComponentIndex {
  const candidates = new Map<string, Map<string, ImportedCycloneDxComponent>>();
  const references = new Map<string, Set<string>>();
  for (let index = 0; index < rawComponents.length; index += 1) {
    if ((index & 255) === 0) {
      throwIfCancelled(signal);
    }
    const parsed = parseComponent(rawComponents[index], limits, reasons);
    const key = parsed.component.key;
    const byEvidence = candidates.get(key) ?? new Map();
    byEvidence.set(componentEvidenceKey(parsed.component), parsed.component);
    candidates.set(key, byEvidence);
    if (parsed.reference !== undefined) {
      const values = references.get(parsed.reference) ?? new Set();
      values.add(key);
      references.set(parsed.reference, values);
    }
  }
  const components: ImportedCycloneDxComponent[] = [];
  for (const [key, byEvidence] of [...candidates.entries()].sort(
    ([left], [right]) => compareText(left, right),
  )) {
    const values = [...byEvidence.entries()].sort(([left], [right]) =>
      compareText(left, right),
    );
    const selected = values[0]?.[1];
    if (selected === undefined) {
      continue;
    }
    components.push(selected);
    if (values.length > 1) {
      addConflict(
        conflicts,
        "COMPONENT_EVIDENCE_CONFLICT",
        key,
        limits.maximumConflicts,
      );
    }
  }
  for (const [reference, keys] of references) {
    if (keys.size > 1) {
      addConflict(
        conflicts,
        "DUPLICATE_COMPONENT_REFERENCE",
        reference,
        limits.maximumConflicts,
      );
      reasons.add("REFERENCE_CONFLICT");
    }
  }
  return {
    components: Object.freeze(components),
    references,
  };
}

function resolveReference(
  reference: string,
  references: ReadonlyMap<string, ReadonlySet<string>>,
): string | undefined {
  const keys = references.get(reference);
  return keys?.size === 1 ? keys.values().next().value : undefined;
}

function buildRelationships(
  rawRelationships: readonly unknown[] | undefined,
  references: ReadonlyMap<string, ReadonlySet<string>>,
  limits: CycloneDxImportLimits,
  conflicts: Map<string, CycloneDxConflict>,
  reasons: Set<CycloneDxCoverageReason>,
  signal: AbortSignal | undefined,
): readonly ImportedCycloneDxRelationship[] {
  if (rawRelationships === undefined) {
    reasons.add("RELATIONSHIPS_NOT_DECLARED");
    return Object.freeze([]);
  }
  const relationships = new Map<string, Set<string>>();
  let targetCount = 0;
  for (let index = 0; index < rawRelationships.length; index += 1) {
    if ((index & 255) === 0) {
      throwIfCancelled(signal);
    }
    const raw = record(rawRelationships[index], "CycloneDX dependency relationship");
    const rawRef = token(raw.ref, "relationship ref", 4_096);
    const componentKey = resolveReference(rawRef, references);
    if (componentKey === undefined) {
      addConflict(
        conflicts,
        "UNKNOWN_RELATIONSHIP_REFERENCE",
        rawRef,
        limits.maximumConflicts,
      );
      reasons.add("REFERENCE_CONFLICT");
      continue;
    }
    const targets = array(
      raw.dependsOn,
      "relationship targets",
      limits.maximumRelationshipTargets,
      false,
    ) ?? [];
    const resolved = relationships.get(componentKey) ?? new Set<string>();
    for (const targetValue of targets) {
      targetCount += 1;
      if (targetCount > limits.maximumRelationshipTargets) {
        throw new CycloneDxImportError(
          "LIMIT_EXCEEDED",
          "CycloneDX relationship targets exceed the safety limit",
        );
      }
      const targetRef = token(targetValue, "relationship target", 4_096);
      const targetKey = resolveReference(targetRef, references);
      if (targetKey === undefined) {
        addConflict(
          conflicts,
          "UNKNOWN_RELATIONSHIP_REFERENCE",
          targetRef,
          limits.maximumConflicts,
        );
        reasons.add("REFERENCE_CONFLICT");
      } else {
        resolved.add(targetKey);
      }
    }
    relationships.set(componentKey, resolved);
  }
  return Object.freeze(
    [...relationships.entries()]
      .sort(([left], [right]) => compareText(left, right))
      .map(([componentKey, dependsOn]) =>
        Object.freeze({
          componentKey,
          dependsOn: Object.freeze([...dependsOn].sort()),
        }),
      ),
  );
}

function parseRating(value: unknown): ImportedCycloneDxRating {
  const raw = record(value, "CycloneDX vulnerability rating");
  const severity = optionalToken(raw.severity, "rating severity", 32)?.toLowerCase();
  if (severity !== undefined && !SEVERITIES.has(severity)) {
    throw new CycloneDxImportError("INVALID_INPUT", "Rating severity is invalid");
  }
  if (
    raw.score !== undefined &&
    (typeof raw.score !== "number" ||
      !Number.isFinite(raw.score) ||
      raw.score < 0 ||
      raw.score > 10)
  ) {
    throw new CycloneDxImportError("INVALID_INPUT", "Rating score is invalid");
  }
  const sourceObject =
    raw.source === undefined ? undefined : record(raw.source, "rating source");
  const source = optionalToken(sourceObject?.name, "rating source name", 128);
  if (severity === undefined && raw.score === undefined && source === undefined) {
    throw new CycloneDxImportError("INVALID_INPUT", "Rating has no supported evidence");
  }
  return Object.freeze({
    ...(severity === undefined
      ? {}
      : {
          severity: severity as Exclude<
            ImportedCycloneDxRating["severity"],
            undefined
          >,
        }),
    ...(raw.score === undefined ? {} : { score: raw.score }),
    ...(source === undefined ? {} : { source }),
  });
}

function buildVulnerabilities(
  rawVulnerabilities: readonly unknown[] | undefined,
  references: ReadonlyMap<string, ReadonlySet<string>>,
  limits: CycloneDxImportLimits,
  conflicts: Map<string, CycloneDxConflict>,
  reasons: Set<CycloneDxCoverageReason>,
  signal: AbortSignal | undefined,
): readonly ImportedCycloneDxVulnerability[] {
  if (rawVulnerabilities === undefined) {
    reasons.add("VULNERABILITIES_NOT_DECLARED");
    return Object.freeze([]);
  }
  const findings = new Map<string, ImportedCycloneDxVulnerability>();
  const identityEvidence = new Map<string, Set<string>>();
  let affectedCount = 0;
  for (let index = 0; index < rawVulnerabilities.length; index += 1) {
    if ((index & 255) === 0) {
      throwIfCancelled(signal);
    }
    const raw = record(rawVulnerabilities[index], "CycloneDX vulnerability");
    const id = token(raw.id, "vulnerability id", 512);
    const sourceObject =
      raw.source === undefined ? undefined : record(raw.source, "vulnerability source");
    const source = optionalToken(sourceObject?.name, "vulnerability source name", 128) ?? "UNKNOWN";
    const rawRatings = array(
      raw.ratings,
      "vulnerability ratings",
      limits.maximumRatings,
      false,
    ) ?? [];
    const ratingsByEvidence = new Map<string, ImportedCycloneDxRating>();
    for (const ratingValue of rawRatings) {
      const rating = parseRating(ratingValue);
      ratingsByEvidence.set(canonicalJson(json(rating)), rating);
    }
    const ratings = Object.freeze(
      [...ratingsByEvidence.entries()]
        .sort(([left], [right]) => compareText(left, right))
        .map(([, rating]) => rating),
    );
    const rawAffects = array(
      raw.affects,
      "vulnerability affects",
      limits.maximumAffectedComponents,
      false,
    ) ?? [];
    const affected = new Set<string>();
    for (const affectValue of rawAffects) {
      affectedCount += 1;
      if (affectedCount > limits.maximumAffectedComponents) {
        throw new CycloneDxImportError(
          "LIMIT_EXCEEDED",
          "CycloneDX affected components exceed the safety limit",
        );
      }
      const affect = record(affectValue, "vulnerability affect");
      const ref = token(affect.ref, "vulnerability affected ref", 4_096);
      const resolved = resolveReference(ref, references);
      if (resolved === undefined) {
        addConflict(
          conflicts,
          "UNKNOWN_AFFECTED_COMPONENT_REFERENCE",
          ref,
          limits.maximumConflicts,
        );
        reasons.add("REFERENCE_CONFLICT");
      } else {
        affected.add(resolved);
      }
    }
    const affectedComponentKeys = Object.freeze([...affected].sort());
    const identityKey = sha256CanonicalJson(json([source, id]));
    const evidenceHash = sha256CanonicalJson(
      json({ affectedComponentKeys, ratings }),
    );
    const key = sha256CanonicalJson(json([identityKey, evidenceHash]));
    const finding = Object.freeze({
      key,
      identityKey,
      evidenceHash,
      id,
      source,
      affectedComponentKeys,
      ratings,
    });
    findings.set(key, finding);
    const evidence = identityEvidence.get(identityKey) ?? new Set();
    evidence.add(evidenceHash);
    identityEvidence.set(identityKey, evidence);
  }
  for (const [identity, evidence] of identityEvidence) {
    if (evidence.size > 1) {
      addConflict(
        conflicts,
        "VULNERABILITY_EVIDENCE_CONFLICT",
        identity,
        limits.maximumConflicts,
      );
    }
  }
  return Object.freeze(
    [...findings.values()].sort((left, right) =>
      compareText(left.key, right.key),
    ),
  );
}

function compositionCoverage(
  rawCompositions: readonly unknown[] | undefined,
  declared: boolean,
  reasons: Set<CycloneDxCoverageReason>,
): ImportedEvidenceCompleteness {
  if (!declared) {
    return "unknown";
  }
  if (rawCompositions === undefined || rawCompositions.length === 0) {
    reasons.add("COMPOSITION_NOT_DECLARED");
    return "unknown";
  }
  const aggregates = rawCompositions.map((value) => {
    const raw = record(value, "CycloneDX composition");
    return token(raw.aggregate, "composition aggregate", 64);
  });
  if (aggregates.some((aggregate) => aggregate === "incomplete")) {
    reasons.add("COMPOSITION_INCOMPLETE");
    return "partial";
  }
  if (aggregates.length > 0 && aggregates.every((aggregate) => aggregate === "complete")) {
    return "complete";
  }
  reasons.add("COMPOSITION_NOT_DECLARED");
  return "unknown";
}

export function importCycloneDxJson(
  text: string,
  options: CycloneDxImportOptions = {},
): ImportedCycloneDxBom {
  try {
    throwIfCancelled(options.signal);
    const limits = resolveLimits(options.limits);
    const value = parseBoundedJson(text, {
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      ...(options.jsonLimits === undefined ? {} : { limits: options.jsonLimits }),
    });
    const root = record(value, "CycloneDX document");
    if (root.bomFormat !== "CycloneDX") {
      throw new CycloneDxImportError(
        "INVALID_INPUT",
        "Document is not a CycloneDX BOM",
      );
    }
    const specVersion = token(root.specVersion, "CycloneDX specVersion", 16);
    if (!SPEC_VERSIONS.has(specVersion)) {
      throw new CycloneDxImportError(
        "INVALID_INPUT",
        "CycloneDX specification version is unsupported",
      );
    }
    const rawComponents = array(
      root.components,
      "CycloneDX components",
      limits.maximumComponents,
      false,
    );
    const rawRelationships = array(
      root.dependencies,
      "CycloneDX dependency relationships",
      limits.maximumRelationships,
      false,
    );
    const rawVulnerabilities = array(
      root.vulnerabilities,
      "CycloneDX vulnerabilities",
      limits.maximumVulnerabilities,
      false,
    );
    const rawCompositions = array(
      root.compositions,
      "CycloneDX compositions",
      limits.maximumComponents,
      false,
    );
    const reasons = new Set<CycloneDxCoverageReason>();
    const conflicts = new Map<string, CycloneDxConflict>();
    if (rawComponents === undefined) {
      reasons.add("COMPONENTS_NOT_DECLARED");
    }
    const componentIndex = buildComponents(
      rawComponents ?? [],
      limits,
      reasons,
      conflicts,
      options.signal,
    );
    const relationships = buildRelationships(
      rawRelationships,
      componentIndex.references,
      limits,
      conflicts,
      reasons,
      options.signal,
    );
    const vulnerabilities = buildVulnerabilities(
      rawVulnerabilities,
      componentIndex.references,
      limits,
      conflicts,
      reasons,
      options.signal,
    );
    const inventory = compositionCoverage(
      rawCompositions,
      rawComponents !== undefined,
      reasons,
    );
    const vulnerabilityAnalysis = compositionCoverage(
      rawCompositions,
      rawVulnerabilities !== undefined,
      reasons,
    );
    const dependencyGraph: ImportedEvidenceCompleteness =
      rawRelationships === undefined
        ? "unknown"
        : conflicts.size > 0
          ? "partial"
          : inventory === "complete"
            ? "complete"
            : inventory;
    const bom: ImportedCycloneDxBom = {
      schema: IMPORTED_CYCLONE_DX_SCHEMA,
      schemaVersion: IMPORTED_CYCLONE_DX_SCHEMA_VERSION,
      source: Object.freeze({
        format: "CycloneDX" as const,
        specVersion: specVersion as ImportedCycloneDxBom["source"]["specVersion"],
        digest: sha256CanonicalJson(value),
      }),
      components: componentIndex.components,
      relationships,
      vulnerabilities,
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
    return deepFreezeJson(json(bom)) as unknown as ImportedCycloneDxBom;
  } catch (error: unknown) {
    if (error instanceof CycloneDxImportError) {
      throw error;
    }
    if (error instanceof BoundedJsonError) {
      throw new CycloneDxImportError(
        error.code === "CANCELLED"
          ? "CANCELLED"
          : error.code === "LIMIT_EXCEEDED"
            ? "LIMIT_EXCEEDED"
            : "INVALID_INPUT",
        error.message,
        { cause: error },
      );
    }
    throw new CycloneDxImportError(
      "INVALID_INPUT",
      "CycloneDX document could not be imported safely",
      { cause: error },
    );
  }
}

/** Runtime guard for callers that persist or transport the normalized model. */
export function verifyImportedCycloneDxBom(
  bom: ImportedCycloneDxBom,
): boolean {
  try {
    if (
      typeof bom !== "object" ||
      bom === null ||
      bom.schema !== IMPORTED_CYCLONE_DX_SCHEMA ||
      bom.schemaVersion !== IMPORTED_CYCLONE_DX_SCHEMA_VERSION ||
      bom.source.format !== "CycloneDX" ||
      !SPEC_VERSIONS.has(bom.source.specVersion) ||
      !/^[0-9a-f]{64}$/u.test(bom.source.digest) ||
      !Array.isArray(bom.components) ||
      !Array.isArray(bom.relationships) ||
      !Array.isArray(bom.vulnerabilities) ||
      !Array.isArray(bom.conflicts) ||
      bom.components.length > CYCLONE_DX_IMPORT_LIMITS.maximumComponents ||
      bom.relationships.length > CYCLONE_DX_IMPORT_LIMITS.maximumRelationships ||
      bom.vulnerabilities.length > CYCLONE_DX_IMPORT_LIMITS.maximumVulnerabilities ||
      bom.conflicts.length > CYCLONE_DX_IMPORT_LIMITS.maximumConflicts
    ) {
      return false;
    }
    const components = new Set<string>();
    for (const component of bom.components) {
      token(component.type, "component type", 64);
      token(component.name, "component name", 512);
      if (component.group !== undefined) {
        token(component.group, "component group", 512);
      }
      if (component.version !== null) {
        token(component.version, "component version", 256);
      }
      if (component.purl !== undefined && sanitizedPurl(component.purl) !== component.purl) {
        return false;
      }
      if (
        component.key !== componentIdentityKey(component) ||
        components.has(component.key)
      ) {
        return false;
      }
      components.add(component.key);
    }
    const relationships = new Set<string>();
    let relationshipTargets = 0;
    for (const relationship of bom.relationships) {
      if (
        relationships.has(relationship.componentKey) ||
        !components.has(relationship.componentKey) ||
        !Array.isArray(relationship.dependsOn)
      ) {
        return false;
      }
      relationships.add(relationship.componentKey);
      const targets = new Set<string>();
      for (const target of relationship.dependsOn) {
        relationshipTargets += 1;
        if (
          relationshipTargets > CYCLONE_DX_IMPORT_LIMITS.maximumRelationshipTargets ||
          !components.has(target) ||
          targets.has(target)
        ) {
          return false;
        }
        targets.add(target);
      }
    }
    const findingKeys = new Set<string>();
    for (const finding of bom.vulnerabilities) {
      token(finding.id, "vulnerability id", 512);
      token(finding.source, "vulnerability source", 128);
      if (
        !Array.isArray(finding.affectedComponentKeys) ||
        !Array.isArray(finding.ratings) ||
        finding.ratings.length > CYCLONE_DX_IMPORT_LIMITS.maximumRatings ||
        finding.affectedComponentKeys.some((key: string) => !components.has(key))
      ) {
        return false;
      }
      for (const rating of finding.ratings) {
        if (
          (rating.severity !== undefined && !SEVERITIES.has(rating.severity)) ||
          (rating.score !== undefined &&
            (!Number.isFinite(rating.score) || rating.score < 0 || rating.score > 10))
        ) {
          return false;
        }
        if (rating.source !== undefined) {
          token(rating.source, "rating source", 128);
        }
      }
      const identityKey = sha256CanonicalJson(json([finding.source, finding.id]));
      const evidenceHash = sha256CanonicalJson(
        json({
          affectedComponentKeys: finding.affectedComponentKeys,
          ratings: finding.ratings,
        }),
      );
      if (
        finding.identityKey !== identityKey ||
        finding.evidenceHash !== evidenceHash ||
        finding.key !== sha256CanonicalJson(json([identityKey, evidenceHash])) ||
        findingKeys.has(finding.key)
      ) {
        return false;
      }
      findingKeys.add(finding.key);
    }
    const completeness = new Set(["complete", "partial", "unknown"]);
    const reasonCodes = new Set<CycloneDxCoverageReason>([
      "COMPOSITION_NOT_DECLARED",
      "COMPOSITION_INCOMPLETE",
      "COMPONENTS_NOT_DECLARED",
      "VULNERABILITIES_NOT_DECLARED",
      "RELATIONSHIPS_NOT_DECLARED",
      "REFERENCE_CONFLICT",
      "PATH_EVIDENCE_OMITTED",
    ]);
    if (
      !completeness.has(bom.coverage.inventory) ||
      !completeness.has(bom.coverage.vulnerabilityAnalysis) ||
      !completeness.has(bom.coverage.dependencyGraph) ||
      !Array.isArray(bom.coverage.reasons) ||
      bom.coverage.reasons.some((reason) => !reasonCodes.has(reason))
    ) {
      return false;
    }
    const conflictCodes = new Set<CycloneDxConflictCode>([
      "COMPONENT_EVIDENCE_CONFLICT",
      "DUPLICATE_COMPONENT_REFERENCE",
      "UNKNOWN_RELATIONSHIP_REFERENCE",
      "UNKNOWN_AFFECTED_COMPONENT_REFERENCE",
      "VULNERABILITY_EVIDENCE_CONFLICT",
    ]);
    if (
      bom.conflicts.some(
        (conflict) =>
          !conflictCodes.has(conflict.code) ||
          !/^[0-9a-f]{64}$/u.test(conflict.subjectHash),
      )
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}
