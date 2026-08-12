import type {
  AdvisoryEvidence,
  AdvisoryObservation,
  AdvisorySeverityDetail,
  EvidenceField,
  IntelligenceFreshness,
  IntelligenceSeverity,
  IntelligenceSourceError,
  IntelligenceSourceResult,
  IntelligenceSourceStatus,
  PackageCoordinate,
} from "./IntelligenceModels";

export const INTELLIGENCE_VALIDATION_LIMITS = Object.freeze({
  maximumProviderLength: 128,
  maximumAdvisoryIdLength: 512,
  maximumAliases: 256,
  maximumEcosystemLength: 64,
  maximumPackageNameLength: 1_024,
  maximumVersionLength: 512,
  maximumSummaryLength: 8_192,
  maximumDetailsLength: 1024 * 1024,
  maximumAffectedRanges: 256,
  maximumAffectedRangeLength: 32_768,
  maximumFixedVersions: 32,
  maximumCwes: 128,
  maximumReferences: 512,
  maximumUrlLength: 4_096,
  maximumSeverityDetails: 64,
  maximumEvidencePerObservation: 1_024,
  maximumEvidenceValueLength: 32_768,
  maximumObservationsPerSource: 50_000,
  maximumSourceErrors: 1_024,
  maximumErrorCodeLength: 128,
  maximumErrorMessageLength: 8_192,
});

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const UNSAFE_INLINE_CHARACTERS =
  /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const UNSAFE_TEXT_CHARACTERS =
  /[\u0000\u000B\u000C\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const RFC3339_UTC_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/u;
const CWE_PATTERN = /^CWE-[1-9]\d{0,9}$/u;

const SEVERITIES: ReadonlySet<IntelligenceSeverity> = new Set([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "UNKNOWN",
]);
const AFFECTEDNESS = new Set(["affected", "unaffected", "unknown"]);
const ADVISORY_STATUSES = new Set(["active", "withdrawn", "unknown"]);
const SOURCE_STATUSES: ReadonlySet<IntelligenceSourceStatus> = new Set([
  "available",
  "partial",
  "unavailable",
]);
const FRESHNESS_VALUES: ReadonlySet<IntelligenceFreshness> = new Set([
  "fresh",
  "stale",
  "unknown",
]);
const EVIDENCE_FIELDS: ReadonlySet<EvidenceField> = new Set([
  "identifier",
  "summary",
  "severity",
  "cvss",
  "affectedness",
  "affected-range",
  "fixed-version",
  "advisory-status",
  "cwe",
  "published",
  "modified",
  "withdrawn",
  "reference",
]);

export class IntelligenceValidationError extends TypeError {
  public constructor(message: string) {
    super(message);
    this.name = "IntelligenceValidationError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    return false;
  }
  return !Object.keys(value).some((key) => FORBIDDEN_KEYS.has(key));
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

function isInlineString(value: unknown, maximumLength: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximumLength &&
    value.trim() === value &&
    !UNSAFE_INLINE_CHARACTERS.test(value)
  );
}

function isText(value: unknown, maximumLength: number): value is string {
  return (
    typeof value === "string" &&
    value.length <= maximumLength &&
    !UNSAFE_TEXT_CHARACTERS.test(value)
  );
}

function isTimestamp(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  const match = RFC3339_UTC_PATTERN.exec(value);
  if (match === null) {
    return false;
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return false;
  }
  const instant = new Date(0);
  instant.setUTCFullYear(year, month - 1, day);
  instant.setUTCHours(hour, minute, second, 0);
  return (
    instant.getUTCFullYear() === year &&
    instant.getUTCMonth() === month - 1 &&
    instant.getUTCDate() === day &&
    Number.isFinite(instant.getTime())
  );
}

function isHttpsUrl(value: unknown): value is string {
  if (
    !isInlineString(value, INTELLIGENCE_VALIDATION_LIMITS.maximumUrlLength)
  ) {
    return false;
  }
  try {
    const parsed = new URL(value);
    return (
      parsed.protocol === "https:" &&
      parsed.hostname.length > 0 &&
      parsed.username.length === 0 &&
      parsed.password.length === 0
    );
  } catch {
    return false;
  }
}

function isUniqueStringArray(
  value: unknown,
  maximumItems: number,
  maximumLength: number,
  validator: (item: unknown, maximumLength: number) => item is string =
    isInlineString,
): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= maximumItems &&
    value.every((item) => validator(item, maximumLength)) &&
    new Set(value).size === value.length
  );
}

function isOptionalTimestamp(value: unknown): value is string | undefined {
  return value === undefined || isTimestamp(value);
}

function isOptionalInlineString(
  value: unknown,
  maximumLength: number,
): value is string | undefined {
  return value === undefined || isInlineString(value, maximumLength);
}

function isOptionalText(
  value: unknown,
  maximumLength: number,
): value is string | undefined {
  return value === undefined || isText(value, maximumLength);
}

function isPackageCoordinate(value: unknown): value is PackageCoordinate {
  const limits = INTELLIGENCE_VALIDATION_LIMITS;
  return (
    isRecord(value) &&
    hasOnlyKeys(value, new Set(["ecosystem", "packageName", "installedVersion"])) &&
    isInlineString(value.ecosystem, limits.maximumEcosystemLength) &&
    isInlineString(value.packageName, limits.maximumPackageNameLength) &&
    isInlineString(value.installedVersion, limits.maximumVersionLength)
  );
}

export function isAdvisoryEvidence(value: unknown): value is AdvisoryEvidence {
  const limits = INTELLIGENCE_VALIDATION_LIMITS;
  return (
    isRecord(value) &&
    hasOnlyKeys(
      value,
      new Set([
        "provider",
        "advisoryId",
        "field",
        "value",
        "timestamp",
        "reference",
      ]),
    ) &&
    isInlineString(value.provider, limits.maximumProviderLength) &&
    isInlineString(value.advisoryId, limits.maximumAdvisoryIdLength) &&
    typeof value.field === "string" &&
    EVIDENCE_FIELDS.has(value.field as EvidenceField) &&
    isText(value.value, limits.maximumEvidenceValueLength) &&
    value.value.length > 0 &&
    isOptionalTimestamp(value.timestamp) &&
    (value.reference === undefined || isHttpsUrl(value.reference))
  );
}

function isSeverityDetail(value: unknown): value is AdvisorySeverityDetail {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, new Set(["type", "score", "source"])) &&
    isInlineString(value.type, 64) &&
    isInlineString(value.score, 2_048) &&
    isOptionalInlineString(value.source, 256)
  );
}

function isSourceError(value: unknown): value is IntelligenceSourceError {
  const limits = INTELLIGENCE_VALIDATION_LIMITS;
  return (
    isRecord(value) &&
    hasOnlyKeys(value, new Set(["code", "message"])) &&
    isInlineString(value.code, limits.maximumErrorCodeLength) &&
    isText(value.message, limits.maximumErrorMessageLength) &&
    value.message.length > 0
  );
}

export function isAdvisoryObservation(
  value: unknown,
): value is AdvisoryObservation {
  if (!isRecord(value)) {
    return false;
  }
  const limits = INTELLIGENCE_VALIDATION_LIMITS;
  if (
    !hasOnlyKeys(
      value,
      new Set([
        "provider",
        "advisoryId",
        "aliases",
        "coordinate",
        "summary",
        "details",
        "severity",
        "cvssScore",
        "providerSeverity",
        "severityDetails",
        "affectedness",
        "affectedRanges",
        "fixedVersions",
        "advisoryStatus",
        "cwes",
        "publishedAt",
        "modifiedAt",
        "withdrawnAt",
        "references",
        "evidence",
      ]),
    ) ||
    !isInlineString(value.provider, limits.maximumProviderLength) ||
    !isInlineString(value.advisoryId, limits.maximumAdvisoryIdLength) ||
    !isUniqueStringArray(
      value.aliases,
      limits.maximumAliases,
      limits.maximumAdvisoryIdLength,
    ) ||
    (value.aliases as string[]).includes(value.advisoryId as string) ||
    !isPackageCoordinate(value.coordinate) ||
    !isText(value.summary, limits.maximumSummaryLength) ||
    !isOptionalText(value.details, limits.maximumDetailsLength) ||
    typeof value.severity !== "string" ||
    !SEVERITIES.has(value.severity as IntelligenceSeverity) ||
    (value.cvssScore !== undefined &&
      (typeof value.cvssScore !== "number" ||
        !Number.isFinite(value.cvssScore) ||
        value.cvssScore < 0 ||
        value.cvssScore > 10)) ||
    !isOptionalInlineString(value.providerSeverity, 256) ||
    (value.severityDetails !== undefined &&
      (!Array.isArray(value.severityDetails) ||
        value.severityDetails.length > limits.maximumSeverityDetails ||
        !value.severityDetails.every(isSeverityDetail))) ||
    typeof value.affectedness !== "string" ||
    !AFFECTEDNESS.has(value.affectedness) ||
    (value.affectedRanges !== undefined &&
      !isUniqueStringArray(
        value.affectedRanges,
        limits.maximumAffectedRanges,
        limits.maximumAffectedRangeLength,
      )) ||
    (value.fixedVersions !== undefined &&
      !isUniqueStringArray(
        value.fixedVersions,
        limits.maximumFixedVersions,
        limits.maximumVersionLength,
      )) ||
    typeof value.advisoryStatus !== "string" ||
    !ADVISORY_STATUSES.has(value.advisoryStatus) ||
    (value.cwes !== undefined &&
      (!isUniqueStringArray(value.cwes, limits.maximumCwes, 32) ||
        !(value.cwes as string[]).every((cwe) => CWE_PATTERN.test(cwe)))) ||
    !isOptionalTimestamp(value.publishedAt) ||
    !isOptionalTimestamp(value.modifiedAt) ||
    !isOptionalTimestamp(value.withdrawnAt) ||
    !Array.isArray(value.references) ||
    value.references.length > limits.maximumReferences ||
    !value.references.every(isHttpsUrl) ||
    new Set(value.references).size !== value.references.length ||
    !Array.isArray(value.evidence) ||
    value.evidence.length > limits.maximumEvidencePerObservation ||
    !value.evidence.every(isAdvisoryEvidence)
  ) {
    return false;
  }
  if (
    value.advisoryStatus === "active" &&
    value.withdrawnAt !== undefined
  ) {
    return false;
  }
  if (
    value.withdrawnAt !== undefined &&
    value.advisoryStatus !== "withdrawn"
  ) {
    return false;
  }
  return (value.evidence as AdvisoryEvidence[]).every(
    (entry) =>
      entry.provider === value.provider &&
      entry.advisoryId === value.advisoryId,
  );
}

function observationIdentity(observation: AdvisoryObservation): string {
  return JSON.stringify([
    observation.provider,
    observation.advisoryId,
    observation.coordinate.ecosystem,
    observation.coordinate.packageName,
    observation.coordinate.installedVersion,
  ]);
}

export function isIntelligenceSourceResult(
  value: unknown,
): value is IntelligenceSourceResult {
  if (!isRecord(value)) {
    return false;
  }
  const limits = INTELLIGENCE_VALIDATION_LIMITS;
  if (
    !hasOnlyKeys(
      value,
      new Set([
        "source",
        "status",
        "freshness",
        "retrievedAt",
        "observations",
        "errors",
      ]),
    ) ||
    !isInlineString(value.source, limits.maximumProviderLength) ||
    typeof value.status !== "string" ||
    !SOURCE_STATUSES.has(value.status as IntelligenceSourceStatus) ||
    typeof value.freshness !== "string" ||
    !FRESHNESS_VALUES.has(value.freshness as IntelligenceFreshness) ||
    !isOptionalTimestamp(value.retrievedAt) ||
    ((value.freshness === "fresh" || value.freshness === "stale") &&
      value.retrievedAt === undefined) ||
    !Array.isArray(value.observations) ||
    value.observations.length > limits.maximumObservationsPerSource ||
    !value.observations.every(isAdvisoryObservation) ||
    !(value.observations as AdvisoryObservation[]).every(
      (observation) => observation.provider === value.source,
    ) ||
    !Array.isArray(value.errors) ||
    value.errors.length > limits.maximumSourceErrors ||
    !value.errors.every(isSourceError) ||
    (value.status === "available" && value.errors.length > 0) ||
    (value.status === "unavailable" && value.observations.length > 0)
  ) {
    return false;
  }
  const identities = (value.observations as AdvisoryObservation[]).map(
    observationIdentity,
  );
  return new Set(identities).size === identities.length;
}

export function assertAdvisoryObservation(
  value: unknown,
): asserts value is AdvisoryObservation {
  if (!isAdvisoryObservation(value)) {
    throw new IntelligenceValidationError(
      "Advisory observation failed bounded schema validation",
    );
  }
}

export function assertIntelligenceSourceResult(
  value: unknown,
): asserts value is IntelligenceSourceResult {
  if (!isIntelligenceSourceResult(value)) {
    throw new IntelligenceValidationError(
      "Intelligence source result failed bounded schema validation",
    );
  }
}
