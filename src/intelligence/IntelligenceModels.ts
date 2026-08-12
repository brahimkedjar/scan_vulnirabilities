export type IntelligenceSeverity =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "UNKNOWN";

export type AdvisoryAffectedness = "affected" | "unaffected" | "unknown";

export type AdvisoryStatus = "active" | "withdrawn" | "unknown";

export type EvidenceField =
  | "identifier"
  | "summary"
  | "severity"
  | "cvss"
  | "affectedness"
  | "affected-range"
  | "fixed-version"
  | "advisory-status"
  | "cwe"
  | "published"
  | "modified"
  | "withdrawn"
  | "reference";

export interface PackageCoordinate {
  readonly ecosystem: string;
  readonly packageName: string;
  readonly installedVersion: string;
}

/** One bounded provider fact retained without resolving it against other facts. */
export interface AdvisoryEvidence {
  readonly provider: string;
  readonly advisoryId: string;
  readonly field: EvidenceField;
  readonly value: string;
  readonly timestamp?: string;
  readonly reference?: string;
}

export interface AdvisorySeverityDetail {
  readonly type: string;
  readonly score: string;
  readonly source?: string;
}

/**
 * One provider's observation for one exact installed package coordinate.
 * Omitted collection fields mean that the source supplied no usable evidence
 * for that field. An explicitly empty collection is retained as authoritative
 * evidence that the provider supplied no entries.
 */
export interface AdvisoryObservation {
  readonly provider: string;
  readonly advisoryId: string;
  readonly aliases: readonly string[];
  readonly coordinate: PackageCoordinate;
  readonly summary: string;
  readonly details?: string;
  readonly severity: IntelligenceSeverity;
  readonly cvssScore?: number;
  readonly providerSeverity?: string;
  readonly severityDetails?: readonly AdvisorySeverityDetail[];
  readonly affectedness: AdvisoryAffectedness;
  readonly affectedRanges?: readonly string[];
  readonly fixedVersions?: readonly string[];
  readonly advisoryStatus: AdvisoryStatus;
  readonly cwes?: readonly string[];
  readonly publishedAt?: string;
  readonly modifiedAt?: string;
  readonly withdrawnAt?: string;
  readonly references: readonly string[];
  readonly evidence: readonly AdvisoryEvidence[];
}

export type IntelligenceSourceStatus =
  | "available"
  | "partial"
  | "unavailable";

export type IntelligenceFreshness = "fresh" | "stale" | "unknown";

export interface IntelligenceSourceError {
  readonly code: string;
  readonly message: string;
}

/** A complete bounded result from one configured intelligence source. */
export interface IntelligenceSourceResult {
  readonly source: string;
  readonly status: IntelligenceSourceStatus;
  readonly freshness: IntelligenceFreshness;
  readonly retrievedAt?: string;
  readonly observations: readonly AdvisoryObservation[];
  readonly errors: readonly IntelligenceSourceError[];
}

export type IntelligenceConflictKind =
  | "severity"
  | "affectedness"
  | "affected-range"
  | "fixed-version"
  | "advisory-status";

/** One observation's side of a conflict; values are never reconciled here. */
export interface ConflictEvidence {
  readonly provider: string;
  readonly advisoryId: string;
  readonly values: readonly string[];
}

export interface IntelligenceConflict {
  readonly kind: IntelligenceConflictKind;
  readonly message: string;
  readonly evidence: readonly ConflictEvidence[];
}

export interface FindingProviderProvenance {
  readonly provider: string;
  readonly advisoryIds: readonly string[];
  readonly sourceStatus: IntelligenceSourceStatus;
  readonly freshness: IntelligenceFreshness;
  readonly retrievedAt?: string;
}

export type IntelligenceConfidenceLevel =
  | "high"
  | "medium"
  | "low"
  | "unknown";

export interface IntelligenceConfidence {
  readonly level: IntelligenceConfidenceLevel;
  readonly reasons: readonly string[];
}

export type EvidenceCompletenessStatus = "complete" | "partial";

export interface EvidenceCompleteness {
  readonly status: EvidenceCompletenessStatus;
  readonly missingFields: readonly EvidenceField[];
  readonly reasons: readonly string[];
}

/**
 * Alias-connected observations for one exact coordinate. `observed*` fields
 * are bounded unions for inspection only; they are not consensus values or
 * remediation recommendations. Consumers must inspect `conflicts`.
 */
export interface CanonicalFinding {
  readonly canonicalId: string;
  readonly aliases: readonly string[];
  readonly coordinate: PackageCoordinate;
  readonly observations: readonly AdvisoryObservation[];
  readonly evidence: readonly AdvisoryEvidence[];
  readonly providers: readonly FindingProviderProvenance[];
  readonly observedSeverities: readonly IntelligenceSeverity[];
  readonly observedAffectedness: readonly AdvisoryAffectedness[];
  readonly observedAdvisoryStatuses: readonly AdvisoryStatus[];
  readonly observedAffectedRanges: readonly string[];
  readonly observedFixedVersions: readonly string[];
  readonly observedCwes: readonly string[];
  readonly conflicts: readonly IntelligenceConflict[];
  readonly confidence: IntelligenceConfidence;
  readonly evidenceCompleteness: EvidenceCompleteness;
}

export type AggregationCompleteness = "complete" | "partial" | "unknown";

export interface VulnerabilityIntelligenceResult {
  readonly findings: readonly CanonicalFinding[];
  readonly sources: readonly IntelligenceSourceResult[];
  readonly conflictCount: number;
  readonly completeness: AggregationCompleteness;
}

export interface VulnerabilityIntelligenceAggregationOptions {
  readonly signal?: AbortSignal;
  readonly maximumSources?: number;
  readonly maximumObservations?: number;
  readonly maximumFindings?: number;
  readonly maximumIdentifierLinks?: number;
  readonly maximumEvidenceRecords?: number;
}
