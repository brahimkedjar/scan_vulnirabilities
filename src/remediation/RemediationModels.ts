import type { Dependency } from "../models/Dependency";

export type RemediationStrategy =
  | "upgrade-direct"
  | "upgrade-parent"
  | "upgrade-transitive"
  | "no-fixed-version"
  | "unresolved"
  | "manual-review";

export type RemediationConfidence = "high" | "medium" | "low";

export type BreakingChangeRisk = "unknown" | "low" | "medium" | "high";

export type RemediationEvidenceSource =
  | "osv"
  | "dependency-graph"
  | "lockfile"
  | "manifest";

export interface RemediationEvidence {
  readonly source: RemediationEvidenceSource;
  readonly description: string;
}

/**
 * One deterministic recommendation for one exact dependency occurrence.
 * `recommendedVersion`, when present, is an exact provider-listed version of
 * the vulnerable package. It is never an invented parent-package version.
 */
export interface RemediationRecommendation {
  /** Stable structural identity used by UI projections, not a display label. */
  readonly recommendationKey: string;
  /** Compatibility field for callers that display the first contributing ID. */
  readonly vulnerabilityId: string;
  readonly vulnerabilityIds: readonly string[];
  readonly dependency: Dependency;
  readonly currentVersion: string;
  readonly recommendedVersion?: string;
  readonly fixedVersions: readonly string[];
  readonly strategy: RemediationStrategy;
  readonly confidence: RemediationConfidence;
  readonly dependencyPath: readonly string[];
  readonly directDependency: boolean;
  readonly breakingChangeRisk: BreakingChangeRisk;
  readonly reason: string;
  readonly evidence: readonly RemediationEvidence[];
}

export interface RemediationAnalysisSummary {
  /** Vulnerability records stored in the analyzed ScanResult set. */
  readonly totalVulnerabilities: number;
  /** Records represented by recommendations with an exact calculated target. */
  readonly remediable: number;
  readonly noKnownFix: number;
  readonly manualReview: number;
  readonly unresolved: number;
  /** `remediable / totalVulnerabilities`, never a claim that files were fixed. */
  readonly remediationCoveragePercent: number;
  /** False when cancellation or a configured analysis bound stopped the pass. */
  readonly analysisComplete: boolean;
}

export interface RemediationAnalysisResult {
  readonly recommendations: readonly RemediationRecommendation[];
  readonly remediable: readonly RemediationRecommendation[];
  readonly noFix: readonly RemediationRecommendation[];
  readonly manualReview: readonly RemediationRecommendation[];
  readonly unresolved: readonly RemediationRecommendation[];
  readonly summary: RemediationAnalysisSummary;
}

export interface RemediationAnalysisOptions {
  readonly signal?: AbortSignal;
  /** Testable lower bound; production remains capped by the hard limit. */
  readonly maximumDependencyOccurrences?: number;
  /** Testable lower bound; production remains capped by the hard limit. */
  readonly maximumVulnerabilityRecords?: number;
  /**
   * Testable lower bound for vulnerability-to-occurrence links. This prevents
   * otherwise bounded input arrays from producing an unbounded Cartesian
   * product when many findings match many duplicate dependency occurrences.
   */
  readonly maximumFindingOccurrenceAssociations?: number;
}
