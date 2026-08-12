import type { Severity } from "../models/Vulnerability";

/** Outcomes are ordered from least to most restrictive: PASS, WARN, FAIL. */
export type SecurityGateStatus = "PASS" | "WARN" | "FAIL";

export type PolicyScanCoverage =
  | "not-scanned"
  | "complete"
  | "partial"
  | "unavailable"
  | "cancelled";

/**
 * Selectors use exact canonical ecosystem and package names. A string selector
 * matches a package name in every ecosystem; an object can scope that name.
 */
export type PolicyPackageSelector =
  | string
  | {
      readonly name: string;
      readonly ecosystem?: string;
    };

export interface IgnoredAdvisoryPolicy {
  /** Matches either a finding's canonical ID or one of its aliases. */
  readonly id: string;
  /** Required RFC 3339 UTC expiration. At the exact instant, the ignore expires. */
  readonly expiresAt: string;
  readonly reason?: string;
}

/**
 * The first bounded workspace-settings policy subset. Fields not represented
 * here (including licenses and provenance) are not evaluated or claimed.
 */
export interface SecurityPolicy {
  readonly schemaVersion?: 1;
  readonly maxCritical?: number;
  readonly maxHigh?: number;
  /** Findings at or above this normalized severity fail the gate. */
  readonly minimumSeverity?: Severity;
  /** Findings at or above this CVSS score fail the gate. */
  readonly minimumCvss?: number;
  /**
   * When enabled, every non-ignored finding needs explicit, current
   * known-exploitation evidence. Listed or unknown evidence fails closed.
   */
  readonly requireKnownExploitedAbsent?: boolean;
  readonly allowedEcosystems?: readonly string[];
  /** A blocked selector always wins over an allowed selector. */
  readonly blockedPackages?: readonly PolicyPackageSelector[];
  /** When non-empty, dependencies not matching this allowlist fail. */
  readonly allowedPackages?: readonly PolicyPackageSelector[];
  readonly ignoredAdvisories?: readonly IgnoredAdvisoryPolicy[];
}

export type PolicyKnownExploitationStatus =
  | "known-exploited"
  | "not-known-exploited"
  | "unknown";

/** Optional enrichment is joined to a finding by its exact identity. */
export interface PolicyFindingIntelligence {
  readonly advisoryId: string;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly installedVersion: string;
  readonly knownExploitation: PolicyKnownExploitationStatus;
}

export type PolicyReasonCode =
  | "POLICY_INVALID"
  | "INPUT_INVALID"
  | "INTELLIGENCE_INVALID"
  | "INPUT_LIMIT_EXCEEDED"
  | "EVALUATION_CANCELLED"
  | "SCAN_NOT_AVAILABLE"
  | "SCAN_INCOMPLETE"
  | "HIDDEN_FINDINGS"
  | "CRITICAL_LIMIT_EXCEEDED"
  | "HIGH_LIMIT_EXCEEDED"
  | "SEVERITY_THRESHOLD_EXCEEDED"
  | "SEVERITY_UNKNOWN"
  | "CVSS_THRESHOLD_EXCEEDED"
  | "CVSS_UNKNOWN"
  | "KNOWN_EXPLOITED"
  | "KNOWN_EXPLOITATION_UNKNOWN"
  | "ECOSYSTEM_NOT_ALLOWED"
  | "PACKAGE_BLOCKED"
  | "PACKAGE_NOT_ALLOWED"
  | "ADVISORY_IGNORE_EXPIRED";

export interface PolicyReason {
  readonly code: PolicyReasonCode;
  readonly disposition: "WARN" | "FAIL";
  readonly message: string;
  readonly advisoryId?: string;
  readonly ecosystem?: string;
  readonly packageName?: string;
  readonly installedVersion?: string;
  readonly actual?: number;
  readonly limit?: number;
}

export interface SecurityGateSummary {
  readonly dependenciesEvaluated: number;
  readonly findingsEvaluated: number;
  readonly ignoredFindings: number;
  readonly criticalFindings: number;
  readonly highFindings: number;
  /** Provider-reported records unavailable to the policy evaluator. */
  readonly hiddenFindings: number;
}

export interface SecurityGateResult {
  readonly status: SecurityGateStatus;
  /** False for invalid input, incomplete evidence, cancellation, or limits. */
  readonly complete: boolean;
  readonly cancelled: boolean;
  readonly policyValid: boolean;
  readonly coverage: PolicyScanCoverage;
  readonly evaluatedAt: string;
  readonly reasons: readonly PolicyReason[];
  readonly summary: SecurityGateSummary;
}

export interface SecurityPolicyEvaluationContext {
  /**
   * Pass the latest-attempt coverage when evaluating a ScanResultStore
   * snapshot. If omitted, coverage is conservatively derived from the input.
   */
  readonly coverage?: PolicyScanCoverage;
  readonly findingIntelligence?: readonly PolicyFindingIntelligence[];
  readonly signal?: AbortSignal;
}

export interface SecurityPolicyEngineOptions {
  readonly clock?: () => number;
  readonly maximumResults?: number;
  readonly maximumDependencies?: number;
  readonly maximumFindings?: number;
  readonly maximumPolicyEntries?: number;
  readonly maximumReasons?: number;
}
