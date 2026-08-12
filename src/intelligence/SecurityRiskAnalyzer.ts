import type { Severity, Vulnerability } from "../models/Vulnerability";

export type KnownExploitationStatus =
  | "known-exploited"
  | "not-known-exploited"
  | "unknown";

export type RiskReachabilityStatus =
  | "confirmed"
  | "likely"
  | "not-observed"
  | "unknown";

export interface KnownExploitationEvidence {
  readonly status: KnownExploitationStatus;
  /** A bounded label such as `CISA KEV`; it is evidence provenance, not proof. */
  readonly source?: string;
}

export interface RiskReachabilityEvidence {
  readonly status: RiskReachabilityStatus;
  readonly source?: string;
}

/** Optional evidence unavailable from the current OSV-only scan result. */
export interface SecurityRiskEnrichment {
  readonly knownExploitation?: KnownExploitationEvidence;
  readonly reachability?: RiskReachabilityEvidence;
}

export type SecurityRiskFactorId =
  | "severity"
  | "cvss"
  | "known-exploitation"
  | "reachability";

export type SecurityRiskEvidenceState = "observed" | "absent" | "unknown";

export interface SecurityRiskFactor {
  readonly id: SecurityRiskFactorId;
  readonly label: string;
  readonly evidenceState: SecurityRiskEvidenceState;
  readonly value: string;
  /** Points justified by observed evidence. Unknown evidence always adds zero. */
  readonly contribution: number;
  readonly maximumContribution: number;
  /** Unscored capacity retained as a range; it is not asserted risk. */
  readonly uncertainty: number;
  readonly reason: string;
  readonly source?: string;
}

export type SecurityRiskBand =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "UNKNOWN";

export type RiskEvidenceCompleteness = "complete" | "partial" | "unknown";

export interface SecurityRiskScore {
  readonly vulnerabilityKey: string;
  /** Minimum score supported by known evidence. */
  readonly score: number;
  /** Upper bound if every missing factor reached its defined maximum. */
  readonly maximumScore: number;
  readonly band: SecurityRiskBand;
  readonly maximumBand: SecurityRiskBand;
  readonly completeness: RiskEvidenceCompleteness;
  readonly missingEvidence: readonly SecurityRiskFactorId[];
  readonly factors: readonly SecurityRiskFactor[];
}

export interface SecurityRiskAnalysisOptions {
  readonly signal?: AbortSignal;
}

export interface SecurityRiskBatchOptions extends SecurityRiskAnalysisOptions {
  readonly maximumFindings?: number;
}

export interface SecurityRiskBatchResult {
  readonly scores: readonly SecurityRiskScore[];
  readonly processed: number;
  readonly total: number;
  readonly truncated: boolean;
  readonly cancelled: boolean;
  /** Processing completeness is separate from evidence completeness. */
  readonly analysisComplete: boolean;
  readonly evidenceComplete: boolean;
}

const HARD_MAXIMUM_FINDINGS = 50_000;
const MAXIMUM_SOURCE_LENGTH = 128;
const MAXIMUM_IDENTITY_LENGTH = 512;
const UNSAFE_TEXT =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/gu;

const SEVERITY_POINTS: Readonly<Record<Exclude<Severity, "UNKNOWN">, number>> =
  Object.freeze({
    LOW: 8,
    MEDIUM: 18,
    HIGH: 30,
    CRITICAL: 40,
  });

function boundedText(value: unknown, maximum: number): string | undefined {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    return undefined;
  }
  const sanitized = value.replace(UNSAFE_TEXT, "�");
  return sanitized.trim().length === 0 ? undefined : sanitized;
}

function source(value: unknown): string | undefined {
  return boundedText(value, MAXIMUM_SOURCE_LENGTH);
}

function vulnerabilityKey(vulnerability: Vulnerability): string {
  return JSON.stringify([
    boundedText(vulnerability.source, MAXIMUM_IDENTITY_LENGTH) ?? "UNKNOWN",
    boundedText(vulnerability.id, MAXIMUM_IDENTITY_LENGTH) ?? "UNKNOWN",
    boundedText(vulnerability.ecosystem, MAXIMUM_IDENTITY_LENGTH) ?? "UNKNOWN",
    boundedText(vulnerability.packageName, MAXIMUM_IDENTITY_LENGTH) ?? "UNKNOWN",
    boundedText(vulnerability.installedVersion, MAXIMUM_IDENTITY_LENGTH) ??
      "UNKNOWN",
  ]);
}

function freezeFactor(factor: SecurityRiskFactor): SecurityRiskFactor {
  return Object.freeze(factor);
}

function severityFactor(value: unknown): SecurityRiskFactor {
  if (
    value === "LOW" ||
    value === "MEDIUM" ||
    value === "HIGH" ||
    value === "CRITICAL"
  ) {
    const contribution = SEVERITY_POINTS[value];
    return freezeFactor({
      id: "severity",
      label: "Normalized severity",
      evidenceState: "observed",
      value,
      contribution,
      maximumContribution: 40,
      uncertainty: 0,
      reason: `${value} normalized severity contributes ${contribution.toString()} of 40 possible points.`,
    });
  }
  return freezeFactor({
    id: "severity",
    label: "Normalized severity",
    evidenceState: "unknown",
    value: "UNKNOWN",
    contribution: 0,
    maximumContribution: 40,
    uncertainty: 40,
    reason: "Normalized severity is unknown; no severity points were invented.",
  });
}

function cvssFactor(value: unknown): SecurityRiskFactor {
  if (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 10
  ) {
    const contribution = Math.round(value * 3);
    return freezeFactor({
      id: "cvss",
      label: "CVSS base score",
      evidenceState: "observed",
      value: value.toFixed(1),
      contribution,
      maximumContribution: 30,
      uncertainty: 0,
      reason: `CVSS ${value.toFixed(1)} contributes ${contribution.toString()} of 30 possible points.`,
    });
  }
  return freezeFactor({
    id: "cvss",
    label: "CVSS base score",
    evidenceState: "unknown",
    value: "UNKNOWN",
    contribution: 0,
    maximumContribution: 30,
    uncertainty: 30,
    reason: "A valid CVSS score is unavailable; no CVSS points were invented.",
  });
}

function knownExploitationFactor(
  evidence: KnownExploitationEvidence | undefined,
): SecurityRiskFactor {
  const evidenceSource = source(evidence?.source);
  if (evidence?.status === "known-exploited") {
    return freezeFactor({
      id: "known-exploitation",
      label: "Known exploitation",
      evidenceState: "observed",
      value: "KNOWN_EXPLOITED",
      contribution: 20,
      maximumContribution: 20,
      uncertainty: 0,
      reason: "Authoritative enrichment marks this vulnerability as known exploited.",
      ...(evidenceSource === undefined ? {} : { source: evidenceSource }),
    });
  }
  if (evidence?.status === "not-known-exploited") {
    return freezeFactor({
      id: "known-exploitation",
      label: "Known exploitation",
      evidenceState: "absent",
      value: "NOT_LISTED",
      contribution: 0,
      maximumContribution: 20,
      uncertainty: 0,
      reason:
        "The supplied evidence does not list known exploitation; this is not proof that exploitation is impossible.",
      ...(evidenceSource === undefined ? {} : { source: evidenceSource }),
    });
  }
  return freezeFactor({
    id: "known-exploitation",
    label: "Known exploitation",
    evidenceState: "unknown",
    value: "UNKNOWN",
    contribution: 0,
    maximumContribution: 20,
    uncertainty: 20,
    reason:
      "Known-exploitation evidence is unavailable; no exploitability points were invented.",
    ...(evidenceSource === undefined ? {} : { source: evidenceSource }),
  });
}

function reachabilityFactor(
  evidence: RiskReachabilityEvidence | undefined,
): SecurityRiskFactor {
  const evidenceSource = source(evidence?.source);
  if (evidence?.status === "confirmed") {
    return freezeFactor({
      id: "reachability",
      label: "Reachability",
      evidenceState: "observed",
      value: "CONFIRMED_REACHABLE",
      contribution: 10,
      maximumContribution: 10,
      uncertainty: 0,
      reason: "Available static evidence confirms a reachable dependency path.",
      ...(evidenceSource === undefined ? {} : { source: evidenceSource }),
    });
  }
  if (evidence?.status === "likely") {
    return freezeFactor({
      id: "reachability",
      label: "Reachability",
      evidenceState: "observed",
      value: "LIKELY_REACHABLE",
      contribution: 6,
      maximumContribution: 10,
      uncertainty: 0,
      reason: "Available static evidence indicates likely reachability.",
      ...(evidenceSource === undefined ? {} : { source: evidenceSource }),
    });
  }
  if (evidence?.status === "not-observed") {
    return freezeFactor({
      id: "reachability",
      label: "Reachability",
      evidenceState: "absent",
      value: "NOT_OBSERVED",
      contribution: 0,
      maximumContribution: 10,
      uncertainty: 0,
      reason:
        "Static analysis did not observe reachability; this is not a claim that the vulnerability is unreachable or not exploitable.",
      ...(evidenceSource === undefined ? {} : { source: evidenceSource }),
    });
  }
  return freezeFactor({
    id: "reachability",
    label: "Reachability",
    evidenceState: "unknown",
    value: "UNKNOWN",
    contribution: 0,
    maximumContribution: 10,
    uncertainty: 10,
    reason: "Reachability is unknown; no reachability points were invented.",
    ...(evidenceSource === undefined ? {} : { source: evidenceSource }),
  });
}

function riskBand(score: number, knownEvidence: boolean): SecurityRiskBand {
  if (!knownEvidence) {
    return "UNKNOWN";
  }
  if (score >= 80) {
    return "CRITICAL";
  }
  if (score >= 55) {
    return "HIGH";
  }
  if (score >= 25) {
    return "MEDIUM";
  }
  return "LOW";
}

function maximumFindings(value: number | undefined): number {
  const selected = value ?? HARD_MAXIMUM_FINDINGS;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > HARD_MAXIMUM_FINDINGS
  ) {
    throw new RangeError(
      `maximumFindings must be between 1 and ${HARD_MAXIMUM_FINDINGS.toString()}`,
    );
  }
  return selected;
}

export class SecurityRiskAnalysisCancelledError extends Error {
  public constructor() {
    super("Security risk analysis was cancelled");
    this.name = "SecurityRiskAnalysisCancelledError";
  }
}

export class SecurityRiskAnalyzer {
  public analyze(
    vulnerability: Vulnerability,
    enrichment: SecurityRiskEnrichment = {},
    options: SecurityRiskAnalysisOptions = {},
  ): SecurityRiskScore {
    if (options.signal?.aborted === true) {
      throw new SecurityRiskAnalysisCancelledError();
    }
    const factors = Object.freeze([
      severityFactor(vulnerability.severity),
      cvssFactor(vulnerability.cvssScore),
      knownExploitationFactor(enrichment.knownExploitation),
      reachabilityFactor(enrichment.reachability),
    ]);
    const score = factors.reduce(
      (total, factor) => total + factor.contribution,
      0,
    );
    const uncertainty = factors.reduce(
      (total, factor) => total + factor.uncertainty,
      0,
    );
    const missingEvidence = Object.freeze(
      factors
        .filter((factor) => factor.evidenceState === "unknown")
        .map((factor) => factor.id),
    );
    const knownEvidence = missingEvidence.length < factors.length;
    const completeness: RiskEvidenceCompleteness =
      missingEvidence.length === 0
        ? "complete"
        : knownEvidence
          ? "partial"
          : "unknown";
    return Object.freeze({
      vulnerabilityKey: vulnerabilityKey(vulnerability),
      score,
      maximumScore: Math.min(100, score + uncertainty),
      band: riskBand(score, knownEvidence),
      maximumBand: riskBand(Math.min(100, score + uncertainty), true),
      completeness,
      missingEvidence,
      factors,
    });
  }

  public analyzeMany(
    vulnerabilities: readonly Vulnerability[],
    enrichmentFor: (
      vulnerability: Vulnerability,
    ) => SecurityRiskEnrichment | undefined = () => undefined,
    options: SecurityRiskBatchOptions = {},
  ): SecurityRiskBatchResult {
    const limit = maximumFindings(options.maximumFindings);
    const scores: SecurityRiskScore[] = [];
    const selected = vulnerabilities.slice(0, limit);
    let cancelled = options.signal?.aborted === true;
    if (!cancelled) {
      for (const vulnerability of selected) {
        if (options.signal?.aborted === true) {
          cancelled = true;
          break;
        }
        const enrichment = enrichmentFor(vulnerability) ?? {};
        scores.push(this.analyze(vulnerability, enrichment));
      }
    }
    const truncated = selected.length < vulnerabilities.length;
    Object.freeze(scores);
    return Object.freeze({
      scores,
      processed: scores.length,
      total: vulnerabilities.length,
      truncated,
      cancelled,
      analysisComplete: !truncated && !cancelled,
      evidenceComplete:
        !truncated &&
        !cancelled &&
        scores.every((risk) => risk.completeness === "complete"),
    });
  }
}
