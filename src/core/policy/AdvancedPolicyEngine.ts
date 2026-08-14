import type { LicenseInventory } from "../license/LicenseIntelligence";
import type { ProvenanceAnalysisResult } from "../provenance/ProvenanceIntelligence";
import type { StaticReachabilityResult } from "../reachability/StaticReachability";
import {
  scanResultKnownVulnerabilities,
  type ScanResult,
} from "../../models/ScanResult";
import type { Severity, Vulnerability } from "../../models/Vulnerability";
import {
  SecurityPolicyEngine,
  type PolicyFindingIntelligence,
  type PolicyScanCoverage,
  type SecurityGateResult,
  type SecurityPolicy,
} from "../../policy";
import { classifyScanCoverage } from "../../services/ScanResultStore";

export type AdvancedPolicyStatus = "PASS" | "WARN" | "FAIL";
export type UnknownEvidenceDisposition = "allow" | "warn" | "fail";
export type ProviderConfidence = "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface AdvancedSecurityPolicy {
  readonly schemaVersion: 1;
  readonly vulnerability?: SecurityPolicy;
  readonly requireCompleteCoverage?: boolean;
  readonly minimumCoveragePercent?: number;
  readonly failOnKnownExploited?: boolean;
  readonly minimumReachableSeverity?: Severity;
  readonly unknownReachability?: UnknownEvidenceDisposition;
  readonly failOnDeniedLicense?: boolean;
  readonly reviewRequiredLicense?: UnknownEvidenceDisposition;
  readonly unknownLicense?: UnknownEvidenceDisposition;
  readonly failOnSuspiciousProvenance?: boolean;
  readonly unknownProvenance?: UnknownEvidenceDisposition;
  readonly failOnAnomalySignals?: readonly string[];
  readonly deniedDependencyTypes?: readonly ("direct" | "transitive")[];
  readonly deniedEnvironments?: readonly (
    | "production"
    | "development"
    | "optional"
    | "peer"
  )[];
  readonly deniedPackageManagers?: readonly string[];
  readonly deniedEcosystems?: readonly string[];
  readonly minimumProviderConfidence?: Exclude<ProviderConfidence, "UNKNOWN">;
  /** No EPSS provider is connected; requiring it always fails closed today. */
  readonly requireEpssEvidence?: boolean;
}

export interface AdvancedPolicyEvaluationContext {
  readonly coverage?: PolicyScanCoverage;
  readonly findingIntelligence?: readonly PolicyFindingIntelligence[];
  readonly licenses?: LicenseInventory;
  readonly provenance?: ProvenanceAnalysisResult;
  readonly reachability?: StaticReachabilityResult;
  readonly providerConfidence?: ProviderConfidence;
  readonly signal?: AbortSignal;
}

export type AdvancedPolicyReasonCode =
  | "POLICY_INVALID"
  | "SCAN_INCOMPLETE"
  | "COVERAGE_BELOW_THRESHOLD"
  | "KNOWN_EXPLOITED"
  | "KNOWN_EXPLOITATION_UNKNOWN"
  | "REACHABLE_VULNERABILITY"
  | "REACHABILITY_UNKNOWN"
  | "LICENSE_DENIED"
  | "LICENSE_REVIEW_REQUIRED"
  | "LICENSE_UNKNOWN"
  | "PROVENANCE_SUSPICIOUS"
  | "PROVENANCE_UNKNOWN"
  | "SUPPLY_CHAIN_ANOMALY"
  | "DEPENDENCY_TYPE_DENIED"
  | "ENVIRONMENT_DENIED"
  | "PACKAGE_MANAGER_DENIED"
  | "ECOSYSTEM_DENIED"
  | "PROVIDER_CONFIDENCE_INSUFFICIENT"
  | "EPSS_NOT_CONFIGURED"
  | "EVIDENCE_LIMIT_EXCEEDED"
  | "EVALUATION_CANCELLED";

export interface AdvancedPolicyReason {
  readonly code: AdvancedPolicyReasonCode;
  readonly disposition: "WARN" | "FAIL";
  readonly message: string;
  readonly findingKey?: string;
  readonly packageName?: string;
  readonly ecosystem?: string;
  readonly actual?: number;
  readonly limit?: number;
}

export interface AdvancedPolicySummary {
  readonly dependenciesEvaluated: number;
  readonly findingsEvaluated: number;
  readonly coveragePercent: number;
  readonly knownExploited: number;
  readonly reachableFindings: number;
  readonly deniedLicenses: number;
  readonly suspiciousProvenance: number;
  readonly anomalySignals: number;
}

export interface AdvancedPolicyResult {
  readonly status: AdvancedPolicyStatus;
  readonly complete: boolean;
  readonly policyValid: boolean;
  readonly cancelled: boolean;
  readonly evaluatedAt: string;
  readonly base: SecurityGateResult;
  readonly reasons: readonly AdvancedPolicyReason[];
  readonly summary: AdvancedPolicySummary;
}

export interface AdvancedPolicyEngineOptions {
  readonly clock?: () => number;
  readonly maximumDependencies?: number;
  readonly maximumFindings?: number;
  readonly maximumEvidenceRecords?: number;
  readonly maximumReasons?: number;
}

const HARD_MAXIMUM_DEPENDENCIES = 100_000;
const HARD_MAXIMUM_FINDINGS = 100_000;
const HARD_MAXIMUM_EVIDENCE = 100_000;
const HARD_MAXIMUM_REASONS = 50_000;
const MAXIMUM_POLICY_ITEMS = 2_000;
const MAXIMUM_POLICY_TEXT = 512;
const UNSAFE_TEXT =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u;
const SEVERITY_RANK: Readonly<Record<Severity, number>> = Object.freeze({
  UNKNOWN: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
});
const CONFIDENCE_RANK: Readonly<Record<ProviderConfidence, number>> =
  Object.freeze({ UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 3 });
const POLICY_KEYS = new Set([
  "schemaVersion",
  "vulnerability",
  "requireCompleteCoverage",
  "minimumCoveragePercent",
  "failOnKnownExploited",
  "minimumReachableSeverity",
  "unknownReachability",
  "failOnDeniedLicense",
  "reviewRequiredLicense",
  "unknownLicense",
  "failOnSuspiciousProvenance",
  "unknownProvenance",
  "failOnAnomalySignals",
  "deniedDependencyTypes",
  "deniedEnvironments",
  "deniedPackageManagers",
  "deniedEcosystems",
  "minimumProviderConfidence",
  "requireEpssEvidence",
]);

function boundedOption(
  value: number | undefined,
  fallback: number,
  hardMaximum: number,
  label: string,
): number {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > hardMaximum) {
    throw new RangeError(`${label} is outside the supported safety range`);
  }
  return selected;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeText(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAXIMUM_POLICY_TEXT &&
    value.trim() === value &&
    !UNSAFE_TEXT.test(value)
  );
}

function validArray(
  value: unknown,
  allowed?: ReadonlySet<string>,
): value is readonly string[] {
  return (
    value === undefined ||
    (Array.isArray(value) &&
      value.length <= MAXIMUM_POLICY_ITEMS &&
      value.every(
        (entry) => safeText(entry) && (allowed === undefined || allowed.has(entry)),
      ))
  );
}

function validBoolean(value: unknown): boolean {
  return value === undefined || typeof value === "boolean";
}

function validDisposition(value: unknown): boolean {
  return value === undefined || value === "allow" || value === "warn" || value === "fail";
}

function validPolicy(value: unknown): value is AdvancedSecurityPolicy {
  if (
    !isRecord(value) ||
    value.schemaVersion !== 1 ||
    !Object.keys(value).every((key) => POLICY_KEYS.has(key)) ||
    !validBoolean(value.requireCompleteCoverage) ||
    !validBoolean(value.failOnKnownExploited) ||
    !validBoolean(value.failOnDeniedLicense) ||
    !validBoolean(value.failOnSuspiciousProvenance) ||
    !validBoolean(value.requireEpssEvidence) ||
    !validDisposition(value.unknownReachability) ||
    !validDisposition(value.reviewRequiredLicense) ||
    !validDisposition(value.unknownLicense) ||
    !validDisposition(value.unknownProvenance)
  ) {
    return false;
  }
  if (
    value.minimumCoveragePercent !== undefined &&
    (typeof value.minimumCoveragePercent !== "number" ||
      !Number.isFinite(value.minimumCoveragePercent) ||
      value.minimumCoveragePercent < 0 ||
      value.minimumCoveragePercent > 100)
  ) {
    return false;
  }
  if (
    value.minimumReachableSeverity !== undefined &&
    (typeof value.minimumReachableSeverity !== "string" ||
      !Object.prototype.hasOwnProperty.call(
        SEVERITY_RANK,
        value.minimumReachableSeverity,
      ))
  ) {
    return false;
  }
  if (
    value.minimumProviderConfidence !== undefined &&
    value.minimumProviderConfidence !== "LOW" &&
    value.minimumProviderConfidence !== "MEDIUM" &&
    value.minimumProviderConfidence !== "HIGH"
  ) {
    return false;
  }
  return (
    validArray(value.failOnAnomalySignals) &&
    validArray(value.deniedDependencyTypes, new Set(["direct", "transitive"])) &&
    validArray(
      value.deniedEnvironments,
      new Set(["production", "development", "optional", "peer"]),
    ) &&
    validArray(value.deniedPackageManagers) &&
    validArray(value.deniedEcosystems)
  );
}

export function advancedPolicyFindingKey(
  finding: Pick<
    Vulnerability,
    "source" | "id" | "ecosystem" | "packageName" | "installedVersion"
  >,
): string {
  return JSON.stringify([
    finding.source,
    finding.id,
    finding.ecosystem,
    finding.packageName,
    finding.installedVersion,
  ]);
}

function coverageFromResults(
  results: readonly ScanResult[],
  explicit: PolicyScanCoverage | undefined,
): PolicyScanCoverage {
  if (explicit !== undefined) {
    return explicit;
  }
  return classifyScanCoverage(results);
}

function coveragePercent(results: readonly ScanResult[]): number {
  let discovered = 0;
  let checked = 0;
  let hasCoverage = false;
  for (const result of results) {
    for (const coverage of result.ecosystemCoverage ?? result.projectCoverage ?? []) {
      hasCoverage = true;
      discovered += Math.max(0, coverage.discovered);
      checked += Math.max(0, Math.min(coverage.checked, coverage.discovered));
    }
  }
  if (!hasCoverage) {
    return results.every((result) => result.dependenciesScanned === 0) ? 100 : 0;
  }
  return discovered === 0 ? 100 : Math.max(0, Math.min(100, (checked / discovered) * 100));
}

function resultStatus(
  base: SecurityGateResult,
  reasons: readonly AdvancedPolicyReason[],
): AdvancedPolicyStatus {
  if (base.status === "FAIL" || reasons.some((reason) => reason.disposition === "FAIL")) {
    return "FAIL";
  }
  if (base.status === "WARN" || reasons.some((reason) => reason.disposition === "WARN")) {
    return "WARN";
  }
  return "PASS";
}

function disposition(
  value: UnknownEvidenceDisposition | undefined,
  fallback: UnknownEvidenceDisposition,
): "WARN" | "FAIL" | undefined {
  const selected = value ?? fallback;
  return selected === "allow" ? undefined : selected === "warn" ? "WARN" : "FAIL";
}

export class AdvancedPolicyEngine {
  private readonly clock: () => number;
  private readonly maximumDependencies: number;
  private readonly maximumFindings: number;
  private readonly maximumEvidence: number;
  private readonly maximumReasons: number;
  private readonly baseEngine: SecurityPolicyEngine;

  public constructor(options: AdvancedPolicyEngineOptions = {}) {
    this.clock = options.clock ?? Date.now;
    this.maximumDependencies = boundedOption(
      options.maximumDependencies,
      10_000,
      HARD_MAXIMUM_DEPENDENCIES,
      "maximumDependencies",
    );
    this.maximumFindings = boundedOption(
      options.maximumFindings,
      50_000,
      HARD_MAXIMUM_FINDINGS,
      "maximumFindings",
    );
    this.maximumEvidence = boundedOption(
      options.maximumEvidenceRecords,
      50_000,
      HARD_MAXIMUM_EVIDENCE,
      "maximumEvidenceRecords",
    );
    this.maximumReasons = boundedOption(
      options.maximumReasons,
      20_000,
      HARD_MAXIMUM_REASONS,
      "maximumReasons",
    );
    this.baseEngine = new SecurityPolicyEngine({
      clock: this.clock,
      maximumDependencies: Math.min(this.maximumDependencies, 10_000),
      maximumFindings: Math.min(this.maximumFindings, 50_000),
    });
  }

  public evaluate(
    results: readonly ScanResult[],
    policyValue: AdvancedSecurityPolicy | unknown,
    context: AdvancedPolicyEvaluationContext = {},
  ): AdvancedPolicyResult {
    const evaluatedAt = new Date(this.clock()).toISOString();
    const coverage = coverageFromResults(results, context.coverage);
    const base = this.baseEngine.evaluate(
      results,
      isRecord(policyValue) && isRecord(policyValue.vulnerability)
        ? policyValue.vulnerability
        : {},
      {
        coverage,
        ...(context.findingIntelligence === undefined
          ? {}
          : { findingIntelligence: context.findingIntelligence }),
        ...(context.signal === undefined ? {} : { signal: context.signal }),
      },
    );
    const reasons: AdvancedPolicyReason[] = [];
    let reasonsOmitted = false;
    let knownExploited = 0;
    let reachable = 0;
    let deniedLicenses = 0;
    let suspiciousProvenance = 0;
    let anomalySignals = 0;
    let dependencyCount = 0;
    const findings: Vulnerability[] = [];
    for (const result of results) {
      dependencyCount = Math.min(
        this.maximumDependencies + 1,
        dependencyCount + result.dependencies.length,
      );
      for (const finding of scanResultKnownVulnerabilities(result)) {
        if (findings.length > this.maximumFindings) {
          break;
        }
        findings.push(finding);
      }
    }
    const percent = coveragePercent(results);
    const add = (reason: AdvancedPolicyReason): void => {
      if (reasons.length < this.maximumReasons) {
        reasons.push(Object.freeze(reason));
      } else {
        reasonsOmitted = true;
      }
    };
    if (context.signal?.aborted === true) {
      add({
        code: "EVALUATION_CANCELLED",
        disposition: "FAIL",
        message: "Advanced policy evaluation was cancelled and failed closed.",
      });
    }
    if (!validPolicy(policyValue)) {
      add({
        code: "POLICY_INVALID",
        disposition: "FAIL",
        message: "Advanced policy is invalid, contradictory, or outside its safety bounds.",
      });
    } else if (
      dependencyCount > this.maximumDependencies ||
      findings.length > this.maximumFindings
    ) {
      add({
        code: "EVIDENCE_LIMIT_EXCEEDED",
        disposition: "FAIL",
        message: "Advanced policy input exceeds the configured evaluation limit.",
      });
    } else {
      const policy = policyValue;
      const evidenceCount =
        (context.findingIntelligence?.length ?? 0) +
        (context.licenses?.entries.length ?? 0) +
        (context.provenance?.packages.length ?? 0) +
        (context.provenance?.anomalies.length ?? 0) +
        (context.reachability?.findings.length ?? 0);
      if (evidenceCount > this.maximumEvidence) {
        add({
          code: "EVIDENCE_LIMIT_EXCEEDED",
          disposition: "FAIL",
          message: "Advanced policy evidence exceeds the configured limit.",
        });
      }
      if (policy.requireCompleteCoverage === true && coverage !== "complete") {
        add({
          code: "SCAN_INCOMPLETE",
          disposition: "FAIL",
          message: "Policy requires complete scan coverage, but current evidence is incomplete.",
        });
      }
      if (
        policy.minimumCoveragePercent !== undefined &&
        percent < policy.minimumCoveragePercent
      ) {
        add({
          code: "COVERAGE_BELOW_THRESHOLD",
          disposition: "FAIL",
          message: "Dependency coverage is below the configured minimum.",
          actual: percent,
          limit: policy.minimumCoveragePercent,
        });
      }
      const intelligenceByKey = new Map<string, PolicyFindingIntelligence>();
      for (const entry of (context.findingIntelligence ?? []).slice(0, this.maximumEvidence)) {
        intelligenceByKey.set(
          JSON.stringify([
            entry.advisoryId,
            entry.ecosystem,
            entry.packageName,
            entry.installedVersion,
          ]),
          entry,
        );
      }
      if (policy.failOnKnownExploited === true) {
        for (const finding of findings) {
          const exact = intelligenceByKey.get(
            JSON.stringify([
              finding.id,
              finding.ecosystem,
              finding.packageName,
              finding.installedVersion,
            ]),
          );
          if (exact?.knownExploitation === "known-exploited") {
            knownExploited += 1;
            add({
              code: "KNOWN_EXPLOITED",
              disposition: "FAIL",
              message: "A finding has current authoritative known-exploitation evidence.",
              findingKey: advancedPolicyFindingKey(finding),
              packageName: finding.packageName,
              ecosystem: finding.ecosystem,
            });
          } else if (exact?.knownExploitation !== "not-known-exploited") {
            add({
              code: "KNOWN_EXPLOITATION_UNKNOWN",
              disposition: "FAIL",
              message: "Known-exploitation evidence is absent, stale, or unknown.",
              findingKey: advancedPolicyFindingKey(finding),
              packageName: finding.packageName,
              ecosystem: finding.ecosystem,
            });
          }
        }
      }
      if (policy.minimumReachableSeverity !== undefined) {
        const reachabilityByTarget = new Map(
          (context.reachability?.findings ?? [])
            .slice(0, this.maximumEvidence)
            .map((entry) => [entry.targetId, entry]),
        );
        for (const finding of findings) {
          if (SEVERITY_RANK[finding.severity] < SEVERITY_RANK[policy.minimumReachableSeverity]) {
            continue;
          }
          const key = advancedPolicyFindingKey(finding);
          const evidence = reachabilityByTarget.get(key);
          if (evidence?.status === "REACHABLE") {
            reachable += 1;
            add({
              code: "REACHABLE_VULNERABILITY",
              disposition: "FAIL",
              message: "Static analysis observed a bounded source path to a vulnerable dependency at or above the configured severity.",
              findingKey: key,
              packageName: finding.packageName,
              ecosystem: finding.ecosystem,
            });
          } else if (evidence?.status !== "NOT_OBSERVED" || context.reachability?.coverage.analysisComplete !== true) {
            const selected = disposition(policy.unknownReachability, "fail");
            if (selected !== undefined) {
              add({
                code: "REACHABILITY_UNKNOWN",
                disposition: selected,
                message: "Reachability is unknown; NOT_OBSERVED is never treated as proof of non-exploitability.",
                findingKey: key,
                packageName: finding.packageName,
                ecosystem: finding.ecosystem,
              });
            }
          }
        }
      }
      const licenseEvidenceCount = context.licenses?.entries.length ?? 0;
      if (licenseEvidenceCount > this.maximumEvidence) {
        add({
          code: "EVIDENCE_LIMIT_EXCEEDED",
          disposition: "FAIL",
          message: "License evidence exceeds the configured limit.",
        });
      } else if (
        policy.failOnDeniedLicense === true ||
        policy.reviewRequiredLicense !== undefined ||
        policy.unknownLicense !== undefined
      ) {
        if (context.licenses === undefined || !context.licenses.coverage.analysisComplete || !context.licenses.coverage.policyValid) {
          const selected = disposition(policy.unknownLicense, "fail");
          if (selected !== undefined) {
            add({
              code: "LICENSE_UNKNOWN",
              disposition: selected,
              message: "License evidence or license-policy evaluation is incomplete.",
            });
          }
        }
        for (const entry of (context.licenses?.entries ?? []).slice(0, this.maximumEvidence)) {
          if (entry.finding.outcome === "DENIED" && policy.failOnDeniedLicense === true) {
            deniedLicenses += 1;
            add({
              code: "LICENSE_DENIED",
              disposition: "FAIL",
              message: "Explicit dependency license metadata is denied by policy.",
              packageName: entry.name,
              ecosystem: entry.ecosystem,
            });
          } else if (entry.finding.outcome === "REVIEW_REQUIRED") {
            const selected = disposition(policy.reviewRequiredLicense, "warn");
            if (selected !== undefined) {
              add({
                code: "LICENSE_REVIEW_REQUIRED",
                disposition: selected,
                message: "Dependency license metadata requires review.",
                packageName: entry.name,
                ecosystem: entry.ecosystem,
              });
            }
          } else if (entry.finding.outcome === "UNKNOWN") {
            const selected = disposition(policy.unknownLicense, "fail");
            if (selected !== undefined) {
              add({
                code: "LICENSE_UNKNOWN",
                disposition: selected,
                message: "Dependency license metadata is unknown.",
                packageName: entry.name,
                ecosystem: entry.ecosystem,
              });
            }
          }
        }
      }
      const provenanceCount = context.provenance?.packages.length ?? 0;
      if (provenanceCount > this.maximumEvidence) {
        add({
          code: "EVIDENCE_LIMIT_EXCEEDED",
          disposition: "FAIL",
          message: "Provenance evidence exceeds the configured limit.",
        });
      } else if (
        policy.failOnSuspiciousProvenance === true ||
        policy.unknownProvenance !== undefined ||
        (policy.failOnAnomalySignals?.length ?? 0) > 0
      ) {
        if (context.provenance === undefined || !context.provenance.coverage.analysisComplete) {
          const selected = disposition(policy.unknownProvenance, "fail");
          if (selected !== undefined) {
            add({
              code: "PROVENANCE_UNKNOWN",
              disposition: selected,
              message: "Package provenance evidence is absent or incomplete.",
            });
          }
        }
        const configuredSignals = new Set(policy.failOnAnomalySignals ?? []);
        for (const entry of (context.provenance?.packages ?? []).slice(0, this.maximumEvidence)) {
          if (entry.status === "SUSPICIOUS" && policy.failOnSuspiciousProvenance === true) {
            suspiciousProvenance += 1;
            add({
              code: "PROVENANCE_SUSPICIOUS",
              disposition: "FAIL",
              message: "Evidence-supported package provenance signals require investigation.",
              packageName: entry.packageName,
              ecosystem: entry.ecosystem,
            });
          } else if (entry.status === "UNKNOWN") {
            const selected = disposition(policy.unknownProvenance, "fail");
            if (selected !== undefined) {
              add({
                code: "PROVENANCE_UNKNOWN",
                disposition: selected,
                message: "Package provenance is unknown.",
                packageName: entry.packageName,
                ecosystem: entry.ecosystem,
              });
            }
          }
          for (const anomaly of entry.anomalies) {
            if (configuredSignals.has(anomaly.signal)) {
              anomalySignals += 1;
              add({
                code: "SUPPLY_CHAIN_ANOMALY",
                disposition: "FAIL",
                message: "A configured evidence-supported supply-chain anomaly signal was observed; this is not a malware verdict.",
                packageName: entry.packageName,
                ecosystem: entry.ecosystem,
              });
            }
          }
        }
      }
      const deniedDependencyTypes = new Set(policy.deniedDependencyTypes ?? []);
      const deniedEnvironments = new Set(policy.deniedEnvironments ?? []);
      const deniedManagers = new Set(policy.deniedPackageManagers ?? []);
      const deniedEcosystems = new Set(policy.deniedEcosystems ?? []);
      for (const result of results) {
        for (const dependency of result.dependencies) {
          if (deniedDependencyTypes.has(dependency.dependencyType)) {
            add({
              code: "DEPENDENCY_TYPE_DENIED",
              disposition: "FAIL",
              message: "A dependency type is denied by policy.",
              packageName: dependency.name,
              ecosystem: dependency.ecosystem,
            });
          }
          if (deniedEnvironments.has(dependency.environment)) {
            add({
              code: "ENVIRONMENT_DENIED",
              disposition: "FAIL",
              message: "A dependency environment is denied by policy.",
              packageName: dependency.name,
              ecosystem: dependency.ecosystem,
            });
          }
          if (
            dependency.packageManager !== undefined &&
            deniedManagers.has(dependency.packageManager)
          ) {
            add({
              code: "PACKAGE_MANAGER_DENIED",
              disposition: "FAIL",
              message: "A package manager is denied by policy.",
              packageName: dependency.name,
              ecosystem: dependency.ecosystem,
            });
          }
          if (deniedEcosystems.has(dependency.ecosystem)) {
            add({
              code: "ECOSYSTEM_DENIED",
              disposition: "FAIL",
              message: "A dependency ecosystem is denied by policy.",
              packageName: dependency.name,
              ecosystem: dependency.ecosystem,
            });
          }
        }
      }
      if (
        policy.minimumProviderConfidence !== undefined &&
        CONFIDENCE_RANK[context.providerConfidence ?? "UNKNOWN"] <
          CONFIDENCE_RANK[policy.minimumProviderConfidence]
      ) {
        add({
          code: "PROVIDER_CONFIDENCE_INSUFFICIENT",
          disposition: "FAIL",
          message: "Provider confidence evidence is below the configured minimum or unavailable.",
        });
      }
      if (policy.requireEpssEvidence === true) {
        add({
          code: "EPSS_NOT_CONFIGURED",
          disposition: "FAIL",
          message: "No authoritative EPSS provider is configured; EPSS policy fails closed.",
        });
      }
    }
    if (reasonsOmitted) {
      reasons.splice(this.maximumReasons - 1, 1, Object.freeze({
        code: "EVIDENCE_LIMIT_EXCEEDED",
        disposition: "FAIL",
        message: "Advanced policy reasons exceeded the configured limit.",
      }));
    }
    const frozenReasons = Object.freeze(
      [...reasons].sort(
        (left, right) =>
          left.code.localeCompare(right.code, "en") ||
          (left.ecosystem ?? "").localeCompare(right.ecosystem ?? "", "en") ||
          (left.packageName ?? "").localeCompare(right.packageName ?? "", "en") ||
          (left.findingKey ?? "").localeCompare(right.findingKey ?? "", "en"),
      ),
    );
    const status = resultStatus(base, frozenReasons);
    const complete =
      status !== "FAIL" ||
      !frozenReasons.some((reason) =>
        reason.code === "SCAN_INCOMPLETE" ||
        reason.code.endsWith("UNKNOWN") ||
        reason.code === "EVIDENCE_LIMIT_EXCEEDED" ||
        reason.code === "EVALUATION_CANCELLED" ||
        reason.code === "POLICY_INVALID" ||
        reason.code === "EPSS_NOT_CONFIGURED",
      );
    return Object.freeze({
      status,
      complete: base.complete && complete,
      policyValid: validPolicy(policyValue) && base.policyValid,
      cancelled:
        context.signal?.aborted === true ||
        base.cancelled ||
        context.licenses?.coverage.cancelled === true ||
        context.provenance?.coverage.cancelled === true ||
        context.reachability?.coverage.cancelled === true,
      evaluatedAt,
      base,
      reasons: frozenReasons,
      summary: Object.freeze({
        dependenciesEvaluated: Math.min(dependencyCount, this.maximumDependencies),
        findingsEvaluated: Math.min(findings.length, this.maximumFindings),
        coveragePercent: Math.round(percent * 100) / 100,
        knownExploited,
        reachableFindings: reachable,
        deniedLicenses,
        suspiciousProvenance,
        anomalySignals,
      }),
    });
  }
}
