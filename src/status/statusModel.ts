import type { ScanResult } from "../models/ScanResult";
import type { RemediationAnalysisResult } from "../remediation/RemediationModels";
import type { RemediationApplySnapshot } from "../webview/webviewTypes";
import {
  type RetainedVulnerabilityFinding,
  type ScanCoverage,
  vulnerabilityFindingKey,
} from "../services/ScanResultStore";

export type DependencyStatusState =
  | "scanning"
  | "not-scanned"
  | "empty"
  | "clean"
  | "findings"
  | "incomplete";

export interface DependencyStatusModel {
  readonly state: DependencyStatusState;
  readonly text: string;
  readonly tooltip: string;
  readonly vulnerabilityCount: number;
  /** Kept separate from current vulnerability and coverage totals. */
  readonly retainedFindingCount: number;
  readonly suppressedVulnerabilityCount: number;
  readonly dependenciesScanned: number;
  readonly unresolvedCount: number;
  readonly coverageComplete: boolean;
}

export interface DependencyStatusOptions {
  readonly latestAttemptCoverage?: ScanCoverage;
  readonly retainedFindings?: readonly RetainedVulnerabilityFinding[];
  readonly retainedFindingsTruncated?: boolean;
  /** Analysis of current displayed findings only. */
  readonly remediationAnalysis?: RemediationAnalysisResult;
  /** Session-only Phase 5B operation and result summary. */
  readonly remediationApply?: RemediationApplySnapshot;
}

const COVERAGE_ERROR_CODES = new Set<string>([
  "NO_LOCKFILE",
  "INVALID_MANIFEST",
  "INVALID_LOCKFILE",
  "UNSUPPORTED_LOCKFILE",
  "UNSUPPORTED_PACKAGE_MANAGER",
  "UNSUPPORTED_PACKAGE_SOURCE",
  "UNSUPPORTED_PACKAGE_IDENTITY",
  "DEPENDENCY_UNRESOLVED",
  "DEPENDENCY_LIMIT",
  "UNSUPPORTED_VERSION",
  "PROVIDER_ERROR",
  "WORKSPACE_ERROR",
]);

function boundedSum(values: readonly number[]): number {
  let total = 0;
  for (const value of values) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      continue;
    }
    if (value > Number.MAX_SAFE_INTEGER - total) {
      return Number.MAX_SAFE_INTEGER;
    }
    total += value;
  }
  return total;
}

export function countSuppressedVulnerabilities(
  results: readonly ScanResult[],
): number {
  return boundedSum(
    results.map((result) => {
      const providerFindings = boundedSum(
        result.providerResults.map((provider) => provider.vulnerabilitiesFound),
      );
      return Math.max(0, providerFindings - result.vulnerabilities.length);
    }),
  );
}

function findingText(count: number, adjective = ""): string {
  const qualifier = adjective.length === 0 ? "" : `${adjective} `;
  return `${count.toString()} ${qualifier}${count === 1 ? "finding" : "findings"}`;
}

function countRetainedFindings(
  results: readonly ScanResult[],
  retainedFindings: readonly RetainedVulnerabilityFinding[],
): number {
  const currentKeys = new Set(
    results.flatMap((result) =>
      result.vulnerabilities.map(vulnerabilityFindingKey),
    ),
  );
  const retainedKeys = new Set<string>();
  for (const finding of retainedFindings) {
    const key = vulnerabilityFindingKey(finding.vulnerability);
    if (!currentKeys.has(key)) {
      retainedKeys.add(key);
    }
  }
  return retainedKeys.size;
}

function retainedFindingText(count: number, truncated: boolean): string {
  if (count === 0) {
    return truncated
      ? "additional last-complete findings not reconfirmed"
      : "";
  }
  return `${count.toString()} last-complete ${count === 1 ? "finding" : "findings"} not reconfirmed${truncated ? "; more omitted" : ""}`;
}

function remediationStatusText(
  vulnerabilityCount: number,
  analysis: RemediationAnalysisResult | undefined,
): { readonly suffix: string; readonly tooltip: string } {
  if (analysis === undefined || vulnerabilityCount === 0) {
    return { suffix: "", tooltip: "" };
  }
  const remediable = Math.min(
    vulnerabilityCount,
    boundedSum([analysis.summary.remediable]),
  );
  const manualReview = Math.min(
    vulnerabilityCount,
    boundedSum([analysis.summary.manualReview]),
  );
  if (remediable > 0) {
    return {
      suffix: ` · ${remediable.toString()} remediable`,
      tooltip: ` ${remediable.toString()} displayed ${remediable === 1 ? "finding has" : "findings have"} a calculated remediation candidate; no files have been changed.`,
    };
  }
  if (manualReview > 0) {
    return {
      suffix: ` · ${manualReview.toString()} manual review${manualReview === 1 ? "" : "s"}`,
      tooltip: ` ${manualReview.toString()} displayed ${manualReview === 1 ? "finding requires" : "findings require"} manual remediation review.`,
    };
  }
  return { suffix: "", tooltip: "" };
}

function sanitizeStatusText(value: string, maximumLength = 512): string {
  const bounded =
    value.length <= maximumLength
      ? value
      : `${value.slice(0, Math.max(0, maximumLength - 14))}… (truncated)`;
  return bounded.replace(
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/gu,
    "�",
  );
}

function remediationApplyStatusText(
  snapshot: RemediationApplySnapshot | undefined,
): { readonly suffix: string; readonly tooltip: string } | undefined {
  const operation = snapshot?.activeOperation;
  if (operation !== undefined) {
    const labels: Readonly<Record<typeof operation.stage, string>> = {
      previewing: "previewing remediation",
      "preview-ready": "remediation preview ready",
      applying: "applying remediation",
      validating: "validating remediation",
      rescanning: "rescanning remediation",
      "rolling-back": "rolling back remediation",
    };
    const label = labels[operation.stage];
    return {
      suffix: ` · ${label}`,
      tooltip: ` A user-initiated remediation is ${label}.${operation.message === undefined ? "" : ` ${sanitizeStatusText(operation.message)}`}`,
    };
  }
  const result = snapshot?.lastResult;
  if (result === undefined) {
    return undefined;
  }
  if (result.status === "successful") {
    const resolved = boundedSum([result.vulnerabilitiesResolved]);
    return {
      suffix: " · remediation succeeded",
      tooltip: ` The last explicitly approved remediation completed after validation and rescan; ${resolved.toString()} ${resolved === 1 ? "vulnerability was" : "vulnerabilities were"} resolved.`,
    };
  }
  if (result.status === "partial") {
    const remaining = boundedSum([result.vulnerabilitiesRemaining]);
    return {
      suffix: " · partial remediation",
      tooltip: ` The last explicitly approved remediation was partial; ${remaining.toString()} targeted ${remaining === 1 ? "vulnerability remains" : "vulnerabilities remain"}.`,
    };
  }
  if (result.status === "failed") {
    return {
      suffix: result.rolledBack
        ? " · remediation rolled back"
        : " · remediation failed",
      tooltip: ` The last remediation failed${result.rolledBack ? result.rollbackVerified === false ? "; rollback could not be fully verified" : " and was rolled back" : ""}. ${sanitizeStatusText(result.message)}`,
    };
  }
  return {
    suffix: " · remediation cancelled",
    tooltip: " The last remediation was cancelled; cancellation is not a successful fix.",
  };
}

export function scanCoverageIsComplete(
  results: readonly ScanResult[],
  latestAttemptCoverage?: ScanCoverage,
): boolean {
  if (results.length === 0) {
    return false;
  }

  if (
    latestAttemptCoverage !== undefined &&
    latestAttemptCoverage !== "complete"
  ) {
    return false;
  }

  return results.every((result) => {
    const coverageEntries =
      result.ecosystemCoverage ?? result.projectCoverage ?? [];
    if (
      result.cancelled ||
      result.errors.some((error) => COVERAGE_ERROR_CODES.has(error.code)) ||
      coverageEntries.some(
        (coverage) =>
          coverage.unresolved > 0 ||
          coverage.unsupported > 0 ||
          coverage.checked < coverage.resolved ||
          coverage.resolved + coverage.unresolved + coverage.unsupported <
            coverage.discovered,
      )
    ) {
      return false;
    }

    if (result.dependenciesScanned === 0) {
      return true;
    }

    if (result.providerResults.length === 0) {
      return false;
    }

    return result.providerResults.every(
      (provider) =>
        provider.status === "available" &&
        provider.failed === 0 &&
        provider.successful >= provider.dependenciesEligible,
    );
  });
}

export function buildDependencyStatusModel(
  results: readonly ScanResult[],
  scanning: boolean,
  options: DependencyStatusOptions = {},
): DependencyStatusModel {
  const vulnerabilityCount = boundedSum(
    results.map((result) => result.vulnerabilities.length),
  );
  const remediationStatus =
    remediationApplyStatusText(options.remediationApply) ??
    remediationStatusText(
      vulnerabilityCount,
      options.remediationAnalysis,
    );
  const retainedFindingCount = countRetainedFindings(
    results,
    options.retainedFindings ?? [],
  );
  const retainedSummary = retainedFindingText(
    retainedFindingCount,
    options.retainedFindingsTruncated === true,
  );
  const retainedTooltip =
    retainedSummary.length === 0
      ? ""
      : ` ${retainedSummary[0]?.toUpperCase() ?? ""}${retainedSummary.slice(1)}; this evidence is from the last complete scan and is not included in current coverage or dependency counts.`;
  const suppressedVulnerabilityCount =
    countSuppressedVulnerabilities(results);
  const dependenciesScanned = boundedSum(
    results.map((result) => result.dependenciesScanned),
  );
  const unresolvedCount = boundedSum(
    results.flatMap((result) =>
      (result.ecosystemCoverage ?? result.projectCoverage ?? []).map(
        (coverage) => coverage.unresolved + coverage.unsupported,
      ),
    ),
  );
  const phase4CoveragePresent = results.some(
    (result) =>
      result.ecosystemCoverage !== undefined ||
      result.projectCoverage !== undefined,
  );
  const coverageComplete = scanCoverageIsComplete(
    results,
    options.latestAttemptCoverage,
  );

  if (scanning) {
    return {
      state: "scanning",
      text: `$(shield) Scanning...${remediationStatus.suffix}`,
      tooltip: `Dependency Auditor is scanning resolved dependencies.${remediationStatus.tooltip}${retainedTooltip}`,
      vulnerabilityCount,
      retainedFindingCount,
      suppressedVulnerabilityCount,
      dependenciesScanned,
      unresolvedCount,
      coverageComplete: false,
    };
  }

  if (options.latestAttemptCoverage === "cancelled") {
    return {
      state: "incomplete",
      text: "$(shield) Dependencies: Scan cancelled",
      tooltip: `${
        results.length === 0
          ? "The dependency scan was cancelled before results were available."
          : "The latest dependency scan was cancelled; previously displayed results remain available."
      }${retainedTooltip}`,
      vulnerabilityCount,
      retainedFindingCount,
      suppressedVulnerabilityCount,
      dependenciesScanned,
      unresolvedCount,
      coverageComplete: false,
    };
  }

  if (results.length === 0 && retainedFindingCount === 0) {
    return {
      state: "not-scanned",
      text: "$(shield) Dependencies: Not scanned",
      tooltip: "Run Dependency Auditor to check resolved dependencies.",
      vulnerabilityCount: 0,
      retainedFindingCount: 0,
      suppressedVulnerabilityCount: 0,
      dependenciesScanned: 0,
      unresolvedCount: 0,
      coverageComplete: false,
    };
  }

  if (
    dependenciesScanned === 0 &&
    unresolvedCount === 0 &&
    coverageComplete &&
    retainedFindingCount === 0
  ) {
    return {
      state: "empty",
      text: "$(shield) Dependencies: None scanned",
      tooltip: "No supported resolved dependencies were found.",
      vulnerabilityCount,
      retainedFindingCount,
      suppressedVulnerabilityCount,
      dependenciesScanned,
      unresolvedCount,
      coverageComplete,
    };
  }

  if (!coverageComplete) {
    const visibleFindingText = findingText(vulnerabilityCount);
    const filteredFindingText = findingText(
      suppressedVulnerabilityCount,
      "filtered",
    );
    const latestUnavailable = options.latestAttemptCoverage === "unavailable";
    const baseTooltip =
      vulnerabilityCount === 0 && suppressedVulnerabilityCount === 0
        ? `${latestUnavailable ? "The latest vulnerability database check was unavailable. " : ""}Dependency scan coverage is incomplete${unresolvedCount === 0 ? "" : `; ${unresolvedCount.toString()} dependencies are unresolved or unsupported`}; zero current findings is not a clean result.`
        : `${visibleFindingText} displayed${suppressedVulnerabilityCount === 0 ? "" : `; ${filteredFindingText} hidden by the severity filter`}${unresolvedCount === 0 ? "" : `; ${unresolvedCount.toString()} dependencies unresolved or unsupported`}; ${latestUnavailable ? "the latest vulnerability database check was unavailable" : "dependency scan coverage is incomplete"}.`;
    return {
      state: "incomplete",
      text: (() => {
        const currentFindingSummary =
          vulnerabilityCount === 0 && suppressedVulnerabilityCount === 0
            ? "Scan incomplete"
            : vulnerabilityCount === 0
              ? filteredFindingText
              : suppressedVulnerabilityCount === 0
                ? visibleFindingText
                : `${visibleFindingText}, ${filteredFindingText}`;
        const findingSummary =
          retainedSummary.length === 0
            ? currentFindingSummary
            : `${currentFindingSummary}; ${retainedSummary}`;
        return `$(shield) Dependencies: ${findingSummary}${remediationStatus.suffix}${unresolvedCount === 0 ? "" : ` · ${unresolvedCount.toString()} unresolved`}`;
      })(),
      tooltip: `${baseTooltip}${remediationStatus.tooltip}${retainedTooltip}`,
      vulnerabilityCount,
      retainedFindingCount,
      suppressedVulnerabilityCount,
      dependenciesScanned,
      unresolvedCount,
      coverageComplete,
    };
  }

  if (suppressedVulnerabilityCount > 0) {
    const visibleFindingText = findingText(vulnerabilityCount);
    const filteredFindingText = findingText(
      suppressedVulnerabilityCount,
      "filtered",
    );
    return {
      state: "findings",
      text: `$(shield) Dependencies: ${vulnerabilityCount === 0 ? filteredFindingText : `${visibleFindingText}, ${filteredFindingText}`}${remediationStatus.suffix}`,
      tooltip: `${visibleFindingText} displayed; ${filteredFindingText} hidden by the severity filter.${remediationStatus.tooltip}`,
      vulnerabilityCount,
      retainedFindingCount,
      suppressedVulnerabilityCount,
      dependenciesScanned,
      unresolvedCount,
      coverageComplete,
    };
  }

  if (vulnerabilityCount === 0) {
    return {
      state: "clean",
      text: `$(shield) Dependencies: No known vulnerabilities${remediationStatus.suffix}`,
      tooltip: `No known vulnerabilities were reported for ${dependenciesScanned.toString()} audited dependencies. This is not a claim of overall application security.${remediationStatus.tooltip}`,
      vulnerabilityCount,
      retainedFindingCount,
      suppressedVulnerabilityCount,
      dependenciesScanned,
      unresolvedCount,
      coverageComplete,
    };
  }

  const vulnerabilityLabel =
    vulnerabilityCount === 1 ? "vulnerability" : "vulnerabilities";
  return {
    state: "findings",
    text: phase4CoveragePresent
      ? `$(shield) Dependencies: ${findingText(vulnerabilityCount)}${remediationStatus.suffix}`
      : `$(shield) Dependencies: ${vulnerabilityCount.toString()} ${vulnerabilityLabel}${remediationStatus.suffix}`,
    tooltip: `${vulnerabilityCount.toString()} known ${vulnerabilityLabel} reported in resolved dependencies.${remediationStatus.tooltip}`,
    vulnerabilityCount,
    retainedFindingCount,
    suppressedVulnerabilityCount,
    dependenciesScanned,
    unresolvedCount,
    coverageComplete,
  };
}
