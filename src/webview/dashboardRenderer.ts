import type { ProviderStatus, ScanResult } from "../models/ScanResult";
import type { Severity, Vulnerability } from "../models/Vulnerability";
import type { RemediationAnalysisResult } from "../remediation/RemediationModels";
import {
  type RetainedVulnerabilityFinding,
  vulnerabilityFindingKey,
} from "../services/ScanResultStore";
import { scanCoverageIsComplete } from "../status/statusModel";
import {
  assertWebviewNonce,
  escapeHtml,
  normalizeDisplaySeverity,
} from "./webviewSecurity";
import type {
  RemediationApplySnapshot,
  RemediationHistoryRecordView,
  ScanCoverage,
} from "./webviewTypes";

export const DEPENDENCY_RISK_WEIGHTS = Object.freeze({
  CRITICAL: 20,
  HIGH: 10,
  MEDIUM: 4,
  LOW: 1,
  UNKNOWN: 0,
} satisfies Readonly<Record<Severity, number>>);

export const DEPENDENCY_RISK_FORMULA =
  "min(100, round((20×critical + 10×high + 4×medium + 1×low) ÷ (20×dependencies scanned) × 100))";

const NO_SUPPORTED_FILE_ERROR_CODES = new Set([
  "NO_LOCKFILE",
  "UNSUPPORTED_PACKAGE_MANAGER",
]);

const SEVERITY_RANK: Readonly<Record<Severity, number>> = Object.freeze({
  UNKNOWN: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
});

export interface SeverityCounts {
  readonly CRITICAL: number;
  readonly HIGH: number;
  readonly MEDIUM: number;
  readonly LOW: number;
  readonly UNKNOWN: number;
}

export interface ProviderCoverageSummary {
  readonly provider: string;
  readonly status: ProviderStatus;
  readonly eligible: number;
  readonly submitted: number;
  readonly successful: number;
  readonly failed: number;
  readonly cacheHits: number;
  readonly staleCacheFallbacks: number;
}

export interface TopVulnerableDependency {
  readonly packageName: string;
  readonly installedVersion: string;
  readonly ecosystem: string;
  readonly ecosystemGroup: string;
  readonly ecosystemLabel: string;
  readonly severity: Severity;
  readonly vulnerabilityCount: number;
}

export interface EcosystemCoverageSummary {
  readonly key: string;
  readonly label: string;
  readonly ecosystem: string;
  readonly packageManagers: readonly string[];
  readonly discovered: number;
  readonly resolved: number;
  readonly checked: number;
  readonly vulnerable: number;
  readonly unresolved: number;
  readonly unsupported: number;
  readonly displayedFindings: number;
  readonly percentage: number;
}

export interface DashboardSummary {
  readonly resultCount: number;
  readonly projectNames: readonly string[];
  readonly lastScanTimestamp?: string;
  readonly dependenciesScanned: number;
  readonly vulnerableDependencies: number;
  readonly dependenciesWithNoKnownFindings: number;
  /** Findings retained after the configured severity threshold is applied. */
  readonly totalVulnerabilities: number;
  readonly hiddenFindings: number;
  readonly severityCounts: SeverityCounts;
  readonly dependencyRiskScore: number;
  readonly weightedRiskPoints: number;
  readonly providerCoverage: readonly ProviderCoverageSummary[];
  readonly ecosystemCoverage: readonly EcosystemCoverageSummary[];
  readonly coverageComplete: boolean;
  readonly providerUnavailable: boolean;
  readonly cancelled: boolean;
  readonly hasNoSupportedDependencyFiles: boolean;
  readonly topVulnerableDependencies: readonly TopVulnerableDependency[];
}

export interface DashboardRenderContext {
  readonly workspaceOpen: boolean;
  readonly scanResults: readonly ScanResult[];
  readonly latestAttempt?: readonly ScanResult[];
  readonly displayedCoverage?: ScanCoverage;
  readonly latestAttemptCoverage?: ScanCoverage;
  readonly latestAttemptTimestamp?: string;
  readonly lastSuccessfulTimestamp?: string;
  readonly retainedFindings?: readonly RetainedVulnerabilityFinding[];
  readonly retainedFindingsTruncated?: boolean;
  /** Derived only from current displayed ScanResult findings. */
  readonly remediationAnalysis?: RemediationAnalysisResult;
  readonly remediationAnalysisLabel?: string;
  readonly remediationAnalysisTimestamp?: string;
  /** Session-only Phase 5B presentation state; no file contents are stored. */
  readonly remediationApply?: RemediationApplySnapshot;
}

const MAXIMUM_RETAINED_FINDING_ROWS = 100;

function finiteCount(value: number): number {
  return Number.isFinite(value) && value > 0 ? Math.trunc(value) : 0;
}

function emptySeverityCounts(): SeverityCounts {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
}

export function countVulnerabilitiesBySeverity(
  vulnerabilities: readonly Vulnerability[],
): SeverityCounts {
  const counts: Record<Severity, number> = emptySeverityCounts();
  for (const vulnerability of vulnerabilities) {
    counts[normalizeDisplaySeverity(vulnerability.severity)] += 1;
  }
  return counts;
}

/**
 * A finding-density indicator, not an application-security score. A score of
 * 100 means at least 20 weighted finding points per scanned dependency.
 */
export function calculateDependencyRiskScore(
  dependenciesScanned: number,
  vulnerabilities: readonly Vulnerability[],
): number {
  const dependencyCount = finiteCount(dependenciesScanned);
  if (dependencyCount === 0) {
    return 0;
  }
  const weightedPoints = vulnerabilities.reduce(
    (total, vulnerability) =>
      total +
      DEPENDENCY_RISK_WEIGHTS[
        normalizeDisplaySeverity(vulnerability.severity)
      ],
    0,
  );
  return Math.min(
    100,
    Math.round((weightedPoints / (20 * dependencyCount)) * 100),
  );
}

function projectNames(results: readonly ScanResult[]): string[] {
  const names = new Set<string>();
  for (const result of results) {
    for (const location of result.workspacePath.split(";")) {
      const normalized = location.trim().replace(/\\/gu, "/").replace(/\/+$/u, "");
      const name = normalized.split("/").at(-1);
      if (name !== undefined && name.length > 0) {
        names.add(name);
      }
      if (names.size >= 20) {
        return [...names];
      }
    }
  }
  return [...names];
}

function lastScanTimestamp(results: readonly ScanResult[]): string | undefined {
  let latestValue: string | undefined;
  let latestTime = Number.NEGATIVE_INFINITY;
  for (const result of results) {
    const time = Date.parse(result.scannedAt);
    if (Number.isFinite(time) && time > latestTime) {
      latestTime = time;
      latestValue = result.scannedAt;
    }
  }
  return latestValue;
}

function providerStatusRank(status: ProviderStatus): number {
  switch (status) {
    case "available":
      return 0;
    case "partial":
      return 1;
    case "unavailable":
      return 2;
  }
}

function summarizeProviderCoverage(
  results: readonly ScanResult[],
): ProviderCoverageSummary[] {
  const summaries = new Map<string, ProviderCoverageSummary>();
  for (const result of results) {
    for (const coverage of result.providerResults) {
      const current = summaries.get(coverage.provider);
      const status =
        current === undefined ||
        providerStatusRank(coverage.status) > providerStatusRank(current.status)
          ? coverage.status
          : current.status;
      summaries.set(coverage.provider, {
        provider: coverage.provider,
        status,
        eligible:
          (current?.eligible ?? 0) + finiteCount(coverage.dependenciesEligible),
        submitted:
          (current?.submitted ?? 0) +
          finiteCount(coverage.dependenciesSubmitted),
        successful:
          (current?.successful ?? 0) + finiteCount(coverage.successful),
        failed: (current?.failed ?? 0) + finiteCount(coverage.failed),
        cacheHits: (current?.cacheHits ?? 0) + finiteCount(coverage.cacheHits),
        staleCacheFallbacks:
          (current?.staleCacheFallbacks ?? 0) +
          finiteCount(coverage.staleCacheFallbacks),
      });
    }
  }
  return [...summaries.values()].sort((left, right) =>
    left.provider < right.provider ? -1 : left.provider > right.provider ? 1 : 0,
  );
}

function ecosystemGroup(
  ecosystem: string,
  packageManager?: string,
): { readonly key: string; readonly label: string } {
  if (ecosystem === "PyPI") {
    return { key: "PyPI", label: "Python" };
  }
  if (ecosystem === "crates.io") {
    return { key: "crates.io", label: "Cargo" };
  }
  if (ecosystem === "Packagist") {
    return { key: "Packagist", label: "Composer" };
  }
  if (ecosystem === "Maven" && packageManager === "gradle") {
    return { key: "Gradle", label: "Gradle" };
  }
  return { key: ecosystem, label: ecosystem };
}

function dependencyManagersByCoordinate(
  results: readonly ScanResult[],
): ReadonlyMap<string, ReadonlySet<string>> {
  const managers = new Map<string, Set<string>>();
  for (const result of results) {
    for (const dependency of result.dependencies) {
      const key = JSON.stringify([
        dependency.ecosystem,
        dependency.name,
        dependency.installedVersion,
      ]);
      const values = managers.get(key) ?? new Set<string>();
      if (dependency.packageManager !== undefined) {
        values.add(dependency.packageManager);
      }
      managers.set(key, values);
    }
  }
  return managers;
}

function topVulnerableDependencies(
  vulnerabilities: readonly Vulnerability[],
  managers: ReadonlyMap<string, ReadonlySet<string>>,
): TopVulnerableDependency[] {
  const grouped = new Map<string, TopVulnerableDependency>();
  for (const vulnerability of vulnerabilities) {
    const severity = normalizeDisplaySeverity(vulnerability.severity);
    const matchingManagers = managers.get(
      JSON.stringify([
        vulnerability.ecosystem,
        vulnerability.packageName,
        vulnerability.installedVersion,
      ]),
    );
    const displayGroups = new Map(
      [...(matchingManagers ?? [undefined])].map((manager) => {
        const group = ecosystemGroup(vulnerability.ecosystem, manager);
        return [group.key, group] as const;
      }),
    );
    for (const group of displayGroups.values()) {
      const key = `${vulnerability.ecosystem}\u0000${vulnerability.packageName}\u0000${vulnerability.installedVersion}\u0000${group.key}`;
      const current = grouped.get(key);
      grouped.set(key, {
        packageName: vulnerability.packageName,
        installedVersion: vulnerability.installedVersion,
        ecosystem: vulnerability.ecosystem,
        ecosystemGroup: group.key,
        ecosystemLabel: group.label,
        severity:
          current === undefined ||
          SEVERITY_RANK[severity] > SEVERITY_RANK[current.severity]
            ? severity
            : current.severity,
        vulnerabilityCount: (current?.vulnerabilityCount ?? 0) + 1,
      });
    }
  }
  return [...grouped.values()]
    .sort(
      (left, right) =>
        SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity] ||
        right.vulnerabilityCount - left.vulnerabilityCount ||
        (left.packageName < right.packageName
          ? -1
          : left.packageName > right.packageName
            ? 1
            : left.installedVersion < right.installedVersion
              ? -1
              : left.installedVersion > right.installedVersion
                ? 1
                : left.ecosystemGroup.localeCompare(right.ecosystemGroup)),
    )
    .slice(0, 10);
}

function summarizeEcosystemCoverage(
  results: readonly ScanResult[],
  vulnerabilities: readonly Vulnerability[],
  managers: ReadonlyMap<string, ReadonlySet<string>>,
): EcosystemCoverageSummary[] {
  const summaries = new Map<string, EcosystemCoverageSummary>();
  const coverages = results.flatMap((result) =>
    result.projectCoverage ?? result.ecosystemCoverage ?? [],
  );
  for (const coverage of coverages) {
    const manager = coverage.packageManagers[0];
    const group = ecosystemGroup(coverage.ecosystem, manager);
    const current = summaries.get(group.key);
    const discovered = (current?.discovered ?? 0) + finiteCount(coverage.discovered);
    const checked = (current?.checked ?? 0) + finiteCount(coverage.checked);
    summaries.set(group.key, {
      key: group.key,
      label: group.label,
      ecosystem: coverage.ecosystem,
      packageManagers: [
        ...new Set([
          ...(current?.packageManagers ?? []),
          ...coverage.packageManagers,
        ]),
      ].sort(),
      discovered,
      resolved: (current?.resolved ?? 0) + finiteCount(coverage.resolved),
      checked,
      vulnerable:
        (current?.vulnerable ?? 0) + finiteCount(coverage.vulnerable),
      unresolved:
        (current?.unresolved ?? 0) + finiteCount(coverage.unresolved),
      unsupported:
        (current?.unsupported ?? 0) + finiteCount(coverage.unsupported),
      displayedFindings: current?.displayedFindings ?? 0,
      percentage:
        discovered === 0 ? 0 : Math.min(100, Math.round((checked / discovered) * 100)),
    });
  }
  for (const vulnerability of vulnerabilities) {
    const matchingManagers = managers.get(
      JSON.stringify([
        vulnerability.ecosystem,
        vulnerability.packageName,
        vulnerability.installedVersion,
      ]),
    );
    const displayGroups = new Set(
      [...(matchingManagers ?? [undefined])].map(
        (manager) => ecosystemGroup(vulnerability.ecosystem, manager).key,
      ),
    );
    for (const groupKey of displayGroups) {
      const current = summaries.get(groupKey);
      if (current !== undefined) {
        summaries.set(groupKey, {
          ...current,
          displayedFindings: current.displayedFindings + 1,
        });
      }
    }
  }
  return [...summaries.values()].sort((left, right) =>
    left.label.localeCompare(right.label),
  );
}

export function summarizeScanResults(
  results: readonly ScanResult[],
): DashboardSummary {
  const vulnerabilities = results.flatMap((result) => result.vulnerabilities);
  const dependenciesScanned = results.reduce(
    (total, result) => total + finiteCount(result.dependenciesScanned),
    0,
  );
  const vulnerableDependencies = results.reduce(
    (total, result) => total + finiteCount(result.vulnerableDependencies),
    0,
  );
  const severityCounts = countVulnerabilitiesBySeverity(vulnerabilities);
  const managers = dependencyManagersByCoordinate(results);
  const providerCoverage = summarizeProviderCoverage(results);
  const providerFindings = results.reduce(
    (total, result) =>
      total +
      result.providerResults.reduce(
        (providerTotal, provider) =>
          providerTotal + finiteCount(provider.vulnerabilitiesFound),
        0,
      ),
    0,
  );
  const hiddenFindings = Math.max(
    0,
    providerFindings - vulnerabilities.length,
  );
  const coverageComplete = scanCoverageIsComplete(results);
  const providerUnavailable =
    providerCoverage.length > 0 &&
    providerCoverage.every((provider) => provider.status === "unavailable");
  const hasNoSupportedDependencyFiles =
    results.length > 0 &&
    dependenciesScanned === 0 &&
    results.some((result) =>
      result.errors.some((error) =>
        NO_SUPPORTED_FILE_ERROR_CODES.has(error.code),
      ),
    );
  const weightedRiskPoints =
    severityCounts.CRITICAL * DEPENDENCY_RISK_WEIGHTS.CRITICAL +
    severityCounts.HIGH * DEPENDENCY_RISK_WEIGHTS.HIGH +
    severityCounts.MEDIUM * DEPENDENCY_RISK_WEIGHTS.MEDIUM +
    severityCounts.LOW * DEPENDENCY_RISK_WEIGHTS.LOW;

  const summary: DashboardSummary = {
    resultCount: results.length,
    projectNames: projectNames(results),
    dependenciesScanned,
    vulnerableDependencies,
    dependenciesWithNoKnownFindings: Math.max(
      0,
      dependenciesScanned - vulnerableDependencies,
    ),
    totalVulnerabilities: vulnerabilities.length,
    hiddenFindings,
    severityCounts,
    dependencyRiskScore: calculateDependencyRiskScore(
      dependenciesScanned,
      vulnerabilities,
    ),
    weightedRiskPoints,
    providerCoverage,
    ecosystemCoverage: summarizeEcosystemCoverage(
      results,
      vulnerabilities,
      managers,
    ),
    coverageComplete,
    providerUnavailable,
    cancelled: results.some((result) => result.cancelled),
    hasNoSupportedDependencyFiles,
    topVulnerableDependencies: topVulnerableDependencies(
      vulnerabilities,
      managers,
    ),
  };
  const timestamp = lastScanTimestamp(results);
  return timestamp === undefined
    ? summary
    : { ...summary, lastScanTimestamp: timestamp };
}

function formatTimestamp(value: string | undefined): string {
  if (value === undefined) {
    return "Not scanned yet";
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) {
    return "Unknown";
  }
  return `${parsed.toISOString().slice(0, 10)} ${parsed
    .toISOString()
    .slice(11, 16)} UTC`;
}

function selectRetainedFindings(
  results: readonly ScanResult[],
  retainedFindings: readonly RetainedVulnerabilityFinding[],
): readonly RetainedVulnerabilityFinding[] {
  const currentKeys = new Set(
    results.flatMap((result) =>
      result.vulnerabilities.map(vulnerabilityFindingKey),
    ),
  );
  const selected = new Map<string, RetainedVulnerabilityFinding>();
  for (const finding of retainedFindings) {
    const key = vulnerabilityFindingKey(finding.vulnerability);
    if (!currentKeys.has(key) && !selected.has(key)) {
      selected.set(key, finding);
    }
  }
  return [...selected.values()];
}

function renderRetainedFindings(
  findings: readonly RetainedVulnerabilityFinding[],
  truncated: boolean,
): string {
  if (findings.length === 0 && !truncated) {
    return "";
  }
  const visible = findings.slice(0, MAXIMUM_RETAINED_FINDING_ROWS);
  const omitted = Math.max(0, findings.length - visible.length);
  const rows = visible
    .map(({ vulnerability, lastConfirmedAt }) => {
      const severity = normalizeDisplaySeverity(vulnerability.severity);
      return `<tr>
        <th scope="row"><code>${escapeHtml(vulnerability.packageName, 256)}@${escapeHtml(vulnerability.installedVersion, 128)}</code></th>
        <td>${escapeHtml(vulnerability.ecosystem, 128)}</td>
        <td><span class="severity-text severity-${severity.toLowerCase()}">${severity}</span></td>
        <td><code>${escapeHtml(vulnerability.source, 128)}:${escapeHtml(vulnerability.id, 256)}</code></td>
        <td>${escapeHtml(formatTimestamp(lastConfirmedAt), 64)}</td>
      </tr>`;
    })
    .join("");
  const omissionNotice =
    omitted === 0 && !truncated
      ? ""
      : `<p class="muted">${omitted > 0 ? `${omitted.toString()} additional retained ${omitted === 1 ? "finding is" : "findings are"} omitted from this table. ` : ""}${truncated ? "Additional last-complete findings were omitted by the bounded evidence limit." : ""}</p>`;
  return `<section class="card state-warning" aria-labelledby="retained-heading">
    <h2 id="retained-heading">Last complete scan findings — not reconfirmed (${findings.length.toString()})</h2>
    <p>These findings were confirmed by the last complete scan but were not reconfirmed by the current incomplete scan.</p>
    <p class="muted">They remain visible as historical evidence and are not included in current coverage, provider, risk, or dependency counts.</p>
    ${rows.length === 0 ? "" : `<div class="table-wrap"><table><thead><tr><th scope="col">Dependency</th><th scope="col">Ecosystem</th><th scope="col">Severity</th><th scope="col">Advisory</th><th scope="col">Last confirmed</th></tr></thead><tbody>${rows}</tbody></table></div>`}
    ${omissionNotice}
  </section>`;
}

function severityCard(label: string, count: number, className: string): string {
  return `<article class="metric severity ${className}" aria-label="${escapeHtml(label)}: ${count}">
    <span class="severity-label"><span class="severity-symbol" aria-hidden="true">!</span>${escapeHtml(label)}</span>
    <strong>${count}</strong>
  </article>`;
}

function renderStateMessage(
  context: DashboardRenderContext,
  summary: DashboardSummary,
): string {
  if (!context.workspaceOpen) {
    return '<section class="state state-neutral" role="status"><h2>No workspace is open.</h2><p>Open a workspace to scan supported dependency metadata.</p></section>';
  }
  if (context.latestAttemptCoverage === "unavailable") {
    const attempt = summarizeScanResults(
      context.latestAttempt ?? context.scanResults,
    );
    const providers =
      attempt.providerCoverage.length === 0
        ? "Not available"
        : attempt.providerCoverage
            .map((provider) => provider.provider)
            .join(", ");
    const successful = attempt.providerCoverage.reduce(
      (total, provider) => total + provider.successful,
      0,
    );
    const failed = attempt.providerCoverage.reduce(
      (total, provider) => total + provider.failed,
      0,
    );
    const cacheAvailable = attempt.providerCoverage.some(
      (provider) =>
        provider.cacheHits > 0 || provider.staleCacheFallbacks > 0,
    );
    return `<section class="state state-danger" role="alert"><h2>Vulnerability database unavailable.</h2><p>The latest attempt could not complete. Previously stored results may remain visible below and must not be interpreted as a clean refresh.</p><dl class="failure-details"><dt>Provider</dt><dd>${escapeHtml(providers, 512)}</dd><dt>Dependencies discovered</dt><dd>${attempt.dependenciesScanned}</dd><dt>Successfully checked</dt><dd>${successful}</dd><dt>Failed</dt><dd>${failed}</dd><dt>Cached results</dt><dd>${cacheAvailable ? "available" : "unavailable"}</dd></dl></section>`;
  }
  if (context.latestAttemptCoverage === "cancelled") {
    return '<section class="state state-warning" role="alert"><h2>Latest dependency scan was cancelled.</h2><p>Previously stored results may remain visible below. Cancellation is not a completed vulnerability check.</p></section>';
  }
  if (context.latestAttemptCoverage === "partial") {
    if (summary.hasNoSupportedDependencyFiles) {
      return '<section class="state state-neutral" role="status"><h2>No supported dependency files were found.</h2><p>The latest scan could not establish dependency coverage.</p></section>';
    }
    return '<section class="state state-warning" role="alert"><h2>Latest scan coverage is incomplete.</h2><p>Some dependencies could not be checked. Displayed findings are partial.</p></section>';
  }
  if (summary.resultCount === 0) {
    return '<section class="state state-neutral" role="status"><h2>No scan results yet.</h2><p>Scan the workspace to check known vulnerabilities.</p></section>';
  }
  if (summary.hasNoSupportedDependencyFiles) {
    return '<section class="state state-neutral" role="status"><h2>No supported dependency files were found.</h2><p>No enabled ecosystem adapter found readable dependency metadata.</p></section>';
  }
  if (summary.providerUnavailable) {
    return '<section class="state state-danger" role="alert"><h2>Vulnerability database unavailable.</h2><p>The displayed findings may be incomplete. A failed check is not a clean result.</p></section>';
  }
  if (!summary.coverageComplete) {
    return '<section class="state state-warning" role="alert"><h2>Scan coverage is incomplete.</h2><p>Some dependencies could not be checked. Zero findings does not mean zero known vulnerabilities.</p></section>';
  }
  if (summary.dependenciesScanned === 0) {
    return '<section class="state state-neutral" role="status"><h2>No dependencies were available to scan.</h2></section>';
  }
  if (summary.totalVulnerabilities === 0) {
    if (summary.hiddenFindings > 0) {
      return '<section class="state state-warning" role="status"><h2>No findings meet the configured severity threshold.</h2><p>The provider reported known findings at severities currently hidden from the displayed result.</p></section>';
    }
    return '<section class="state state-success" role="status"><h2>No known vulnerabilities were found.</h2><p>This describes the completed provider check, not overall application security.</p></section>';
  }
  return `<section class="state state-warning" role="status"><h2>${summary.totalVulnerabilities} known ${summary.totalVulnerabilities === 1 ? "vulnerability" : "vulnerabilities"} found.</h2><p>Review affected dependencies and available fixed versions.</p></section>`;
}

function renderHiddenFindingsNotice(summary: DashboardSummary): string {
  if (summary.hiddenFindings === 0) {
    return "";
  }
  return `<section class="state state-warning threshold-notice" role="status"><h2>Severity threshold applied</h2><p><strong>${summary.hiddenFindings} known ${summary.hiddenFindings === 1 ? "finding" : "findings"} hidden by configured severity threshold.</strong></p><p>Severity cards, top dependencies, and the Dependency Risk Score below use displayed findings only.</p></section>`;
}

function renderRemediationSummary(
  analysis: RemediationAnalysisResult | undefined,
  displayedVulnerabilityCount: number,
  label?: string,
  timestamp?: string,
): string {
  if (analysis === undefined) {
    return "";
  }
  const total = finiteCount(displayedVulnerabilityCount);
  const remediable = Math.min(
    total,
    finiteCount(analysis.summary.remediable),
  );
  const manualReview = Math.min(
    total,
    finiteCount(analysis.summary.manualReview),
  );
  const noKnownFix = Math.min(
    total,
    finiteCount(analysis.summary.noKnownFix),
  );
  const unresolved = Math.min(
    total,
    finiteCount(analysis.summary.unresolved),
  );
  const coverage =
    total === 0 ? 0 : Math.min(100, Math.round((remediable / total) * 100));
  return `<section class="card remediation-summary" aria-labelledby="remediation-summary-heading">
    <h2 id="remediation-summary-heading">Remediation</h2>
    ${label === undefined ? "" : `<p class="muted">Analysis source: ${escapeHtml(label, 128)}${timestamp === undefined ? "" : ` · ${escapeHtml(formatTimestamp(timestamp), 64)}`}</p>`}
    <p><strong>${total.toString()} displayed ${total === 1 ? "vulnerability" : "vulnerabilities"}</strong></p>
    <dl>
      <dt>Remediable</dt><dd>${remediable.toString()}</dd>
      <dt>Manual review required</dt><dd>${manualReview.toString()}</dd>
      <dt>No known fixed version</dt><dd>${noKnownFix.toString()}</dd>
      <dt>Unresolved dependency</dt><dd>${unresolved.toString()}</dd>
    </dl>
    <h3>Remediation Coverage</h3>
    <p><progress aria-label="Remediation coverage ${coverage.toString()} percent" max="100" value="${coverage.toString()}">${coverage.toString()}%</progress> <strong>${coverage.toString()}%</strong></p>
    <p class="muted">${remediable.toString()} of ${total.toString()} displayed vulnerability records have a calculated remediation candidate. This does not mean they are fixed.${analysis.summary.analysisComplete ? "" : " Analysis is incomplete; manual review remains required."}</p>
  </section>`;
}

function remediationResultHeading(
  record: RemediationHistoryRecordView,
): string {
  if (record.status === "successful") {
    return `✓ ${finiteCount(record.vulnerabilitiesResolved).toString()} ${finiteCount(record.vulnerabilitiesResolved) === 1 ? "vulnerability" : "vulnerabilities"} resolved`;
  }
  if (record.status === "partial") {
    return "⚠ Partial remediation";
  }
  if (record.status === "cancelled") {
    return "Remediation cancelled";
  }
  return record.rolledBack
    ? "✕ Remediation failed — rolled back"
    : "✕ Remediation failed";
}

function renderRemediationHistoryRecord(
  record: RemediationHistoryRecordView,
): string {
  const target =
    record.recommendedVersion === undefined
      ? escapeHtml(record.currentVersion, 512)
      : `${escapeHtml(record.currentVersion, 512)} → ${escapeHtml(record.recommendedVersion, 512)}`;
  const rollbackWarning =
    record.rolledBack && record.rollbackVerified === false
      ? '<strong class="danger-text">Rollback could not be fully verified. Inspect the affected files.</strong>'
      : "";
  return `<li><strong>${escapeHtml(record.packageName, 512)}</strong> <code>${target}</code><br>${escapeHtml(remediationResultHeading(record), 256)} · <time>${escapeHtml(formatTimestamp(record.timestamp), 64)}</time><br><span class="muted">${escapeHtml(record.message, 2_048)}</span>${rollbackWarning.length === 0 ? "" : `<br>${rollbackWarning}`}</li>`;
}

function renderRemediationActions(
  analysis: RemediationAnalysisResult | undefined,
  snapshot: RemediationApplySnapshot | undefined,
): string {
  if (analysis === undefined || snapshot === undefined) {
    return "";
  }
  const currentKeys = new Set(
    analysis.recommendations.map(
      (recommendation) => recommendation.recommendationKey,
    ),
  );
  const capabilities = new Map<
    string,
    "safe" | "preview-only" | "unsupported"
  >();
  for (const entry of snapshot.capabilities) {
    if (!currentKeys.has(entry.recommendationKey)) {
      continue;
    }
    const current = capabilities.get(entry.recommendationKey);
    capabilities.set(
      entry.recommendationKey,
      current === undefined || current === entry.capability
        ? entry.capability
        : "unsupported",
    );
  }
  let safe = 0;
  let previewOnly = 0;
  let unsupported = 0;
  for (const capability of capabilities.values()) {
    if (capability === "safe") {
      safe += 1;
    } else if (capability === "preview-only") {
      previewOnly += 1;
    } else {
      unsupported += 1;
    }
  }
  const operation = snapshot.activeOperation;
  const lastResult = snapshot.lastResult;
  const history = snapshot.history.slice(-20).reverse();
  return `<section class="card remediation-actions-card" aria-labelledby="remediation-actions-heading">
    <h2 id="remediation-actions-heading">Remediation actions</h2>
    <p><strong>${safe.toString()} ${safe === 1 ? "fix" : "fixes"} available</strong></p>
    <dl>
      <dt>Safe preview and apply</dt><dd>${safe.toString()}</dd>
      <dt>Preview only</dt><dd>${previewOnly.toString()}</dd>
      <dt>Manual review</dt><dd>${unsupported.toString()}</dd>
    </dl>
    <div class="actions remediation-buttons">
      ${safe > 0 ? '<button type="button" data-action="reviewFixes">Review Fixes</button>' : ""}
      ${safe === 0 && previewOnly > 0 ? '<button type="button" data-action="reviewFixes">Review Remediation</button>' : ""}
      ${history.length > 0 ? '<button type="button" class="secondary" data-action="showRemediationHistory">Remediation History</button>' : ""}
    </div>
    ${operation === undefined ? "" : `<p class="state state-warning" role="status"><strong>Remediation in progress:</strong> ${escapeHtml(operation.stage.replaceAll("-", " "), 64)}.${operation.message === undefined ? "" : ` ${escapeHtml(operation.message, 2_048)}`}</p>`}
    ${lastResult === undefined ? "" : `<section class="last-remediation" aria-labelledby="last-remediation-heading"><h3 id="last-remediation-heading">Last remediation</h3><p><strong>${escapeHtml(remediationResultHeading(lastResult), 256)}</strong></p><p>${escapeHtml(lastResult.message, 2_048)}</p>${lastResult.before === undefined || lastResult.after === undefined ? "" : `<div class="before-after"><article><strong>Before</strong><br>${finiteCount(lastResult.before.dependencies).toString()} dependencies · ${finiteCount(lastResult.before.vulnerabilities).toString()} vulnerabilities<br>Critical ${finiteCount(lastResult.before.critical).toString()} · High ${finiteCount(lastResult.before.high).toString()} · Medium ${finiteCount(lastResult.before.medium).toString()}</article><article><strong>After</strong><br>${finiteCount(lastResult.after.dependencies).toString()} dependencies · ${finiteCount(lastResult.after.vulnerabilities).toString()} vulnerabilities<br>Critical ${finiteCount(lastResult.after.critical).toString()} · High ${finiteCount(lastResult.after.high).toString()} · Medium ${finiteCount(lastResult.after.medium).toString()}</article></div>`}</section>`}
    ${history.length === 0 ? "" : `<details class="remediation-history"><summary>Session remediation history (${snapshot.history.length.toString()})</summary><ol>${history.map(renderRemediationHistoryRecord).join("")}</ol></details>`}
  </section>`;
}

function renderProviderCoverage(
  providers: readonly ProviderCoverageSummary[],
): string {
  if (providers.length === 0) {
    return '<p class="muted">Provider coverage is not available.</p>';
  }
  return `<div class="table-wrap"><table>
    <thead><tr><th scope="col">Provider</th><th scope="col">Status</th><th scope="col">Successful</th><th scope="col">Failed</th><th scope="col">Cached</th></tr></thead>
    <tbody>${providers
      .map(
        (provider) => `<tr>
          <th scope="row">${escapeHtml(provider.provider, 256)}</th>
          <td><span class="status status-${provider.status}"><span aria-hidden="true">${provider.status === "available" ? "✓" : "!"}</span> ${escapeHtml(provider.status)}</span></td>
          <td>${provider.successful} / ${provider.eligible}</td>
          <td>${provider.failed}</td>
          <td>${provider.cacheHits} fresh, ${provider.staleCacheFallbacks} stale</td>
        </tr>`,
      )
      .join("")}</tbody>
  </table></div>`;
}

function renderTopDependencies(
  dependencies: readonly TopVulnerableDependency[],
): string {
  if (dependencies.length === 0) {
    return '<p class="muted">No vulnerable dependencies to display.</p>';
  }
  return `<div class="table-wrap"><table>
    <thead><tr><th scope="col">Dependency</th><th scope="col">Ecosystem</th><th scope="col">Highest severity</th><th scope="col">Vulnerabilities</th></tr></thead>
    <tbody>${dependencies
      .map(
        (dependency) => `<tr data-ecosystem-group="${escapeHtml(dependency.ecosystemGroup, 64)}">
          <th scope="row"><code>${escapeHtml(dependency.packageName, 512)}@${escapeHtml(dependency.installedVersion, 512)}</code></th>
          <td>${escapeHtml(dependency.ecosystemLabel, 64)}</td>
          <td><span class="severity-text severity-${dependency.severity.toLowerCase()}"><span aria-hidden="true">!</span> ${dependency.severity}</span></td>
          <td>${dependency.vulnerabilityCount}</td>
        </tr>`,
      )
      .join("")}</tbody>
  </table></div>`;
}

function renderEcosystemFilters(
  ecosystems: readonly EcosystemCoverageSummary[],
): string {
  if (ecosystems.length === 0) {
    return "";
  }
  return `<nav class="filter-bar" aria-label="Filter dashboard by ecosystem">
    <button type="button" class="secondary filter-button" data-ecosystem-filter="all" aria-pressed="true">All</button>
    ${ecosystems
      .map(
        (coverage) =>
          `<button type="button" class="secondary filter-button" data-ecosystem-filter="${escapeHtml(coverage.key, 64)}" aria-pressed="false">${escapeHtml(coverage.label, 64)}</button>`,
      )
      .join("")}
  </nav>`;
}

function renderEcosystemCoverage(
  ecosystems: readonly EcosystemCoverageSummary[],
): string {
  if (ecosystems.length === 0) {
    return '<p class="muted">Ecosystem coverage is not available for legacy results.</p>';
  }
  return `<div class="table-wrap"><table>
    <thead><tr><th scope="col">Ecosystem</th><th scope="col">Displayed findings</th><th scope="col">Discovered</th><th scope="col">Resolved</th><th scope="col">Checked</th><th scope="col">Vulnerable</th><th scope="col">Unresolved</th><th scope="col">Unsupported</th><th scope="col">Coverage</th></tr></thead>
    <tbody>${ecosystems
      .map(
        (coverage) => `<tr data-ecosystem-group="${escapeHtml(coverage.key, 64)}">
          <th scope="row">${escapeHtml(coverage.label, 64)}<span class="muted ecosystem-detail">${coverage.packageManagers.length === 0 ? "" : ` (${escapeHtml(coverage.packageManagers.join(", "), 256)})`}</span></th>
          <td>${coverage.displayedFindings}</td>
          <td>${coverage.discovered}</td>
          <td>${coverage.resolved}</td>
          <td>${coverage.checked}</td>
          <td>${coverage.vulnerable}</td>
          <td>${coverage.unresolved}</td>
          <td>${coverage.unsupported}</td>
          <td><progress aria-label="${escapeHtml(coverage.label, 64)} dependency coverage ${coverage.percentage}%" max="100" value="${coverage.percentage}">${coverage.percentage}%</progress> ${coverage.percentage}%</td>
        </tr>`,
      )
      .join("")}</tbody>
  </table></div>`;
}

function renderRiskRows(counts: SeverityCounts): string {
  const maximum = Math.max(
    1,
    counts.CRITICAL,
    counts.HIGH,
    counts.MEDIUM,
    counts.LOW,
  );
  return (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const)
    .map(
      (severity) => `<div class="risk-row">
        <span><span aria-hidden="true">!</span> ${severity}</span>
        <progress aria-label="${severity}: ${counts[severity]} findings" max="${maximum}" value="${counts[severity]}">${counts[severity]}</progress>
        <strong>${counts[severity]}</strong>
      </div>`,
    )
    .join("");
}

function renderNoWorkspaceDocument(nonce: string, scriptUri: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dependency Security</title>
  <style nonce="${nonce}">
    :root { color-scheme: light dark; }
    * { box-sizing: border-box; }
    body { margin: 0; padding: 24px; color: var(--vscode-editor-foreground); background: var(--vscode-editor-background); font: 13px/1.5 var(--vscode-font-family); }
    main { max-width: 880px; margin: 0 auto; }
    .header { display: flex; gap: 18px; align-items: flex-start; justify-content: space-between; }
    h1 { margin: 0; font-size: 26px; }
    h2 { margin: 0 0 2px; font-size: 17px; }
    p { margin: 6px 0; }
    .state { margin-top: 20px; padding: 16px; border: 1px solid var(--vscode-panel-border); border-left: 4px solid var(--vscode-focusBorder); background: var(--vscode-sideBar-background); }
    button { min-height: 32px; padding: 6px 13px; border: 1px solid var(--vscode-panel-border); color: var(--vscode-button-foreground); background: var(--vscode-button-background); cursor: not-allowed; opacity: .65; font: inherit; }
    @media (max-width: 600px) { body { padding: 14px; } .header { display: block; } button { margin-top: 14px; } }
    @media (forced-colors: active) { .state, button { border-color: CanvasText; } }
  </style>
</head>
<body>
  <main>
    <header class="header">
      <h1>Dependency Security</h1>
      <button type="button" disabled aria-label="Scan Workspace; no workspace is open">Scan Workspace</button>
    </header>
    <section class="state" role="status">
      <h2>No workspace is open.</h2>
      <p>Open a workspace to scan supported dependency metadata.</p>
    </section>
  </main>
  <script nonce="${nonce}" src="${escapeHtml(scriptUri, 4_096)}"></script>
</body>
</html>`;
}

export function renderDashboardDocument(
  context: DashboardRenderContext,
  rawNonce: string,
  scriptUri: string,
): string {
  const nonce = assertWebviewNonce(rawNonce);
  if (!context.workspaceOpen) {
    return renderNoWorkspaceDocument(nonce, scriptUri);
  }
  const summary = summarizeScanResults(context.scanResults);
  const retainedFindings = selectRetainedFindings(
    context.scanResults,
    context.retainedFindings ?? [],
  );
  const project =
    summary.projectNames.length === 0
      ? "Not available"
      : summary.projectNames.join(", ");
  const scanAction = summary.resultCount === 0 ? "scanWorkspace" : "refreshScan";
  const scanLabel = summary.resultCount === 0 ? "Scan Workspace" : "Rescan Workspace";
  const vulnerabilityButton =
    summary.totalVulnerabilities === 0 && retainedFindings.length === 0
      ? '<button type="button" disabled aria-label="View vulnerabilities; no findings meet the configured severity threshold">View Vulnerabilities</button>'
      : '<button type="button" class="secondary" data-action="showVulnerabilities">View Vulnerabilities</button>';
  const lastSuccessfulTimestamp =
    context.lastSuccessfulTimestamp ??
    (context.latestAttemptCoverage === undefined
      ? summary.lastScanTimestamp
      : undefined);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dependency Security</title>
  <style nonce="${nonce}">
    :root { color-scheme: light dark; }
    * { box-sizing: border-box; }
    body { margin: 0; padding: 24px; color: var(--vscode-editor-foreground); background: var(--vscode-editor-background); font: 13px/1.5 var(--vscode-font-family); }
    main { max-width: 1080px; margin: 0 auto; }
    h1 { margin: 0; font-size: 26px; }
    h2 { margin: 0 0 12px; font-size: 17px; }
    h3 { margin: 15px 0 7px; font-size: 14px; }
    p { margin: 6px 0; }
    .subtitle, .muted { color: var(--vscode-descriptionForeground); }
    .header { display: flex; gap: 18px; align-items: flex-start; justify-content: space-between; margin-bottom: 20px; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    button { min-height: 32px; padding: 6px 13px; border: 1px solid transparent; color: var(--vscode-button-foreground); background: var(--vscode-button-background); cursor: pointer; font: inherit; }
    button.secondary { color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
    button:hover { background: var(--vscode-button-hoverBackground); }
    button.secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }
    button:focus-visible { outline: 2px solid var(--vscode-focusBorder); outline-offset: 2px; }
    button:hover { background: var(--vscode-button-hoverBackground); }
    button:focus-visible { outline: 2px solid var(--vscode-focusBorder); outline-offset: 2px; }
    button.secondary { color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
    button.secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }
    button:disabled { cursor: not-allowed; opacity: .65; }
    [hidden] { display: none !important; }
    .filter-bar { display: flex; gap: 7px; flex-wrap: wrap; margin: 12px 0 18px; }
    .filter-button[aria-pressed="true"] { outline: 2px solid var(--vscode-focusBorder); outline-offset: 1px; }
    .ecosystem-detail { font-weight: 400; }
    .state { margin: 16px 0; padding: 14px 16px; border: 1px solid var(--vscode-panel-border); border-left-width: 4px; background: var(--vscode-sideBar-background); }
    .state h2 { margin-bottom: 2px; }
    .state-danger { border-left-color: var(--vscode-errorForeground); }
    .state-warning { border-left-color: var(--vscode-editorWarning-foreground); }
    .state-success { border-left-color: var(--vscode-testing-iconPassed); }
    .state-neutral { border-left-color: var(--vscode-focusBorder); }
    .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(125px, 1fr)); gap: 10px; margin: 18px 0; }
    .metric { min-height: 90px; padding: 14px; border: 1px solid var(--vscode-panel-border); background: var(--vscode-sideBar-background); }
    .metric strong { display: block; margin-top: 7px; font-size: 25px; }
    .severity-label { font-size: 11px; font-weight: 650; letter-spacing: .04em; }
    .severity-symbol { display: inline-grid; place-items: center; width: 16px; height: 16px; margin-right: 6px; border: 1px solid currentColor; border-radius: 50%; font-size: 11px; }
    .critical, .severity-critical { color: var(--vscode-errorForeground); }
    .high, .severity-high { color: var(--vscode-editorError-foreground); }
    .medium, .severity-medium { color: var(--vscode-editorWarning-foreground); }
    .low, .severity-low { color: var(--vscode-editorInfo-foreground); }
    .unknown, .severity-unknown { color: var(--vscode-descriptionForeground); }
    .no-findings { color: var(--vscode-testing-iconPassed); }
    .grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(280px, .55fr); gap: 14px; margin: 14px 0; }
    .card { padding: 17px; border: 1px solid var(--vscode-panel-border); background: var(--vscode-sideBar-background); }
    .score { font-size: 34px; font-weight: 700; }
    .score span { font-size: 16px; font-weight: 400; color: var(--vscode-descriptionForeground); }
    .formula { overflow-wrap: anywhere; font-family: var(--vscode-editor-font-family); font-size: 11px; }
    .risk-row { display: grid; grid-template-columns: 92px 1fr 35px; align-items: center; gap: 9px; margin: 8px 0; font-size: 11px; }
    progress { width: 100%; height: 10px; accent-color: var(--vscode-progressBar-background); }
    dl { display: grid; grid-template-columns: minmax(145px, 1fr) minmax(80px, 1fr); gap: 7px 16px; margin: 0; }
    dt { color: var(--vscode-descriptionForeground); }
    dd { margin: 0; font-weight: 600; text-align: right; }
    section { margin-top: 22px; }
    .table-wrap { overflow-x: auto; border: 1px solid var(--vscode-panel-border); }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 9px 11px; border-bottom: 1px solid var(--vscode-panel-border); text-align: left; vertical-align: top; }
    tbody tr:last-child th, tbody tr:last-child td { border-bottom: 0; }
    thead { background: var(--vscode-sideBar-background); }
    code { color: inherit; font-family: var(--vscode-editor-font-family); overflow-wrap: anywhere; }
    .status, .severity-text { font-weight: 650; text-transform: uppercase; }
    .status-unavailable { color: var(--vscode-errorForeground); }
    .status-partial { color: var(--vscode-editorWarning-foreground); }
    .status-available { color: var(--vscode-testing-iconPassed); }
    .remediation-buttons { margin-top: 14px; }
    .last-remediation { padding-top: 14px; border-top: 1px solid var(--vscode-panel-border); }
    .before-after { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
    .before-after article { padding: 12px; border: 1px solid var(--vscode-panel-border); }
    .remediation-history { margin-top: 14px; }
    .remediation-history li { margin: 10px 0; overflow-wrap: anywhere; }
    .danger-text { color: var(--vscode-errorForeground); }
    @media (max-width: 720px) { body { padding: 14px; } .header { display: block; } .actions { margin-top: 14px; } .grid, .before-after { grid-template-columns: 1fr; } }
    @media (forced-colors: active) { .card, .metric, .state, .table-wrap, .before-after article { border-color: CanvasText; } button { border-color: ButtonText; } }
  </style>
</head>
<body>
  <main>
    <header class="header">
      <div>
        <h1>Dependency Security</h1>
        <p class="subtitle">Project: <strong>${escapeHtml(project, 2_048)}</strong> · Last successful scan: <time>${escapeHtml(formatTimestamp(lastSuccessfulTimestamp))}</time></p>
      </div>
      <nav class="actions" aria-label="Dependency security actions">
        <button type="button" data-action="${scanAction}">${scanLabel}</button>
        ${vulnerabilityButton}
      </nav>
    </header>

    ${renderStateMessage(context, summary)}
    ${renderRetainedFindings(
      retainedFindings,
      context.retainedFindingsTruncated === true,
    )}
    ${renderHiddenFindingsNotice(summary)}
    ${renderEcosystemFilters(summary.ecosystemCoverage)}

    <section aria-labelledby="findings-heading">
      <h2 id="findings-heading">Findings summary</h2>
      <div class="metrics">
        ${severityCard("CRITICAL", summary.severityCounts.CRITICAL, "critical")}
        ${severityCard("HIGH", summary.severityCounts.HIGH, "high")}
        ${severityCard("MEDIUM", summary.severityCounts.MEDIUM, "medium")}
        ${severityCard("LOW", summary.severityCounts.LOW, "low")}
        ${severityCard("UNKNOWN", summary.severityCounts.UNKNOWN, "unknown")}
        <article class="metric filtered" aria-label="Known findings hidden by configured severity threshold: ${summary.hiddenFindings}"><span class="severity-label"><span class="severity-symbol" aria-hidden="true">−</span>HIDDEN BY THRESHOLD</span><strong>${summary.hiddenFindings}</strong></article>
        <article class="metric no-findings" aria-label="Dependencies with no known findings: ${summary.dependenciesWithNoKnownFindings}"><span class="severity-label"><span class="severity-symbol" aria-hidden="true">✓</span>NO KNOWN FINDINGS</span><strong>${summary.dependenciesWithNoKnownFindings}</strong></article>
      </div>
    </section>

    ${renderRemediationSummary(
      context.remediationAnalysis,
      summary.totalVulnerabilities,
      context.remediationAnalysisLabel,
      context.remediationAnalysisTimestamp,
    )}
    ${renderRemediationActions(
      context.remediationAnalysis,
      context.remediationApply,
    )}

    <div class="grid">
      <section class="card" aria-labelledby="overview-heading">
        <h2 id="overview-heading">Risk overview</h2>
        ${renderRiskRows(summary.severityCounts)}
      </section>
      <section class="card" aria-labelledby="score-heading">
        <h2 id="score-heading">Dependency Risk Score</h2>
        <div class="score" aria-label="Dependency Risk Score ${summary.dependencyRiskScore} out of 100">${summary.dependencyRiskScore} <span>/ 100</span></div>
        <p>${summary.weightedRiskPoints} weighted displayed-finding points across ${summary.dependenciesScanned} scanned dependencies.</p>
        <p class="muted">This score uses findings that meet the configured severity threshold. Hidden known findings are reported separately. It is not a claim about overall application security.</p>
        <p class="formula">Formula: ${escapeHtml(DEPENDENCY_RISK_FORMULA)}</p>
      </section>
    </div>

    <section class="card" aria-labelledby="scan-heading">
      <h2 id="scan-heading">Scan summary</h2>
      <dl>
        <dt>Dependencies scanned</dt><dd>${summary.dependenciesScanned}</dd>
        <dt>Vulnerable dependencies (all severities)</dt><dd>${summary.vulnerableDependencies}</dd>
        <dt>Displayed known findings</dt><dd>${summary.totalVulnerabilities}</dd>
        <dt>Known findings hidden by configured severity threshold</dt><dd>${summary.hiddenFindings}</dd>
        <dt>Coverage</dt><dd>${summary.coverageComplete ? "Complete" : "Incomplete"}</dd>
      </dl>
    </section>

    <section aria-labelledby="coverage-heading">
      <h2 id="coverage-heading">Dependency coverage by ecosystem</h2>
      ${renderEcosystemCoverage(summary.ecosystemCoverage)}
    </section>

    <section aria-labelledby="provider-heading">
      <h2 id="provider-heading">Provider coverage</h2>
      ${renderProviderCoverage(summary.providerCoverage)}
    </section>

    <section aria-labelledby="top-heading">
      <h2 id="top-heading">Top vulnerable dependencies in displayed findings</h2>
      ${renderTopDependencies(summary.topVulnerableDependencies)}
    </section>
  </main>
  <script nonce="${nonce}" src="${escapeHtml(scriptUri, 4_096)}"></script>
</body>
</html>`;
}
