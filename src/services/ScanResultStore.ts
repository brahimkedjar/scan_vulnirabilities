import {
  dependencyManifestPath,
  type Dependency,
} from "../models/Dependency";
import type {
  ScanErrorCode,
  ScanResult,
} from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";

export type ScanCoverage =
  | "not-scanned"
  | "complete"
  | "partial"
  | "unavailable"
  | "cancelled";

export interface DisposableLike {
  dispose(): void;
}

export interface ScanResultStoreSnapshot {
  /** Monotonic authority revision; changes on every observable store mutation. */
  readonly revision: number;
  /** Results exposed through getAll(); normally the latest usable attempt. */
  readonly results: readonly ScanResult[];
  readonly displayedCoverage: ScanCoverage;
  readonly scanning: boolean;
  /** Always records the newest completed attempt, including provider failures. */
  readonly latestAttempt: readonly ScanResult[];
  readonly latestAttemptCoverage: ScanCoverage;
  readonly latestAttemptTimestamp?: string;
  /** The most recent attempt with complete vulnerability coverage. */
  readonly lastSuccessfulResult: readonly ScanResult[];
  readonly lastSuccessfulTimestamp?: string;
  /**
   * Findings from the last complete scan that the current partial scan did
   * not reconfirm. This is deliberately finding-only evidence: its provider
   * coverage and dependency totals must never be combined with current data.
   */
  readonly retainedFindings: readonly RetainedVulnerabilityFinding[];
  /** True when the bounded retained-finding snapshot omitted older evidence. */
  readonly retainedFindingsTruncated: boolean;
}

export interface ScanResultStoreOptions {
  readonly clock?: () => number;
  readonly maximumListeners?: number;
  readonly maximumRetainedFindings?: number;
}

export interface RetainedVulnerabilityFinding {
  readonly vulnerability: Vulnerability;
  readonly dependencies: readonly Dependency[];
  readonly workspacePaths: readonly string[];
  readonly lastConfirmedAt: string;
}

export type ScanResultStoreListener = (
  snapshot: ScanResultStoreSnapshot,
) => void;

const COVERAGE_ERROR_CODES: ReadonlySet<ScanErrorCode> = new Set([
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
const DEFAULT_MAXIMUM_LISTENERS = 64;
const HARD_MAXIMUM_LISTENERS = 256;
export const MAXIMUM_RETAINED_FINDINGS = 10_000;
const EMPTY_RESULTS: readonly ScanResult[] = Object.freeze([]);
const EMPTY_RETAINED_FINDINGS: readonly RetainedVulnerabilityFinding[] =
  Object.freeze([]);

/** Stable identity used to make the current attempt win over retained data. */
export function vulnerabilityFindingKey(
  vulnerability: Pick<
    Vulnerability,
    "source" | "id" | "ecosystem" | "packageName" | "installedVersion"
  >,
): string {
  return JSON.stringify([
    vulnerability.source,
    vulnerability.id,
    vulnerability.ecosystem,
    vulnerability.packageName,
    vulnerability.installedVersion,
  ]);
}

function packageCoordinateKey(
  value: Pick<Dependency, "ecosystem" | "name" | "installedVersion">,
): string;
function packageCoordinateKey(
  value: Pick<
    Vulnerability,
    "ecosystem" | "packageName" | "installedVersion"
  >,
): string;
function packageCoordinateKey(
  value:
    | Pick<Dependency, "ecosystem" | "name" | "installedVersion">
    | Pick<Vulnerability, "ecosystem" | "packageName" | "installedVersion">,
): string {
  return JSON.stringify([
    value.ecosystem,
    "name" in value ? value.name : value.packageName,
    value.installedVersion,
  ]);
}

function dependencyOriginKey(dependency: Dependency): string | undefined {
  const application = dependency.dependencyPath?.[0];
  const directEntry = dependency.dependencyPath?.[1];
  const manifestPath = dependencyManifestPath(dependency);
  if (
    application === undefined ||
    directEntry === undefined ||
    manifestPath === undefined
  ) {
    return undefined;
  }
  return JSON.stringify([manifestPath, application, directEntry]);
}

export interface RetainedFindingDerivation {
  readonly findings: readonly RetainedVulnerabilityFinding[];
  readonly truncated: boolean;
}

export function deriveRetainedVulnerabilityFindings(
  completeResults: readonly ScanResult[],
  currentResults: readonly ScanResult[],
  lastConfirmedAt: string | undefined,
  maximumFindings = MAXIMUM_RETAINED_FINDINGS,
): RetainedFindingDerivation {
  const boundedMaximum = boundedMaximumRetainedFindings(maximumFindings);
  if (completeResults.length === 0 || lastConfirmedAt === undefined) {
    return { findings: EMPTY_RETAINED_FINDINGS, truncated: false };
  }

  const currentKeys = new Set<string>();
  for (const result of currentResults) {
    for (const vulnerability of result.vulnerabilities) {
      currentKeys.add(vulnerabilityFindingKey(vulnerability));
    }
  }
  const vulnerabilities = new Map<string, Vulnerability>();
  const retainedCoordinates = new Set<string>();
  let truncated = false;

  findingSelection: for (const result of completeResults) {
    for (const vulnerability of result.vulnerabilities) {
      const findingKey = vulnerabilityFindingKey(vulnerability);
      if (currentKeys.has(findingKey) || vulnerabilities.has(findingKey)) {
        continue;
      }
      if (vulnerabilities.size >= boundedMaximum) {
        truncated = true;
        break findingSelection;
      }
      vulnerabilities.set(findingKey, vulnerability);
      retainedCoordinates.add(packageCoordinateKey(vulnerability));
    }
  }

  if (vulnerabilities.size === 0) {
    return { findings: EMPTY_RETAINED_FINDINGS, truncated };
  }

  const coordinateEvidence = new Map<
    string,
    { dependencies: Dependency[]; workspacePaths: Set<string> }
  >();
  const directByOrigin = new Map<string, Dependency>();
  const evidenceFor = (
    coordinate: string,
  ): { dependencies: Dependency[]; workspacePaths: Set<string> } => {
    const existing = coordinateEvidence.get(coordinate);
    if (existing !== undefined) {
      return existing;
    }
    const created = { dependencies: [], workspacePaths: new Set<string>() };
    coordinateEvidence.set(coordinate, created);
    return created;
  };

  for (const result of completeResults) {
    for (const vulnerability of result.vulnerabilities) {
      const findingKey = vulnerabilityFindingKey(vulnerability);
      if (!vulnerabilities.has(findingKey)) {
        continue;
      }
      evidenceFor(packageCoordinateKey(vulnerability)).workspacePaths.add(
        result.workspacePath,
      );
    }
    for (const dependency of result.dependencies) {
      if (dependency.dependencyType === "direct") {
        const origin = dependencyOriginKey(dependency);
        if (origin !== undefined && !directByOrigin.has(origin)) {
          directByOrigin.set(origin, dependency);
        }
      }
      const coordinate = packageCoordinateKey(dependency);
      if (!retainedCoordinates.has(coordinate)) {
        continue;
      }
      const evidence = evidenceFor(coordinate);
      evidence.dependencies.push(dependency);
      evidence.workspacePaths.add(
        dependency.workspacePath ?? result.workspacePath,
      );
    }
  }


  // A transitive vulnerable package is diagnosed on its direct manifest
  // introducer. Retain that anchor alongside the vulnerable-coordinate
  // dependencies so a finding-only snapshot remains actionable.
  for (const evidence of coordinateEvidence.values()) {
    const seenDependencies = new Set(evidence.dependencies);
    for (const dependency of [...evidence.dependencies]) {
      if (dependency.dependencyType === "direct") {
        continue;
      }
      const origin = dependencyOriginKey(dependency);
      const anchor = origin === undefined ? undefined : directByOrigin.get(origin);
      if (anchor !== undefined && !seenDependencies.has(anchor)) {
        seenDependencies.add(anchor);
        evidence.dependencies.push(anchor);
      }
    }
  }

  const frozenCoordinateEvidence = new Map<
    string,
    {
      dependencies: readonly Dependency[];
      workspacePaths: readonly string[];
    }
  >();
  for (const [coordinate, evidence] of coordinateEvidence) {
    frozenCoordinateEvidence.set(
      coordinate,
      Object.freeze({
        dependencies: Object.freeze([...evidence.dependencies]),
        workspacePaths: Object.freeze([...evidence.workspacePaths]),
      }),
    );
  }

  const findings = [...vulnerabilities.values()].map((vulnerability) => {
    const evidence = frozenCoordinateEvidence.get(
      packageCoordinateKey(vulnerability),
    );
    return Object.freeze({
      vulnerability,
      dependencies: evidence?.dependencies ?? Object.freeze([]),
      workspacePaths: evidence?.workspacePaths ?? Object.freeze([]),
      lastConfirmedAt,
    });
  });
  Object.freeze(findings);
  return { findings, truncated };
}

function cloneDependency(dependency: Dependency): Dependency {
  const dependencyPath =
    dependency.dependencyPath === undefined
      ? undefined
      : [...dependency.dependencyPath];
  if (dependencyPath !== undefined) {
    Object.freeze(dependencyPath);
  }
  const metadata =
    dependency.metadata === undefined
      ? undefined
      : Object.freeze(
          Object.fromEntries(
            Object.entries(dependency.metadata).map(([key, value]) => [
              key,
              Array.isArray(value) ? Object.freeze([...value]) : value,
            ]),
          ),
        );
  return Object.freeze({
    ...dependency,
    ...(dependencyPath === undefined ? {} : { dependencyPath }),
    ...(metadata === undefined ? {} : { metadata }),
  });
}

function cloneVulnerability(vulnerability: Vulnerability): Vulnerability {
  const aliases = [...vulnerability.aliases];
  const references = [...vulnerability.references];
  // Provider/cache validation requires Phase 5A fixed evidence. The fallback
  // keeps hand-built legacy test fixtures safe while every stored snapshot
  // exposes the normalized invariant.
  const legacyFixedVersions =
    vulnerability.fixedVersion === undefined
      ? []
      : [vulnerability.fixedVersion];
  const fixedVersions = (
    vulnerability.fixedVersions ?? legacyFixedVersions
  ).slice();
  const remediationCandidates = (
    vulnerability.remediationCandidates ??
    vulnerability.fixedVersions ??
    legacyFixedVersions
  ).slice();
  const severityDetails = vulnerability.severityDetails?.map((detail) =>
    Object.freeze({ ...detail }),
  );
  Object.freeze(aliases);
  Object.freeze(references);
  Object.freeze(fixedVersions);
  Object.freeze(remediationCandidates);
  if (severityDetails !== undefined) {
    Object.freeze(severityDetails);
  }
  return Object.freeze({
    ...vulnerability,
    aliases,
    references,
    fixedVersions,
    remediationCandidates,
    ...(severityDetails === undefined ? {} : { severityDetails }),
  });
}

function cloneResult(result: ScanResult): ScanResult {
  const packageManagers = [...result.packageManagers];
  // The displayed list is normally a reference subset of the unfiltered
  // provider list. Clone each provider record once and share the immutable
  // clone between both arrays so retaining policy evidence does not double
  // the potentially large finding-object graph.
  const vulnerabilityClones = new Map<Vulnerability, Vulnerability>();
  const cloneSharedVulnerability = (
    vulnerability: Vulnerability,
  ): Vulnerability => {
    const existing = vulnerabilityClones.get(vulnerability);
    if (existing !== undefined) {
      return existing;
    }
    const cloned = cloneVulnerability(vulnerability);
    vulnerabilityClones.set(vulnerability, cloned);
    return cloned;
  };
  const unfilteredVulnerabilities = result.unfilteredVulnerabilities?.map(
    cloneSharedVulnerability,
  );
  const vulnerabilities = result.vulnerabilities.map(
    cloneSharedVulnerability,
  );
  const dependencies = result.dependencies.map(cloneDependency);
  const errors = result.errors.map((error) => Object.freeze({ ...error }));
  const providerResults = result.providerResults.map((provider) =>
    Object.freeze({ ...provider }),
  );
  const ecosystemCoverage = result.ecosystemCoverage?.map((coverage) =>
    Object.freeze({
      ...coverage,
      packageManagers: Object.freeze([...coverage.packageManagers]),
    }),
  );
  const projectCoverage = result.projectCoverage?.map((coverage) =>
    Object.freeze({
      ...coverage,
      packageManagers: Object.freeze([...coverage.packageManagers]),
      manifestPaths: Object.freeze([...coverage.manifestPaths]),
    }),
  );
  Object.freeze(packageManagers);
  Object.freeze(vulnerabilities);
  if (unfilteredVulnerabilities !== undefined) {
    Object.freeze(unfilteredVulnerabilities);
  }
  Object.freeze(dependencies);
  Object.freeze(errors);
  Object.freeze(providerResults);
  if (ecosystemCoverage !== undefined) {
    Object.freeze(ecosystemCoverage);
  }
  if (projectCoverage !== undefined) {
    Object.freeze(projectCoverage);
  }
  return Object.freeze({
    ...result,
    packageManagers,
    vulnerabilities,
    ...(unfilteredVulnerabilities === undefined
      ? {}
      : { unfilteredVulnerabilities }),
    dependencies,
    errors,
    providerResults,
    ...(ecosystemCoverage === undefined ? {} : { ecosystemCoverage }),
    ...(projectCoverage === undefined ? {} : { projectCoverage }),
  });
}

function cloneResults(results: readonly ScanResult[]): readonly ScanResult[] {
  const cloned = results.map(cloneResult);
  Object.freeze(cloned);
  return cloned;
}

/**
 * Classifies the vulnerability coverage of one completed, possibly multi-root,
 * scan attempt. Cache write failures do not reduce provider coverage.
 */
export function classifyScanCoverage(
  results: readonly ScanResult[],
): ScanCoverage {
  if (results.length === 0) {
    return "not-scanned";
  }
  if (results.some((result) => result.cancelled)) {
    return "cancelled";
  }

  const providerResults = results.flatMap((result) => result.providerResults);
  const dependenciesScanned = results.reduce(
    (total, result) => total + result.dependenciesScanned,
    0,
  );
  const eligibleProviderResults = providerResults.filter(
    (provider) => provider.dependenciesEligible > 0,
  );
  const hasCoverageError = results.some((result) =>
    result.errors.some((error) => COVERAGE_ERROR_CODES.has(error.code)),
  );
  const hasEcosystemCoverageGap = results.some((result) =>
    (result.ecosystemCoverage ?? result.projectCoverage ?? []).some(
      (coverage) =>
        coverage.unresolved > 0 ||
        coverage.unsupported > 0 ||
        coverage.checked < coverage.resolved,
    ),
  );

  if (dependenciesScanned > 0 && providerResults.length === 0) {
    return "unavailable";
  }
  if (
    eligibleProviderResults.length > 0 &&
    eligibleProviderResults.every(
      (provider) =>
        provider.status === "unavailable" ||
        (provider.successful === 0 && provider.failed > 0),
    )
  ) {
    return "unavailable";
  }
  if (
    hasCoverageError ||
    hasEcosystemCoverageGap ||
    providerResults.some((provider) => provider.status !== "available")
  ) {
    return "partial";
  }
  return "complete";
}

function boundedMaximumListeners(value: number | undefined): number {
  const selected = value ?? DEFAULT_MAXIMUM_LISTENERS;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > HARD_MAXIMUM_LISTENERS
  ) {
    throw new RangeError(
      `maximumListeners must be between 1 and ${HARD_MAXIMUM_LISTENERS.toString()}`,
    );
  }
  return selected;
}

function boundedMaximumRetainedFindings(value: number | undefined): number {
  const selected = value ?? MAXIMUM_RETAINED_FINDINGS;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > MAXIMUM_RETAINED_FINDINGS
  ) {
    throw new RangeError(
      `maximumRetainedFindings must be between 1 and ${MAXIMUM_RETAINED_FINDINGS.toString()}`,
    );
  }
  return selected;
}

function timestamp(clock: () => number): string {
  const value = clock();
  if (!Number.isFinite(value)) {
    throw new RangeError("ScanResultStore clock returned a non-finite value");
  }
  return new Date(value).toISOString();
}

export class ScanResultStore implements DisposableLike {
  private revisionState = 0;
  private results: readonly ScanResult[] = EMPTY_RESULTS;
  private displayedCoverage: ScanCoverage = "not-scanned";
  private scanningState = false;
  private latestResults: readonly ScanResult[] = EMPTY_RESULTS;
  private latestCoverage: ScanCoverage = "not-scanned";
  private latestTimestamp: string | undefined;
  private successfulResults: readonly ScanResult[] = EMPTY_RESULTS;
  private successfulTimestamp: string | undefined;
  private retainedFindings: readonly RetainedVulnerabilityFinding[] =
    EMPTY_RETAINED_FINDINGS;
  private retainedFindingsTruncated = false;
  private readonly listeners = new Map<number, ScanResultStoreListener>();
  private readonly clock: () => number;
  private readonly maximumListeners: number;
  private readonly maximumRetainedFindings: number;
  private nextListenerId = 1;
  private disposed = false;

  public constructor(options: ScanResultStoreOptions = {}) {
    this.clock = options.clock ?? Date.now;
    this.maximumListeners = boundedMaximumListeners(options.maximumListeners);
    this.maximumRetainedFindings = boundedMaximumRetainedFindings(
      options.maximumRetainedFindings,
    );
  }

  public get scanning(): boolean {
    return this.scanningState;
  }

  public get latestAttempt(): readonly ScanResult[] {
    return this.latestResults;
  }

  public get latestAttemptTimestamp(): string | undefined {
    return this.latestTimestamp;
  }

  public get lastSuccessfulResult(): readonly ScanResult[] {
    return this.successfulResults;
  }

  public get lastSuccessfulTimestamp(): string | undefined {
    return this.successfulTimestamp;
  }

  public get retainedVulnerabilityFindings(): readonly RetainedVulnerabilityFinding[] {
    return this.retainedFindings;
  }

  /**
   * Read-only preview used to publish diagnostics atomically before replace().
   * It uses the same prior complete snapshot and configured limit as replace().
   */
  public previewRetainedFindings(
    currentResults: readonly ScanResult[],
  ): RetainedFindingDerivation {
    return deriveRetainedVulnerabilityFindings(
      this.successfulResults,
      currentResults,
      this.successfulTimestamp,
      this.maximumRetainedFindings,
    );
  }

  public get coverage(): ScanCoverage {
    return this.latestCoverage;
  }

  public getAll(): readonly ScanResult[] {
    // Replacement makes one immutable defensive copy, so UI reads are O(1)
    // even when a provider result approaches the scan-wide 64 MiB budget.
    return this.results;
  }

  public getSnapshot(): ScanResultStoreSnapshot {
    return Object.freeze({
      revision: this.revisionState,
      results: this.results,
      displayedCoverage: this.displayedCoverage,
      scanning: this.scanningState,
      latestAttempt: this.latestResults,
      latestAttemptCoverage: this.latestCoverage,
      ...(this.latestTimestamp === undefined
        ? {}
        : { latestAttemptTimestamp: this.latestTimestamp }),
      lastSuccessfulResult: this.successfulResults,
      ...(this.successfulTimestamp === undefined
        ? {}
        : { lastSuccessfulTimestamp: this.successfulTimestamp }),
      retainedFindings: this.retainedFindings,
      retainedFindingsTruncated: this.retainedFindingsTruncated,
    });
  }

  public onDidChange(listener: ScanResultStoreListener): DisposableLike {
    if (this.disposed) {
      throw new Error("ScanResultStore has been disposed");
    }
    if (this.listeners.size >= this.maximumListeners) {
      throw new RangeError(
        `ScanResultStore supports at most ${this.maximumListeners.toString()} listeners`,
      );
    }
    const listenerId = this.nextListenerId;
    this.nextListenerId += 1;
    this.listeners.set(listenerId, listener);
    let subscriptionDisposed = false;
    return {
      dispose: (): void => {
        if (!subscriptionDisposed) {
          subscriptionDisposed = true;
          this.listeners.delete(listenerId);
        }
      },
    };
  }

  public setScanning(scanning: boolean): void {
    if (this.scanningState === scanning) {
      return;
    }
    this.scanningState = scanning;
    this.revisionState += 1;
    this.emitChange();
  }

  public replace(results: readonly ScanResult[]): void {
    const attempt = cloneResults(results);
    const coverage = classifyScanCoverage(attempt);
    const completedAt = timestamp(this.clock);

    this.latestResults = attempt;
    this.latestCoverage = coverage;
    this.latestTimestamp = completedAt;
    this.scanningState = false;

    if (coverage === "not-scanned") {
      // Preserve replace([]) behavior from the original Phase 2 store.
      this.results = EMPTY_RESULTS;
      this.displayedCoverage = "not-scanned";
      this.retainedFindings = EMPTY_RETAINED_FINDINGS;
      this.retainedFindingsTruncated = false;
    } else if (coverage === "complete") {
      this.results = attempt;
      this.displayedCoverage = coverage;
      this.retainedFindings = EMPTY_RETAINED_FINDINGS;
      this.retainedFindingsTruncated = false;
    } else if (coverage === "partial") {
      // A partial result can contain newly confirmed vulnerabilities. Publish
      // it so current findings are never hidden, while retaining the last
      // complete result separately for explicit historical comparison.
      this.results = attempt;
      this.displayedCoverage = coverage;
      const retained = this.previewRetainedFindings(attempt);
      this.retainedFindings = retained.findings;
      this.retainedFindingsTruncated = retained.truncated;
    } else if (this.results.length === 0) {
      // A first failed attempt is still useful for provider/error empty states.
      this.results = attempt;
      this.displayedCoverage = coverage;
    }

    if (coverage === "complete") {
      this.successfulResults = attempt;
      this.successfulTimestamp = completedAt;
    }
    this.revisionState += 1;
    this.emitChange();
  }

  /**
   * Records an aborted latest attempt without replacing the last usable data.
   * This prevents a cancelled refresh from leaving a misleading clean status.
   */
  public recordCancelledAttempt(): void {
    this.latestResults = EMPTY_RESULTS;
    this.latestCoverage = "cancelled";
    this.latestTimestamp = timestamp(this.clock);
    this.scanningState = false;
    this.revisionState += 1;
    this.emitChange();
  }

  public clear(): void {
    this.results = EMPTY_RESULTS;
    this.displayedCoverage = "not-scanned";
    this.scanningState = false;
    this.latestResults = EMPTY_RESULTS;
    this.latestCoverage = "not-scanned";
    this.latestTimestamp = undefined;
    this.successfulResults = EMPTY_RESULTS;
    this.successfulTimestamp = undefined;
    this.retainedFindings = EMPTY_RETAINED_FINDINGS;
    this.retainedFindingsTruncated = false;
    this.revisionState += 1;
    this.emitChange();
  }

  public dispose(): void {
    this.disposed = true;
    this.listeners.clear();
  }

  private emitChange(): void {
    if (this.disposed) {
      return;
    }
    const snapshot = this.getSnapshot();
    for (const listener of [...this.listeners.values()]) {
      try {
        listener(snapshot);
      } catch {
        // A UI subscriber must not break scan-result publication.
      }
    }
  }
}
