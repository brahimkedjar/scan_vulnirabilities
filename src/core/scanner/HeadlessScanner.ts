import { resolve } from "node:path";

import type { Dependency } from "../../models/Dependency";
import type {
  ProjectCoverage,
  ProviderResult,
  ScanError,
  ScanResult,
} from "../../models/ScanResult";
import type { Severity, Vulnerability } from "../../models/Vulnerability";
import { buildCoverage } from "../../services/CoverageBuilder";
import {
  DependencyAuditService,
  type DependencyAuditCache,
  type DependencyAuditResult,
} from "../../services/DependencyAuditService";
import {
  classifyScanCoverage,
  type ScanCoverage,
} from "../../services/ScanResultStore";
import { mapDependencyToOsv } from "../../vulnerability/EcosystemMapper";
import type { VulnerabilityProvider } from "../../vulnerability/VulnerabilityProvider";
import {
  discoverDependencyProjects,
  type StaticDependencyDiscoveryResult,
  type StaticDiscoveryIssue,
} from "../discovery/StaticDependencyDiscovery";
import {
  isCoreCancellation,
  SYSTEM_CLOCK,
  type CoreClock,
  type CoreFileSystem,
  type CoreLogger,
} from "../host/HostContracts";
import { NodeFileSystemError } from "../host/NodeFileSystem";
import {
  parseStaticDependencyProject,
  type StaticParserOptions,
} from "./StaticParserBridge";

export interface HeadlessScannerOptions {
  readonly workspacePaths: readonly string[];
  readonly includeDevelopment: boolean;
  readonly includeProduction: boolean;
  readonly includeTransitive: boolean;
  readonly offline: boolean;
  readonly minimumSeverity: Severity;
  readonly maximumDependencies: number;
  readonly maximumFiles: number;
  readonly maximumBytes: number;
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
}

export interface HeadlessScannerDependencies {
  readonly fileSystem: CoreFileSystem;
  readonly provider?: VulnerabilityProvider;
  readonly clock?: CoreClock;
  readonly logger?: CoreLogger;
}

export type HeadlessScanStatus = "complete" | "incomplete" | "cancelled";

export interface HeadlessScanReason {
  readonly code: string;
  readonly message: string;
  readonly workspacePath?: string;
  readonly path?: string;
}

export interface HeadlessScanOutput {
  readonly schemaVersion: 1;
  readonly status: HeadlessScanStatus;
  readonly coverage: ScanCoverage;
  readonly offline: boolean;
  readonly results: readonly ScanResult[];
  readonly reasons: readonly HeadlessScanReason[];
  readonly limits: {
    readonly maximumDependencies: number;
    readonly maximumFiles: number;
    readonly maximumBytes: number;
    readonly timeoutMs: number;
  };
}

const HARD_MAXIMUM_DEPENDENCIES = 100_000;
const HARD_MAXIMUM_FILES = 2_000_000;
const HARD_MAXIMUM_BYTES = 2 * 1024 * 1024 * 1024;
const HARD_MAXIMUM_TIMEOUT_MS = 60 * 60 * 1_000;
const MAXIMUM_SCAN_ERRORS = 10_000;
const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  UNKNOWN: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const SILENT_LOGGER: CoreLogger = Object.freeze({
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
});

function checkedLimit(value: number, hardMaximum: number, name: string): number {
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > hardMaximum
  ) {
    throw new RangeError(`${name} is outside the supported safety range`);
  }
  return value;
}

function checkedNow(clock: CoreClock): number {
  const value = clock.now();
  if (!Number.isFinite(value)) {
    throw new RangeError("The headless scanner clock returned a non-finite value");
  }
  return value;
}

function discoveryError(issue: StaticDiscoveryIssue): ScanError {
  const code =
    issue.code === "FILE_LIMIT" || issue.code === "BYTE_LIMIT"
      ? "DEPENDENCY_LIMIT"
      : issue.code === "UNSUPPORTED_FORMAT"
        ? "UNSUPPORTED_LOCKFILE"
        : issue.code === "NO_LOCKFILE"
          ? "NO_LOCKFILE"
          : "WORKSPACE_ERROR";
  return {
    code,
    message: issue.message,
    ...(issue.path === undefined ? {} : { path: issue.path }),
  };
}

function stableDependencyKey(dependency: Dependency): string {
  return JSON.stringify([
    dependency.workspacePath ?? "",
    dependency.projectPath ?? "",
    dependency.manifestPath ?? dependency.packageJsonPath ?? "",
    dependency.ecosystem,
    dependency.name,
    dependency.installedVersion,
    dependency.dependencyType,
    dependency.environment,
    dependency.dependencyPath ?? [],
  ]);
}

function stableVulnerabilityKey(vulnerability: Vulnerability): string {
  return JSON.stringify([
    vulnerability.source,
    vulnerability.id,
    vulnerability.ecosystem,
    vulnerability.packageName,
    vulnerability.installedVersion,
  ]);
}

function deduplicateErrors(errors: readonly ScanError[]): ScanError[] {
  const unique = new Map<string, ScanError>();
  for (const error of errors) {
    const key = JSON.stringify([
      error.code,
      error.path ?? "",
      error.packageName ?? "",
      error.provider ?? "",
      error.message,
    ]);
    if (!unique.has(key) && unique.size < MAXIMUM_SCAN_ERRORS) {
      unique.set(key, error);
    }
  }
  return [...unique.values()].sort((left, right) =>
    JSON.stringify(left).localeCompare(JSON.stringify(right), "en"),
  );
}

function coverageForProject(
  workspacePath: string,
  projectPath: string,
  packageManager: string,
  manifestPaths: readonly string[],
  dependencies: readonly Dependency[],
): ProjectCoverage[] {
  const byEcosystem = new Map<string, Dependency[]>();
  for (const dependency of dependencies) {
    const values = byEcosystem.get(dependency.ecosystem) ?? [];
    values.push(dependency);
    byEcosystem.set(dependency.ecosystem, values);
  }
  return [...byEcosystem.entries()].map(([ecosystem, values]) => {
    const unresolved = values.filter(
      (dependency) =>
        dependency.resolutionStatus === "unresolved" ||
        (dependency.resolutionStatus === undefined &&
          dependency.installedVersion.length === 0),
    ).length;
    const unsupported = values.filter(
      (dependency) => dependency.resolutionStatus === "unsupported",
    ).length;
    const resolved = Math.max(0, values.length - unresolved - unsupported);
    return {
      workspacePath,
      projectPath,
      manifestPaths: [...manifestPaths].sort(),
      ecosystem,
      packageManagers: [packageManager],
      discovered: values.length,
      resolved,
      checked: 0,
      vulnerable: 0,
      unresolved,
      unsupported,
    };
  });
}

function emptyCache(): DependencyAuditCache {
  return {
    get: () => ({ status: "miss" }),
    setMany: async () => undefined,
  };
}

function offlineAudit(
  dependencies: readonly Dependency[],
  reason: string,
): DependencyAuditResult {
  const subjects = new Map<
    string,
    { readonly packageName: string; readonly ecosystem: string; readonly version: string }
  >();
  for (const dependency of dependencies) {
    const mapped = mapDependencyToOsv(dependency);
    if (!mapped.supported) continue;
    const key = JSON.stringify([
      mapped.identity.ecosystem,
      mapped.identity.packageName,
      mapped.identity.version,
    ]);
    subjects.set(key, {
      packageName: mapped.identity.packageName,
      ecosystem: mapped.identity.ecosystem,
      version: mapped.identity.version,
    });
  }
  const providerResult: ProviderResult = {
    provider: "OSV",
    status: "unavailable",
    dependenciesEligible: subjects.size,
    dependenciesSubmitted: 0,
    successful: 0,
    failed: subjects.size,
    cacheHits: 0,
    staleCacheFallbacks: 0,
    vulnerabilitiesFound: 0,
  };
  return {
    vulnerabilities: [],
    errors: [
      {
        code: "PROVIDER_ERROR",
        message: reason,
        provider: "OSV",
      },
    ],
    providerResult,
    subjectResults: [...subjects.values()].map((subject) => ({
      ...subject,
      ecosystem: subject.ecosystem as
        | "npm"
        | "PyPI"
        | "Maven"
        | "crates.io"
        | "Go"
        | "NuGet"
        | "Packagist",
      checked: false,
      vulnerabilityCount: 0,
    })),
    cancelled: false,
  };
}

function syntheticFailureResult(
  workspacePath: string,
  scannedAt: string,
  message: string,
  cancelled: boolean,
): ScanResult {
  return {
    workspacePath,
    scannedAt,
    durationMs: 0,
    packageManagers: [],
    dependenciesScanned: 0,
    vulnerableDependencies: 0,
    unfilteredVulnerabilities: [],
    vulnerabilities: [],
    dependencies: [],
    errors: [{ code: "WORKSPACE_ERROR", message, path: workspacePath }],
    providerResults: [],
    ecosystemCoverage: [],
    projectCoverage: [],
    cancelled,
  };
}

function statusFor(
  coverage: ScanCoverage,
  results: readonly ScanResult[],
): HeadlessScanStatus {
  if (coverage === "cancelled" || results.some((result) => result.cancelled)) {
    return "cancelled";
  }
  return coverage === "complete" ? "complete" : "incomplete";
}

export async function scanHeadlessWorkspaces(
  options: HeadlessScannerOptions,
  dependencies: HeadlessScannerDependencies,
): Promise<HeadlessScanOutput> {
  if (!Array.isArray(options.workspacePaths) || options.workspacePaths.length === 0) {
    throw new TypeError("At least one workspace path is required");
  }
  if (!options.includeDevelopment && !options.includeProduction) {
    throw new TypeError("At least one dependency environment must be selected");
  }
  const maximumDependencies = checkedLimit(
    options.maximumDependencies,
    HARD_MAXIMUM_DEPENDENCIES,
    "maximumDependencies",
  );
  const maximumFiles = checkedLimit(
    options.maximumFiles,
    HARD_MAXIMUM_FILES,
    "maximumFiles",
  );
  const maximumBytes = checkedLimit(
    options.maximumBytes,
    HARD_MAXIMUM_BYTES,
    "maximumBytes",
  );
  const timeoutMs = checkedLimit(
    options.timeoutMs,
    HARD_MAXIMUM_TIMEOUT_MS,
    "timeoutMs",
  );
  if (!(options.minimumSeverity in SEVERITY_RANK)) {
    throw new TypeError("minimumSeverity is invalid");
  }

  const clock = dependencies.clock ?? SYSTEM_CLOCK;
  const logger = dependencies.logger ?? SILENT_LOGGER;
  const controller = new AbortController();
  let timedOut = false;
  const onExternalAbort = (): void => controller.abort();
  options.signal?.addEventListener("abort", onExternalAbort, { once: true });
  if (options.signal?.aborted === true) controller.abort();
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const signal = controller.signal;
  const results: ScanResult[] = [];
  const reasons: HeadlessScanReason[] = [];
  let filesConsumed = 0;
  let candidateBytesConsumed = 0;
  let readBytesConsumed = 0;
  let dependenciesConsumed = 0;

  try {
    for (const requestedWorkspace of options.workspacePaths) {
      const started = checkedNow(clock);
      const scannedAt = new Date(started).toISOString();
      const workspacePath = resolve(requestedWorkspace);
      if (signal.aborted) {
        results.push(
          syntheticFailureResult(
            workspacePath,
            scannedAt,
            timedOut
              ? "The headless scan exceeded its configured timeout."
              : "The headless scan was cancelled.",
            true,
          ),
        );
        break;
      }
      if (
        filesConsumed >= maximumFiles ||
        candidateBytesConsumed >= maximumBytes ||
        dependenciesConsumed >= maximumDependencies
      ) {
        results.push(
          syntheticFailureResult(
            workspacePath,
            scannedAt,
            "A scan-wide resource limit was exhausted before this workspace was scanned.",
            false,
          ),
        );
        continue;
      }

      let discovery: StaticDependencyDiscoveryResult;
      try {
        discovery = await discoverDependencyProjects(
          dependencies.fileSystem,
          workspacePath,
          {
            maximumFiles: maximumFiles - filesConsumed,
            maximumBytes: maximumBytes - candidateBytesConsumed,
            signal,
          },
        );
      } catch (error: unknown) {
        if (isCoreCancellation(error)) {
          results.push(
            syntheticFailureResult(
              workspacePath,
              scannedAt,
              timedOut
                ? "The headless scan exceeded its configured timeout."
                : "The headless scan was cancelled.",
              true,
            ),
          );
          break;
        }
        const message =
          error instanceof NodeFileSystemError
            ? "The workspace root could not be opened through the confined filesystem host."
            : "The workspace could not be discovered safely.";
        results.push(
          syntheticFailureResult(workspacePath, scannedAt, message, false),
        );
        continue;
      }
      filesConsumed += discovery.entriesVisited;
      candidateBytesConsumed += discovery.candidateBytes;
      const readCache = new Map<string, Promise<string>>();
      const discoveredPaths = new Set(discovery.files.map((file) => file.path));
      const readText = (path: string): Promise<string> => {
        const existing = readCache.get(path);
        if (existing !== undefined) return existing;
        const operation = (async (): Promise<string> => {
          if (!discoveredPaths.has(path)) {
            throw new NodeFileSystemError(
              "INVALID_PATH",
              "A parser requested metadata that discovery did not authorize.",
              { path },
            );
          }
          const remaining = maximumBytes - readBytesConsumed;
          const value = await dependencies.fileSystem.readTextFile(
            discovery.root,
            path,
            Math.max(0, remaining),
            signal,
          );
          readBytesConsumed += value.bytes;
          return value.text;
        })();
        readCache.set(path, operation);
        return operation;
      };

      const parserOptions: StaticParserOptions = {
        includeDevelopment: options.includeDevelopment,
        includeProduction: options.includeProduction,
        includeTransitive: options.includeTransitive,
        ...(signal === undefined ? {} : { signal }),
      };
      const parsedDependencies: Dependency[] = [];
      const parseErrors: ScanError[] = discovery.issues.map(discoveryError);
      const adapterCoverage: ProjectCoverage[] = [];
      let parserCancelled = discovery.cancelled;
      for (const project of discovery.projects) {
        if (signal.aborted) {
          parserCancelled = true;
          break;
        }
        logger.info(`Static dependency parse: ${project.packageManager}`);
        const parsed = await parseStaticDependencyProject(
          project,
          discovery.root.path,
          discovery.files,
          readText,
          parserOptions,
        );
        parserCancelled ||= parsed.cancelled;
        parseErrors.push(...parsed.errors);
        let selected = [...parsed.dependencies].sort((left, right) =>
          stableDependencyKey(left).localeCompare(stableDependencyKey(right), "en"),
        );
        const remainingDependencies = maximumDependencies - dependenciesConsumed;
        if (selected.length > remainingDependencies) {
          selected = selected.slice(0, Math.max(0, remainingDependencies));
          parseErrors.push({
            code: "DEPENDENCY_LIMIT",
            message:
              "The scan-wide dependency record limit was reached; remaining records were omitted.",
            path: project.rootPath,
          });
        }
        if (parsed.truncated) {
          parseErrors.push({
            code: "DEPENDENCY_LIMIT",
            message: `${project.packageManager} parsing reached a bounded parser safety limit.`,
            path: project.rootPath,
          });
        }
        dependenciesConsumed += selected.length;
        parsedDependencies.push(...selected);
        adapterCoverage.push(
          ...coverageForProject(
            discovery.root.path,
            project.rootPath,
            project.packageManager,
            project.manifestPaths,
            selected,
          ),
        );
        if (dependenciesConsumed >= maximumDependencies) break;
      }

      const sortedDependencies = parsedDependencies.sort((left, right) =>
        stableDependencyKey(left).localeCompare(stableDependencyKey(right), "en"),
      );
      let audit: DependencyAuditResult;
      if (options.offline) {
        audit = offlineAudit(
          sortedDependencies,
          "Offline mode made no network requests, and no authenticated local vulnerability database is configured; vulnerability coverage is unknown.",
        );
      } else if (dependencies.provider === undefined) {
        audit = offlineAudit(
          sortedDependencies,
          "No vulnerability provider is configured for the headless scanner; vulnerability coverage is unknown.",
        );
      } else {
        const service = new DependencyAuditService(
          dependencies.provider,
          emptyCache(),
          { maximumDurationMs: timeoutMs },
        );
        audit = await service.audit(sortedDependencies, { signal });
      }
      const coverage = buildCoverage(
        adapterCoverage,
        sortedDependencies,
        audit,
      );
      const allVulnerabilities = [...audit.vulnerabilities].sort((left, right) =>
        stableVulnerabilityKey(left).localeCompare(
          stableVulnerabilityKey(right),
          "en",
        ),
      );
      const displayedVulnerabilities = allVulnerabilities.filter(
        (vulnerability) =>
          SEVERITY_RANK[vulnerability.severity] >=
          SEVERITY_RANK[options.minimumSeverity],
      );
      const vulnerableCoordinates = new Set(
        allVulnerabilities.map((vulnerability) =>
          JSON.stringify([
            vulnerability.ecosystem,
            vulnerability.packageName,
            vulnerability.installedVersion,
          ]),
        ),
      );
      const finished = checkedNow(clock);
      const result: ScanResult = {
        workspacePath: discovery.root.path,
        scannedAt,
        durationMs: Math.max(0, Math.round(finished - started)),
        packageManagers: [
          ...new Set(discovery.projects.map((project) => project.packageManager)),
        ].sort(),
        dependenciesScanned: sortedDependencies.length,
        vulnerableDependencies: vulnerableCoordinates.size,
        unfilteredVulnerabilities: allVulnerabilities,
        vulnerabilities: displayedVulnerabilities,
        dependencies: sortedDependencies,
        errors: deduplicateErrors([...parseErrors, ...audit.errors]),
        providerResults: [audit.providerResult],
        ecosystemCoverage: coverage.ecosystems,
        projectCoverage: coverage.projects,
        cancelled: parserCancelled || audit.cancelled || signal.aborted,
      };
      results.push(result);
      if (!discovery.complete) {
        reasons.push({
          code: "DISCOVERY_INCOMPLETE",
          message: "Static dependency discovery did not cover every workspace entry.",
          workspacePath: discovery.root.path,
        });
      }
      if (result.cancelled) break;
    }
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", onExternalAbort);
  }

  const coverage = classifyScanCoverage(results);
  for (const result of results) {
    for (const error of result.errors) {
      reasons.push({
        code: error.code,
        message: error.message,
        workspacePath: result.workspacePath,
        ...(error.path === undefined ? {} : { path: error.path }),
      });
    }
  }
  if (timedOut) {
    reasons.push({
      code: "TIMEOUT",
      message: "The scan exceeded its configured timeout and was cancelled.",
    });
  }
  const uniqueReasons = new Map<string, HeadlessScanReason>();
  for (const reason of reasons) {
    const key = JSON.stringify(reason);
    if (!uniqueReasons.has(key)) uniqueReasons.set(key, reason);
  }
  return {
    schemaVersion: 1,
    status: statusFor(coverage, results),
    coverage,
    offline: options.offline,
    results,
    reasons: [...uniqueReasons.values()].sort((left, right) =>
      JSON.stringify(left).localeCompare(JSON.stringify(right), "en"),
    ),
    limits: {
      maximumDependencies,
      maximumFiles,
      maximumBytes,
      timeoutMs,
    },
  };
}
