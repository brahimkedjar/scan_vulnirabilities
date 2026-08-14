import { constants as fileConstants, type Stats } from "node:fs";
import { lstat, open, realpath, type FileHandle } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import {
  analyzeContainerArchive,
  type ContainerArchiveAnalysis,
} from "../core/container/ContainerArchiveAnalyzer";
import type { CoreClock, CoreFileSystem } from "../core/host/HostContracts";
import { NodeFileSystem } from "../core/host/NodeFileSystem";
import {
  analyzeLicenseInventory,
  type LicenseEvidenceInput,
  type LicenseInventory,
  type LicensePolicy,
} from "../core/license/LicenseIntelligence";
import {
  AdvancedPolicyEngine,
  advancedPolicyFindingKey,
  type AdvancedPolicyResult,
} from "../core/policy/AdvancedPolicyEngine";
import {
  analyzeProvenance,
  type PackageProvenanceInput,
  type PackageSourceKind,
  type ProvenanceAnalysisResult,
} from "../core/provenance/ProvenanceIntelligence";
import {
  analyzeWorkspaceReachability,
} from "../core/reachability/NodeSourceCollector";
import {
  analyzeStaticReachability,
  type ReachabilityTargetInput,
  type StaticReachabilityFinding,
  type StaticReachabilityResult,
} from "../core/reachability/StaticReachability";
import {
  diffCycloneDxBoms,
  CycloneDxImportError,
  CycloneDxOperationError,
  importCycloneDxJson,
  mergeCycloneDxBoms,
  serializeCycloneDxBomDiff,
  serializeImportedCycloneDxBom,
  type ImportedCycloneDxBom,
} from "../core/sbom";
import {
  canonicalJson,
  parseBoundedJson,
  type JsonValue,
} from "../core/security/BoundedJson";
import {
  compareSecurityBaseline,
  createSecurityBaseline,
  diffSecuritySnapshots,
  SecurityBaselineError,
  SecurityHistoryError,
  SecuritySnapshotError,
  parseSecurityBaselineJson,
  parseSecuritySnapshotJson,
  serializeSecurityBaseline,
  serializeSecuritySnapshot,
  buildSecuritySnapshot,
  type SecuritySnapshot,
  type SecuritySnapshotDiff,
} from "../core/snapshot";
import {
  scanHeadlessWorkspaces,
  type HeadlessScanOutput,
} from "../core/scanner/HeadlessScanner";
import {
  createOfflineAdvisoryProvider,
  OfflineAdvisoryDatabaseError,
  type OfflineAdvisoryProvider,
} from "../core/vulnerability";
import type {
  SecurityReportDiffEvidence,
  SecurityReportKnownExploitationEvidence,
  SecurityReportLicenseEvidence,
  SecurityReportProvenanceEvidence,
  SecurityReportReachabilityEvidence,
} from "../core/reporting/SecurityReport";
import type { Dependency, DependencyMetadataValue } from "../models/Dependency";
import {
  scanResultKnownVulnerabilities,
  type ScanResult,
} from "../models/ScanResult";
import type { Severity, Vulnerability } from "../models/Vulnerability";
import type { SecurityGateResult } from "../policy/PolicyModels";
import { SecurityPolicyEngine } from "../policy/SecurityPolicyEngine";
import { CisaKevProvider, type CisaKevCache, type CisaKevCatalog } from "../intelligence/enrichment";
import { SecurityIntelligenceError, SecurityIntelligenceService, type SecurityIntelligenceSnapshot } from "../intelligence/SecurityIntelligenceService";
import type { VulnerabilityCacheKey } from "../services/VulnerabilityCache";
import { stableSha256 } from "../sbom/ComponentIdentity";
import { NetworkService } from "../services/NetworkService";
import { classifyScanCoverage } from "../services/ScanResultStore";
import { OsvProvider } from "../vulnerability/providers/OsvProvider";
import type { VulnerabilityProvider } from "../vulnerability/VulnerabilityProvider";
import {
  CLI_EXIT_CODES,
  CLI_USAGE,
  CliUsageError,
  parseCliArguments,
  type CliArguments,
  type CliExitCode,
  type CliFormat,
} from "./args";
import {
  CliOutputError,
  renderScanOutput,
  writeNewOutputFile,
} from "./output";

declare const __DEPENDENCY_AUDITOR_VERSION__: string | undefined;

const VERSION =
  typeof __DEPENDENCY_AUDITOR_VERSION__ === "string"
    ? __DEPENDENCY_AUDITOR_VERSION__
    : "0.9.0";
const MAXIMUM_POLICY_BYTES = 2 * 1024 * 1024;
const MAXIMUM_EVIDENCE_BYTES = 64 * 1024 * 1024;
const MAXIMUM_CONTAINER_BYTES = 128 * 1024 * 1024;
const SEVERITY_RANK: Readonly<Record<Severity, number>> = Object.freeze({
  UNKNOWN: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
});
const ADVANCED_POLICY_KEYS = new Set([
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

export interface CliIo {
  readonly stdout: (value: string) => void;
  readonly stderr: (value: string) => void;
}

export interface CliRuntime {
  readonly fileSystem?: CoreFileSystem;
  readonly provider?: VulnerabilityProvider;
  readonly clock?: CoreClock;
}

interface GateEvaluation {
  readonly exitCode: CliExitCode;
  readonly result: SecurityGateResult | AdvancedPolicyResult;
  readonly reportPolicy: SecurityGateResult;
  readonly intelligence?: SecurityIntelligenceSnapshot;
  readonly licenses?: LicenseInventory;
  readonly provenance?: ProvenanceAnalysisResult;
  readonly reachability?: StaticReachabilityResult;
  readonly reachabilityVulnerabilities?: ReadonlyMap<string, Vulnerability>;
}
interface OfflineDatabaseEvidence {
  readonly source: "local-file";
  readonly observedAt: string;
  readonly ageMs: number;
  readonly generatedAt: string;
  readonly validUntil: string;
  readonly payloadSha256: string;
  readonly entries: number;
  readonly vulnerabilities: number;
  readonly status: "current";
}

const PROCESS_IO: CliIo = Object.freeze({
  stdout: (value: string): void => {
    process.stdout.write(value);
  },
  stderr: (value: string): void => {
    process.stderr.write(value);
  },
});

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) throw new DOMException("Cancelled", "AbortError");
}

function safeErrorMessage(error: unknown): string {
  const value = error instanceof Error ? error.message : "Unknown failure";
  return value
    .replace(
      /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/gu,
      "\uFFFD",
    )
    .slice(0, 4_096);
}

function cliLogger(args: CliArguments, io: CliIo): {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
} {
  return {
    info: (message) => {
      if (args.verbose && !args.quiet) {
        io.stderr(`[info] ${safeErrorMessage(message)}\n`);
      }
    },
    warn: (message) => {
      if (!args.quiet) io.stderr(`[warn] ${safeErrorMessage(message)}\n`);
    },
    error: (message) => {
      if (!args.quiet) io.stderr(`[error] ${safeErrorMessage(message)}\n`);
    },
  };
}

function comparablePath(value: string): string {
  const normalized = resolve(value);
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function sameFile(left: Stats, right: Stats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs
  );
}

async function closeQuietly(handle: FileHandle | undefined): Promise<void> {
  try {
    await handle?.close();
  } catch {
    // Preserve the primary input error.
  }
}

/** Reads an explicitly named local file without following links or trusting a mutable path. */
async function readSafeBinaryInput(
  inputPath: string,
  maximumBytes: number,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  const absolute = resolve(inputPath);
  if (
    absolute.length > 32_768 ||
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > MAXIMUM_CONTAINER_BYTES
  ) {
    throw new CliUsageError("The input path or byte limit is invalid.");
  }
  let handle: FileHandle | undefined;
  try {
    throwIfAborted(signal);
    const requestedParent = resolve(dirname(absolute));
    const canonicalParent = await realpath(requestedParent);
    if (comparablePath(canonicalParent) !== comparablePath(requestedParent)) {
      throw new CliUsageError(
        "Input parent directories cannot contain symbolic links or junctions.",
      );
    }
    const before = await lstat(absolute);
    if (before.isSymbolicLink() || !before.isFile()) {
      throw new CliUsageError("The input must be a regular, non-linked file.");
    }
    if (before.size === 0 || before.size > maximumBytes) {
      throw new CliUsageError("The input is empty or exceeds its safety limit.");
    }
    const canonical = await realpath(absolute);
    if (comparablePath(canonical) !== comparablePath(absolute)) {
      throw new CliUsageError("The input cannot be reached through a link.");
    }
    handle = await open(
      absolute,
      fileConstants.O_RDONLY | (fileConstants.O_NOFOLLOW ?? 0),
    );
    const opened = await handle.stat();
    if (!opened.isFile() || !sameFile(before, opened)) {
      throw new CliUsageError("The input changed while it was being opened.");
    }
    const bytes = new Uint8Array(opened.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      throwIfAborted(signal);
      const result = await handle.read(
        bytes,
        offset,
        Math.min(64 * 1024, bytes.byteLength - offset),
        offset,
      );
      if (result.bytesRead < 1) {
        throw new CliUsageError("The input changed while it was being read.");
      }
      offset += result.bytesRead;
    }
    const openedAfter = await handle.stat();
    const pathAfter = await lstat(absolute);
    if (!sameFile(opened, openedAfter) || !sameFile(opened, pathAfter)) {
      throw new CliUsageError("The input changed while it was being read.");
    }
    return bytes;
  } catch (error: unknown) {
    if (error instanceof CliUsageError || error instanceof DOMException) {
      throw error;
    }
    throw new CliUsageError(`The input could not be read safely: ${safeErrorMessage(error)}`);
  } finally {
    await closeQuietly(handle);
  }
}

async function readSafeTextInput(
  path: string,
  maximumBytes: number,
  signal?: AbortSignal,
): Promise<string> {
  const bytes = await readSafeBinaryInput(path, maximumBytes, signal);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error: unknown) {
    throw new CliUsageError(
      `The input is not valid UTF-8: ${safeErrorMessage(error)}`,
    );
  }
}

async function readPolicy(
  path: string,
  signal?: AbortSignal,
): Promise<JsonValue> {
  const text = await readSafeTextInput(path, MAXIMUM_POLICY_BYTES, signal);
  try {
    return parseBoundedJson(text, {
      ...(signal === undefined ? {} : { signal }),
      limits: {
        maximumBytes: MAXIMUM_POLICY_BYTES,
        maximumDepth: 32,
        maximumNodes: 50_000,
        maximumObjectProperties: 10_000,
        maximumArrayItems: 10_000,
        maximumStringLength: 16_384,
      },
    });
  } catch (error: unknown) {
    throw new CliUsageError(
      `The policy is not valid bounded JSON: ${safeErrorMessage(error)}`,
    );
  }
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAdvancedPolicy(value: unknown): boolean {
  return (
    isRecord(value) &&
    Object.keys(value).some((key) => ADVANCED_POLICY_KEYS.has(key))
  );
}

function failOnPolicy(severity: Severity): JsonValue {
  return { schemaVersion: 1, minimumSeverity: severity };
}

function defaultGatePolicy(): JsonValue {
  return { schemaVersion: 1, minimumSeverity: "HIGH" };
}

function defaultLicensePolicy(): LicensePolicy {
  return Object.freeze({ unknownLicense: "review" as const });
}

function licensePolicyFromValue(value: unknown): LicensePolicy {
  if (!isRecord(value)) return defaultLicensePolicy();
  const list = (key: string): readonly string[] | undefined => {
    const selected = value[key];
    return Array.isArray(selected) && selected.every((item) => typeof item === "string")
      ? selected as readonly string[]
      : undefined;
  };
  const unknown = value.unknownLicense;
  const allowedLicenses = list("allowedLicenses");
  const deniedLicenses = list("deniedLicenses");
  const reviewRequiredLicenses = list("reviewRequiredLicenses");
  return {
    ...(allowedLicenses === undefined ? {} : { allowedLicenses }),
    ...(deniedLicenses === undefined ? {} : { deniedLicenses }),
    ...(reviewRequiredLicenses === undefined
      ? {}
      : { reviewRequiredLicenses }),
    unknownLicense:
      unknown === "allow" || unknown === "deny" || unknown === "review"
        ? unknown
        : "review",
  };
}

function metadataValue(
  dependency: Dependency,
  keys: readonly string[],
): DependencyMetadataValue | undefined {
  for (const key of keys) {
    const value = dependency.metadata?.[key];
    if (value !== undefined && value !== null) return value;
  }
  return undefined;
}

function metadataString(
  dependency: Dependency,
  keys: readonly string[],
): string | undefined {
  const value = metadataValue(dependency, keys);
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function dependencyEvidenceId(dependency: Dependency): string {
  return stableSha256(JSON.stringify([
    dependency.workspacePath ?? "",
    dependency.projectPath ?? "",
    dependency.manifestPath ?? dependency.packageJsonPath ?? "",
    dependency.ecosystem,
    dependency.name,
    dependency.installedVersion,
    dependency.dependencyType,
    dependency.environment,
    dependency.dependencyPath ?? [],
  ]));
}

function licenseInputs(results: readonly ScanResult[]): readonly LicenseEvidenceInput[] {
  return results.flatMap((result) =>
    result.dependencies.map((dependency) => {
      const declaration = metadataValue(dependency, [
        "license",
        "licenses",
        "declaredLicense",
        "licenseExpression",
      ]);
      const declaredLicense =
        typeof declaration === "string" ||
        (Array.isArray(declaration) && declaration.every((entry) => typeof entry === "string"))
          ? declaration as string | readonly string[]
          : undefined;
      return Object.freeze({
        dependencyId: dependencyEvidenceId(dependency),
        name: dependency.name,
        ecosystem: dependency.ecosystem,
        version: dependency.installedVersion || "UNKNOWN",
        dependencyType: dependency.dependencyType,
        ...(declaredLicense === undefined ? {} : { declaredLicense }),
        ...(declaredLicense === undefined
          ? {}
          : { evidenceSource: "dependency-metadata" }),
        ...(dependency.dependencyPath === undefined
          ? {}
          : { dependencyPath: dependency.dependencyPath }),
      });
    }),
  );
}

function sourceKind(value: string | undefined): PackageSourceKind | undefined {
  if (value === undefined) return undefined;
  const lower = value.toLowerCase();
  if (
    lower.startsWith("git:") ||
    lower.startsWith("git+") ||
    lower.startsWith("github:") ||
    lower.includes(".git#")
  ) return "git";
  if (
    lower.startsWith("file:") ||
    lower.startsWith("link:") ||
    lower.startsWith("path:") ||
    lower.startsWith("workspace:")
  ) return "local";
  if (
    lower.startsWith("registry") ||
    lower.startsWith("npm:") ||
    lower.startsWith("sparse+")
  ) return "registry";
  if (lower.startsWith("https://") || lower.startsWith("http://")) return "url";
  return undefined;
}

function provenanceInputs(
  results: readonly ScanResult[],
): readonly PackageProvenanceInput[] {
  return results.flatMap((result) =>
    result.dependencies.map((dependency) => {
      const lockfileSource = metadataString(dependency, [
        "source",
        "cargoSource",
        "composerSource",
      ]);
      const registry = metadataString(dependency, ["registry", "registryUrl"]);
      const repository = metadataString(dependency, ["repository", "repositoryUrl"]);
      const homepage = metadataString(dependency, ["homepage"]);
      const integrity = metadataString(dependency, ["integrity", "checksum", "contentHash"]);
      const resolvedUrl =
        metadataString(dependency, ["resolvedUrl", "resolved", "downloadUrl"]) ??
        (lockfileSource?.startsWith("https://") === true ? lockfileSource : undefined);
      const selectedSourceKind = sourceKind(lockfileSource);
      const purl = metadataString(dependency, ["purl", "packageUrl"]);
      const hasInstallScript = metadataValue(dependency, ["hasInstallScript"]);
      return Object.freeze({
        dependencyId: dependencyEvidenceId(dependency),
        packageName: dependency.name,
        ecosystem: dependency.ecosystem,
        version: dependency.installedVersion || "UNKNOWN",
        ...(purl === undefined ? {} : { packageUrl: purl }),
        ...(selectedSourceKind === undefined ? {} : { sourceKind: selectedSourceKind }),
        ...(registry === undefined ? {} : { registry }),
        ...(repository === undefined ? {} : { repository }),
        ...(homepage === undefined ? {} : { homepage }),
        ...(resolvedUrl === undefined ? {} : { resolvedUrl }),
        ...(lockfileSource === undefined ? {} : { lockfileSource }),
        ...(integrity === undefined
          ? {}
          : { integrity, integrityVerification: "unverified" as const }),
        ...(typeof hasInstallScript === "boolean" ? { hasInstallScript } : {}),
      });
    }),
  );
}

function analyzeLicenses(
  scan: HeadlessScanOutput,
  policy: LicensePolicy,
  signal?: AbortSignal,
): LicenseInventory {
  return analyzeLicenseInventory(licenseInputs(scan.results), policy, {
    maximumRecords: scan.limits.maximumDependencies,
    ...(signal === undefined ? {} : { signal }),
  });
}

function cisaKevCacheKey(key: VulnerabilityCacheKey): string {
  return JSON.stringify([key.provider, key.ecosystem, key.packageName, key.version]);
}

class CliCisaKevCache implements CisaKevCache {
  private readonly values = new Map<string, CisaKevCatalog>();

  public get(key: VulnerabilityCacheKey): ReturnType<CisaKevCache["get"]> {
    const value = this.values.get(cisaKevCacheKey(key));
    if (value === undefined) {
      return Object.freeze({ status: "miss" as const });
    }
    const fetchedAt = Date.parse(value.fetchedAt);
    if (!Number.isFinite(fetchedAt) || fetchedAt < 0) {
      return Object.freeze({ status: "miss" as const });
    }
    return Object.freeze({
      status: "fresh" as const,
      value,
      fetchedAt,
      expiresAt: fetchedAt + 24 * 60 * 60 * 1_000,
    });
  }

  public async setSuccessful(key: VulnerabilityCacheKey, value: CisaKevCatalog): Promise<void> {
    this.values.set(cisaKevCacheKey(key), value);
  }
}

async function loadSecurityIntelligence(
  scan: HeadlessScanOutput,
  args: CliArguments,
  runtime: CliRuntime,
  signal?: AbortSignal,
): Promise<SecurityIntelligenceSnapshot | undefined> {
  if (args.offline) {
    return undefined;
  }
  const vulnerabilities = scan.results.flatMap((result) =>
    scanResultKnownVulnerabilities(result).filter(
      (vulnerability) => vulnerability.source === "OSV",
    ),
  );
  if (vulnerabilities.length === 0) {
    return undefined;
  }
  const kevNetwork = new NetworkService({
    allowedHosts: ["www.cisa.gov"],
    timeoutMs: Math.min(args.timeoutMs, 60_000),
    maximumAttempts: args.refresh ? 3 : 2,
    maximumRequestBytes: 1_024,
    maximumResponseBytes: 4 * 1024 * 1024,
  });
  const clock = runtime.clock;
  const kevAnalysis = new SecurityIntelligenceService(
    new CisaKevProvider(kevNetwork, new CliCisaKevCache()),
    clock === undefined ? {} : { clock: () => clock.now() },
  );
  try {
    return await kevAnalysis.analyze(vulnerabilities, {
      ...(signal === undefined ? {} : { signal }),
    });
  } catch (error: unknown) {
    if (
      error instanceof SecurityIntelligenceError &&
      error.code === "LIMIT_EXCEEDED"
    ) {
      return undefined;
    }
    throw error;
  }
}

function analyzePackageProvenance(
  scan: HeadlessScanOutput,
  signal?: AbortSignal,
): ProvenanceAnalysisResult {
  return analyzeProvenance(provenanceInputs(scan.results), {
    maximumRecords: scan.limits.maximumDependencies,
    ...(signal === undefined ? {} : { signal }),
  });
}

function reachabilityTargets(scan: HeadlessScanOutput): {
  readonly targets: readonly ReachabilityTargetInput[];
  readonly vulnerabilities: ReadonlyMap<string, Vulnerability>;
  readonly unsupported: number;
} {
  const targets = new Map<string, ReachabilityTargetInput>();
  const vulnerabilities = new Map<string, Vulnerability>();
  let unsupported = 0;
  for (const result of scan.results) {
    for (const vulnerability of scanResultKnownVulnerabilities(result)) {
      if (vulnerability.ecosystem !== "npm" && vulnerability.ecosystem !== "PyPI") {
        unsupported += 1;
        continue;
      }
      const targetId = advancedPolicyFindingKey(vulnerability);
      targets.set(targetId, Object.freeze({
        targetId,
        ecosystem: vulnerability.ecosystem,
        packageName: vulnerability.packageName,
      }));
      vulnerabilities.set(targetId, vulnerability);
    }
  }
  return {
    targets: Object.freeze([...targets.values()].sort((left, right) =>
      left.targetId.localeCompare(right.targetId, "en"),
    )),
    vulnerabilities,
    unsupported,
  };
}

function selectReachabilityFinding(
  values: readonly StaticReachabilityFinding[],
): StaticReachabilityFinding | undefined {
  return (
    values.find((value) => value.status === "REACHABLE") ??
    values.find((value) => value.status === "UNKNOWN") ??
    values[0]
  );
}

async function analyzeReachability(
  args: CliArguments,
  scan: HeadlessScanOutput,
  fileSystem: CoreFileSystem,
  signal?: AbortSignal,
): Promise<{
  readonly analysis: StaticReachabilityResult;
  readonly unsupportedTargets: number;
  readonly vulnerabilities: ReadonlyMap<string, Vulnerability>;
}> {
  const selected = reachabilityTargets(scan);
  const roots = args.workspacePaths.length > 0 ? args.workspacePaths : ["."];
  const perRootFiles = Math.max(1, Math.floor(Math.min(args.maximumFiles, 20_000) / roots.length));
  const aggregateBytes = Math.min(args.maximumBytes, 32 * 1024 * 1024);
  const perRootBytes = Math.max(1, Math.floor(aggregateBytes / roots.length));
  const analyses: StaticReachabilityResult[] = [];
  for (const workspace of roots) {
    try {
      analyses.push(await analyzeWorkspaceReachability(
        fileSystem,
        workspace,
        selected.targets,
        {
          maximumEntries: perRootFiles,
          maximumCandidateBytes: perRootBytes,
          maximumSourceBytesPerFile: Math.min(perRootBytes, 2 * 1024 * 1024),
          limits: {
            maximumFiles: perRootFiles,
            maximumBytes: perRootBytes,
            maximumTargets: Math.min(args.maximumDependencies, 10_000),
          },
          ...(signal === undefined ? {} : { signal }),
        },
      ));
    } catch {
      analyses.push(analyzeStaticReachability(
        { sources: [], targets: selected.targets },
        { ...(signal === undefined ? {} : { signal }) },
      ));
    }
  }
  const findings = selected.targets.flatMap((target) => {
    const candidates = analyses.flatMap((analysis) =>
      analysis.findings.filter((finding) => finding.targetId === target.targetId),
    );
    const picked = selectReachabilityFinding(candidates);
    return picked === undefined ? [] : [picked];
  });
  const complete =
    selected.unsupported === 0 &&
    analyses.length > 0 &&
    analyses.every((analysis) => analysis.coverage.analysisComplete);
  const analysis: StaticReachabilityResult = Object.freeze({
    findings: Object.freeze(findings),
    coverage: Object.freeze({
      sourceFilesTotal: analyses.reduce((sum, item) => sum + item.coverage.sourceFilesTotal, 0),
      sourceFilesAnalyzed: analyses.reduce((sum, item) => sum + item.coverage.sourceFilesAnalyzed, 0),
      sourceFilesInvalid: analyses.reduce((sum, item) => sum + item.coverage.sourceFilesInvalid, 0),
      sourceFilesOmitted: analyses.reduce((sum, item) => sum + item.coverage.sourceFilesOmitted, 0),
      bytesAnalyzed: analyses.reduce((sum, item) => sum + item.coverage.bytesAnalyzed, 0),
      targetsTotal: selected.targets.length + selected.unsupported,
      targetsAnalyzed: selected.targets.length,
      entrypointsResolved: analyses.reduce((sum, item) => sum + item.coverage.entrypointsResolved, 0),
      importEdgesObserved: analyses.reduce((sum, item) => sum + item.coverage.importEdgesObserved, 0),
      uncertainReachableFiles: analyses.reduce((sum, item) => sum + item.coverage.uncertainReachableFiles, 0),
      truncated: analyses.some((item) => item.coverage.truncated),
      cancelled: analyses.some((item) => item.coverage.cancelled),
      analysisComplete: complete,
    }),
  });
  return {
    analysis,
    unsupportedTargets: selected.unsupported,
    vulnerabilities: selected.vulnerabilities,
  };
}

function licenseReportEvidence(
  inventory: LicenseInventory,
): readonly SecurityReportLicenseEvidence[] {
  return inventory.entries.map((entry) => ({
    ecosystem: entry.ecosystem,
    packageName: entry.name,
    version: entry.version,
    ...(entry.normalizedExpressions.length === 1
      ? { expression: entry.normalizedExpressions[0] }
      : {}),
    status: entry.finding.outcome,
    ...(entry.evidenceSource === undefined
      ? {}
      : { evidenceSource: entry.evidenceSource }),
  }));
}

function provenanceReportEvidence(
  provenance: ProvenanceAnalysisResult,
): readonly SecurityReportProvenanceEvidence[] {
  return provenance.packages.map((entry) => ({
    ecosystem: entry.ecosystem,
    packageName: entry.packageName,
    version: entry.version,
    status: entry.status,
    evidence: entry.anomalies.map((anomaly) => anomaly.evidence),
    limitations: entry.limitations,
  }));
}

function reachabilityReportEvidence(
  result: StaticReachabilityResult,
  vulnerabilities: ReadonlyMap<string, Vulnerability>,
): readonly SecurityReportReachabilityEvidence[] {
  return result.findings.map((entry) => ({
    ecosystem: entry.ecosystem,
    packageName: entry.packageName,
    version: vulnerabilities.get(entry.targetId)?.installedVersion ?? "UNKNOWN",
    status: entry.status,
    confidence: entry.confidence,
    ...(entry.path.length === 0 ? {} : { path: entry.path }),
    limitations: entry.limitations,
  }));
}

function knownExploitationReportEvidence(
  intelligence: SecurityIntelligenceSnapshot,
): readonly SecurityReportKnownExploitationEvidence[] {
  return intelligence.findings.map((finding) => ({
    advisoryId: finding.advisoryId,
    ecosystem: finding.ecosystem,
    packageName: finding.packageName,
    installedVersion: finding.installedVersion,
    status: finding.knownExploitation.status === "KNOWN_EXPLOITED"
      ? "known-exploited"
      : finding.knownExploitation.status === "NOT_LISTED"
        ? "not-known-exploited"
        : "unknown",
    source: finding.knownExploitation.source,
  }));
}

function snapshotTimestamp(scan: HeadlessScanOutput, runtime: CliRuntime): string {
  return scan.results[0]?.scannedAt ??
    new Date(runtime.clock?.now() ?? 0).toISOString();
}

function buildSnapshot(
  scan: HeadlessScanOutput,
  args: CliArguments,
  runtime: CliRuntime,
  policy?: SecurityGateResult,
  signal?: AbortSignal,
): SecuritySnapshot {
  return buildSecuritySnapshot(scan.results, {
    timestamp: snapshotTimestamp(scan, runtime),
    scannerVersion: VERSION,
    workspaceIdentity: JSON.stringify([...args.workspacePaths].sort()),
    ...(policy === undefined ? {} : { policy }),
    ...(signal === undefined ? {} : { signal }),
  });
}

function snapshotDiffEvidence(diff: SecuritySnapshotDiff): SecurityReportDiffEvidence {
  return {
    status: diff.complete ? "COMPLETE" : "INCOMPLETE",
    addedDependencies:
      diff.dependencies.added.length + diff.dependencies.unknownAdditions.length,
    removedDependencies:
      diff.dependencies.removed.length + diff.dependencies.unknownRemovals.length,
    changedDependencies:
      diff.dependencies.versionChanges.length +
      diff.dependencies.unknownVersionChanges.length +
      diff.dependencies.evidenceChanges.length,
    newVulnerabilities:
      diff.vulnerabilities.added.length +
      diff.vulnerabilities.unknownPreviouslyUnobserved.length,
    resolvedVulnerabilities:
      diff.vulnerabilities.resolved.length,
    unknownAbsences:
      diff.dependencies.unknownRemovals.length +
      diff.vulnerabilities.unknownNoLongerObserved.length,
  };
}

async function evaluateGate(
  args: CliArguments,
  scan: HeadlessScanOutput,
  runtime: CliRuntime,
  fileSystem: CoreFileSystem,
  signal?: AbortSignal,
): Promise<GateEvaluation> {
  const rawPolicy =
    args.policyPath !== undefined
      ? await readPolicy(args.policyPath, signal)
      : args.failOn !== undefined
        ? failOnPolicy(args.failOn)
        : defaultGatePolicy();
  const intelligence = await loadSecurityIntelligence(scan, args, runtime, signal);
  if (!isAdvancedPolicy(rawPolicy)) {
    const gate = new SecurityPolicyEngine({
      ...(runtime.clock === undefined
        ? {}
        : { clock: () => runtime.clock?.now() ?? 0 }),
    }).evaluate(scan.results, rawPolicy, {
      coverage: scan.coverage,
      ...(intelligence === undefined ? {} : { findingIntelligence: intelligence.policyFindings }),
      ...(signal === undefined ? {} : { signal }),
    });
    return {
      exitCode: !gate.policyValid
        ? CLI_EXIT_CODES.INVALID_CONFIGURATION
        : !gate.complete
          ? CLI_EXIT_CODES.INCOMPLETE
          : gate.status === "FAIL"
            ? CLI_EXIT_CODES.POLICY_VIOLATION
            : CLI_EXIT_CODES.SUCCESS,
      result: gate,
      reportPolicy: gate,
      ...(intelligence === undefined ? {} : { intelligence }),
    };
  }
  const licenses = analyzeLicenses(scan, defaultLicensePolicy(), signal);
  const provenance = analyzePackageProvenance(scan, signal);
  const needsReachability =
    isRecord(rawPolicy) && rawPolicy.minimumReachableSeverity !== undefined;
  const reachabilityAnalysis = needsReachability
    ? await analyzeReachability(args, scan, fileSystem, signal)
    : undefined;
  const reachability = reachabilityAnalysis?.analysis;
  const result = new AdvancedPolicyEngine({
    maximumDependencies: args.maximumDependencies,
    maximumFindings: args.maximumDependencies,
    maximumEvidenceRecords: args.maximumDependencies,
    ...(runtime.clock === undefined
      ? {}
      : { clock: () => runtime.clock?.now() ?? 0 }),
  }).evaluate(scan.results, rawPolicy, {
    coverage: scan.coverage,
    ...(intelligence === undefined ? {} : { findingIntelligence: intelligence.policyFindings }),
    licenses,
    provenance,
    ...(reachability === undefined ? {} : { reachability }),
    ...(signal === undefined ? {} : { signal }),
  });
  return {
    exitCode: !result.policyValid
      ? CLI_EXIT_CODES.INVALID_CONFIGURATION
      : !result.complete
        ? CLI_EXIT_CODES.INCOMPLETE
        : result.status === "FAIL"
          ? CLI_EXIT_CODES.POLICY_VIOLATION
          : CLI_EXIT_CODES.SUCCESS,
    result,
    reportPolicy: result.base,
    ...(intelligence === undefined ? {} : { intelligence }),
    licenses,
    provenance,
    ...(reachability === undefined ? {} : { reachability }),
    ...(reachabilityAnalysis === undefined
      ? {}
      : { reachabilityVulnerabilities: reachabilityAnalysis.vulnerabilities }),
  };
}
function findingThresholdViolated(
  results: readonly ScanResult[],
  threshold: Severity,
): boolean {
  return results.some((result) =>
    scanResultKnownVulnerabilities(result).some(
      (vulnerability) =>
        SEVERITY_RANK[vulnerability.severity] >= SEVERITY_RANK[threshold],
    ),
  );
}

async function emit(args: CliArguments, value: string, io: CliIo): Promise<void> {
  if (args.outputPath !== undefined) {
    await writeNewOutputFile(args.outputPath, value);
    if (!args.quiet) io.stderr(`Report created: ${args.outputPath}\n`);
  } else if (!args.quiet || args.format !== "text") {
    io.stdout(value);
  }
}

function serialized(value: unknown, pretty = false): string {
  return pretty
    ? `${JSON.stringify(value, null, 2)}\n`
    : `${canonicalJson(value as JsonValue)}\n`;
}

function requireFormats(args: CliArguments, allowed: readonly CliFormat[]): void {
  if (!allowed.includes(args.format)) {
    throw new CliUsageError(
      `${args.command} does not support --format ${args.format}.`,
    );
  }
}

function importedBomComplete(bom: ImportedCycloneDxBom): boolean {
  return (
    bom.coverage.inventory === "complete" &&
    bom.coverage.vulnerabilityAnalysis === "complete" &&
    bom.coverage.dependencyGraph === "complete" &&
    bom.conflicts.length === 0
  );
}

async function runSbomCommand(
  args: CliArguments,
  io: CliIo,
  signal?: AbortSignal,
): Promise<CliExitCode> {
  requireFormats(args, ["text", "json"]);
  const paths = args.workspacePaths;
  if (args.subcommand === "import") {
    if (paths.length !== 1) throw new CliUsageError("sbom import requires exactly one file.");
    const text = await readSafeTextInput(paths[0] ?? "", MAXIMUM_EVIDENCE_BYTES, signal);
    const bom = importCycloneDxJson(text, { ...(signal === undefined ? {} : { signal }) });
    await emit(args, serializeImportedCycloneDxBom(bom), io);
    return importedBomComplete(bom) ? CLI_EXIT_CODES.SUCCESS : CLI_EXIT_CODES.INCOMPLETE;
  }
  if (args.subcommand === "diff") {
    if (paths.length !== 2) throw new CliUsageError("sbom diff requires exactly two files.");
    const before = importCycloneDxJson(
      await readSafeTextInput(paths[0] ?? "", MAXIMUM_EVIDENCE_BYTES, signal),
      { ...(signal === undefined ? {} : { signal }) },
    );
    const after = importCycloneDxJson(
      await readSafeTextInput(paths[1] ?? "", MAXIMUM_EVIDENCE_BYTES, signal),
      { ...(signal === undefined ? {} : { signal }) },
    );
    const diff = diffCycloneDxBoms(before, after, {
      ...(signal === undefined ? {} : { signal }),
    });
    await emit(args, serializeCycloneDxBomDiff(diff), io);
    return diff.complete ? CLI_EXIT_CODES.SUCCESS : CLI_EXIT_CODES.INCOMPLETE;
  }
  if (args.subcommand === "merge") {
    if (paths.length < 1 || paths.length > 256) {
      throw new CliUsageError("sbom merge requires between one and 256 files.");
    }
    const boms: ImportedCycloneDxBom[] = [];
    for (const path of paths) {
      boms.push(importCycloneDxJson(
        await readSafeTextInput(path, MAXIMUM_EVIDENCE_BYTES, signal),
        { ...(signal === undefined ? {} : { signal }) },
      ));
    }
    const merged = mergeCycloneDxBoms(boms, {
      ...(signal === undefined ? {} : { signal }),
    });
    await emit(args, serializeImportedCycloneDxBom(merged), io);
    return importedBomComplete(merged) ? CLI_EXIT_CODES.SUCCESS : CLI_EXIT_CODES.INCOMPLETE;
  }
  throw new CliUsageError("sbom requires import, diff, or merge.");
}

async function runSnapshotDiffCommand(
  args: CliArguments,
  io: CliIo,
  signal?: AbortSignal,
): Promise<CliExitCode> {
  requireFormats(args, ["text", "json"]);
  if (args.workspacePaths.length !== 2) {
    throw new CliUsageError("diff requires exactly two snapshot files.");
  }
  const before = parseSecuritySnapshotJson(
    await readSafeTextInput(args.workspacePaths[0] ?? "", MAXIMUM_EVIDENCE_BYTES, signal),
    { ...(signal === undefined ? {} : { signal }) },
  );
  const after = parseSecuritySnapshotJson(
    await readSafeTextInput(args.workspacePaths[1] ?? "", MAXIMUM_EVIDENCE_BYTES, signal),
    { ...(signal === undefined ? {} : { signal }) },
  );
  const diff = diffSecuritySnapshots(before, after, {
    ...(signal === undefined ? {} : { signal }),
  });
  await emit(args, serialized(diff), io);
  return diff.complete ? CLI_EXIT_CODES.SUCCESS : CLI_EXIT_CODES.INCOMPLETE;
}

async function runContainerCommand(
  args: CliArguments,
  io: CliIo,
  signal?: AbortSignal,
): Promise<CliExitCode> {
  requireFormats(args, ["text", "json"]);
  if (args.workspacePaths.length !== 1) {
    throw new CliUsageError("container requires exactly one local archive.");
  }
  const maximumArchiveBytes = Math.min(args.maximumBytes, MAXIMUM_CONTAINER_BYTES);
  const bytes = await readSafeBinaryInput(
    args.workspacePaths[0] ?? "",
    maximumArchiveBytes,
    signal,
  );
  const analysis: ContainerArchiveAnalysis = analyzeContainerArchive(bytes, {
    limits: { maximumArchiveBytes },
    ...(signal === undefined ? {} : { signal }),
  });
  await emit(args, serialized(analysis, args.format === "text"), io);
  // OS-package vulnerability and license evidence are intentionally unavailable.
  return CLI_EXIT_CODES.INCOMPLETE;
}

async function scanWithArguments(
  args: CliArguments,
  io: CliIo,
  runtime: CliRuntime,
  fileSystem: CoreFileSystem,
  signal?: AbortSignal,
): Promise<HeadlessScanOutput> {
  const logger = cliLogger(args, io);
  const network = new NetworkService({
    allowedHosts: ["api.osv.dev"],
    timeoutMs: Math.min(args.timeoutMs, 60_000),
    maximumAttempts: args.refresh ? 3 : 2,
  });
  const defaultProvider = new OsvProvider(network, {
    info: (message) => logger.info(message),
    warn: (message) => logger.warn(message),
    error: (message) => logger.error(message),
    show: () => undefined,
  });
  let offlineProvider: OfflineAdvisoryProvider | undefined;
  if (args.offlineDatabasePath !== undefined) {
    const database = await readSafeTextInput(
      args.offlineDatabasePath,
      32 * 1024 * 1024,
      signal,
    );
    offlineProvider = createOfflineAdvisoryProvider(database, {
      ...(signal === undefined ? {} : { signal }),
      ...(runtime.clock === undefined ? {} : { now: runtime.clock.now() }),
    });
  }
  const scan = await scanHeadlessWorkspaces(
    {
      workspacePaths: args.workspacePaths,
      includeDevelopment: args.includeDevelopment,
      includeProduction: args.includeProduction,
      includeTransitive: args.includeTransitive,
      // A validated local provider is safe to query while the user-facing
      // mode remains offline; no network-capable provider is supplied.
      offline: args.offline && offlineProvider === undefined,
      minimumSeverity: args.severity,
      maximumDependencies: args.maximumDependencies,
      maximumFiles: args.maximumFiles,
      maximumBytes: args.maximumBytes,
      timeoutMs: args.timeoutMs,
      ...(signal === undefined ? {} : { signal }),
    },
    {
      fileSystem,
      ...(offlineProvider === undefined
        ? args.offline
          ? {}
          : { provider: runtime.provider ?? defaultProvider }
        : { provider: offlineProvider }),
      ...(runtime.clock === undefined ? {} : { clock: runtime.clock }),
      logger,
    },
  );
  if (offlineProvider === undefined) return scan;
  const observedAtMs = runtime.clock?.now() ?? Date.now();
  const evidence: OfflineDatabaseEvidence = Object.freeze({
    source: "local-file",
    observedAt: new Date(observedAtMs).toISOString(),
    ageMs: Math.max(0, observedAtMs - Date.parse(offlineProvider.metadata.generatedAt)),
    generatedAt: offlineProvider.metadata.generatedAt,
    validUntil: offlineProvider.metadata.validUntil,
    payloadSha256: offlineProvider.metadata.payloadSha256,
    entries: offlineProvider.metadata.entries,
    vulnerabilities: offlineProvider.metadata.vulnerabilities,
    status: offlineProvider.metadata.status,
  });
  return Object.freeze({
    ...scan,
    offline: true,
    offlineAdvisoryDatabase: evidence,
  });
}

function scanArgsWithWorkspaces(
  args: CliArguments,
  workspacePaths: readonly string[],
): CliArguments {
  return { ...args, workspacePaths };
}

async function runBaselineCommand(
  args: CliArguments,
  io: CliIo,
  runtime: CliRuntime,
  fileSystem: CoreFileSystem,
  signal?: AbortSignal,
): Promise<CliExitCode> {
  requireFormats(args, ["text", "json"]);
  if (args.subcommand === "create") {
    const scan = await scanWithArguments(args, io, runtime, fileSystem, signal);
    const snapshot = buildSnapshot(scan, args, runtime, undefined, signal);
    const baseline = createSecurityBaseline(snapshot, {
      createdAt: snapshotTimestamp(scan, runtime),
    });
    await emit(args, serializeSecurityBaseline(baseline), io);
    return snapshot.coverage.status === "complete"
      ? CLI_EXIT_CODES.SUCCESS
      : CLI_EXIT_CODES.INCOMPLETE;
  }
  if (args.subcommand === "compare") {
    const baselinePath = args.workspacePaths[0];
    if (baselinePath === undefined) {
      throw new CliUsageError("baseline compare requires a baseline file.");
    }
    const workspacePaths = args.workspacePaths.slice(1);
    const scanArgs = scanArgsWithWorkspaces(
      args,
      workspacePaths.length === 0 ? ["."] : workspacePaths,
    );
    const baseline = parseSecurityBaselineJson(
      await readSafeTextInput(baselinePath, MAXIMUM_EVIDENCE_BYTES, signal),
      { ...(signal === undefined ? {} : { signal }) },
    );
    const scan = await scanWithArguments(scanArgs, io, runtime, fileSystem, signal);
    const snapshot = buildSnapshot(scan, scanArgs, runtime, undefined, signal);
    const diff = compareSecurityBaseline(baseline, snapshot, {
      ...(signal === undefined ? {} : { signal }),
    });
    await emit(args, serialized(diff), io);
    return diff.complete ? CLI_EXIT_CODES.SUCCESS : CLI_EXIT_CODES.INCOMPLETE;
  }
  throw new CliUsageError("baseline requires create or compare.");
}

function renderGate(
  args: CliArguments,
  scan: HeadlessScanOutput,
  gate: GateEvaluation,
  baselineDiff?: SecuritySnapshotDiff,
): string {
  const evidence = {
    policy: gate.reportPolicy,
    ...(gate.licenses === undefined
      ? {}
      : { licenses: licenseReportEvidence(gate.licenses) }),
    ...(gate.provenance === undefined
      ? {}
      : { provenance: provenanceReportEvidence(gate.provenance) }),
    ...(gate.reachability === undefined
      ? {}
      : {
          reachability: reachabilityReportEvidence(
            gate.reachability,
            gate.reachabilityVulnerabilities ?? new Map(),
          ),
        }),
    ...(gate.intelligence === undefined
      ? {}
      : { knownExploitation: knownExploitationReportEvidence(gate.intelligence) }),
    ...(baselineDiff === undefined
      ? {}
      : { diff: snapshotDiffEvidence(baselineDiff) }),
  };
  if (args.format === "text") {
    return `${renderScanOutput(scan, "text", VERSION)}Gate: ${JSON.stringify(gate.result, null, 2)}\n${
      baselineDiff === undefined
        ? ""
        : `Baseline diff: ${JSON.stringify(baselineDiff, null, 2)}\n`
    }`;
  }
  if (args.format === "json") {
    return serialized({
      scan,
      gate: gate.result,
      ...(gate.intelligence === undefined ? {} : { intelligence: gate.intelligence }),
      ...(gate.licenses === undefined ? {} : { licenses: gate.licenses }),
      ...(gate.provenance === undefined ? {} : { provenance: gate.provenance }),
      ...(gate.reachability === undefined ? {} : { reachability: gate.reachability }),
      ...(baselineDiff === undefined ? {} : { baselineDiff }),
    }, true);
  }
  return renderScanOutput(scan, args.format, VERSION, evidence);
}
export async function runCli(
  argv: readonly string[],
  io: CliIo = PROCESS_IO,
  runtime: CliRuntime = {},
): Promise<CliExitCode> {
  let args: CliArguments;
  try {
    args = parseCliArguments(argv);
  } catch (error: unknown) {
    if (!(error instanceof CliUsageError)) throw error;
    io.stderr(`Configuration error: ${safeErrorMessage(error)}\n\n${CLI_USAGE}`);
    return CLI_EXIT_CODES.INVALID_CONFIGURATION;
  }
  if (args.command === "help") {
    io.stdout(CLI_USAGE);
    return CLI_EXIT_CODES.SUCCESS;
  }
  if (args.command === "version") {
    io.stdout(`${VERSION}\n`);
    return CLI_EXIT_CODES.SUCCESS;
  }

  const controller = new AbortController();
  const interrupt = (): void => controller.abort();
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", interrupt);
  const fileSystem = runtime.fileSystem ?? new NodeFileSystem();
  try {
    if (args.command === "diff") {
      return await runSnapshotDiffCommand(args, io, controller.signal);
    }
    if (args.command === "sbom") {
      return await runSbomCommand(args, io, controller.signal);
    }
    if (args.command === "container") {
      return await runContainerCommand(args, io, controller.signal);
    }
    if (args.command === "baseline") {
      return await runBaselineCommand(
        args,
        io,
        runtime,
        fileSystem,
        controller.signal,
      );
    }

    const scan = await scanWithArguments(
      args,
      io,
      runtime,
      fileSystem,
      controller.signal,
    );
    if (args.command === "licenses") {
      const policy = args.policyPath === undefined
        ? defaultLicensePolicy()
        : licensePolicyFromValue(await readPolicy(args.policyPath, controller.signal));
      const inventory = analyzeLicenses(scan, policy, controller.signal);
      const rendered = ["html", "markdown", "csv"].includes(args.format)
        ? renderScanOutput(scan, args.format, VERSION, {
            licenses: licenseReportEvidence(inventory),
          })
        : serialized({ scanStatus: scan.status, inventory }, args.format === "text");
      requireFormats(args, ["text", "json", "html", "markdown", "csv"]);
      await emit(args, rendered, io);
      if (!inventory.coverage.policyValid) return CLI_EXIT_CODES.INVALID_CONFIGURATION;
      if (inventory.entries.some((entry) => entry.finding.outcome === "DENIED")) {
        return CLI_EXIT_CODES.POLICY_VIOLATION;
      }
      return scan.status === "complete" &&
        inventory.coverage.analysisComplete &&
        inventory.coverage.unknownLicenseRecords === 0 &&
        inventory.entries.every((entry) => entry.finding.outcome === "ALLOWED")
        ? CLI_EXIT_CODES.SUCCESS
        : CLI_EXIT_CODES.INCOMPLETE;
    }
    if (args.command === "provenance") {
      requireFormats(args, ["text", "json", "html", "markdown", "csv"]);
      const provenance = analyzePackageProvenance(scan, controller.signal);
      const rendered = ["html", "markdown", "csv"].includes(args.format)
        ? renderScanOutput(scan, args.format, VERSION, {
            provenance: provenanceReportEvidence(provenance),
          })
        : serialized({ scanStatus: scan.status, provenance }, args.format === "text");
      await emit(args, rendered, io);
      if (provenance.coverage.suspiciousRecords > 0) {
        return CLI_EXIT_CODES.POLICY_VIOLATION;
      }
      return scan.status === "complete" &&
        provenance.coverage.analysisComplete &&
        provenance.coverage.unknownRecords === 0
        ? CLI_EXIT_CODES.SUCCESS
        : CLI_EXIT_CODES.INCOMPLETE;
    }
    if (args.command === "reachability") {
      requireFormats(args, ["text", "json", "html", "markdown", "csv"]);
      const reachability = await analyzeReachability(
        args,
        scan,
        fileSystem,
        controller.signal,
      );
      const rendered = ["html", "markdown", "csv"].includes(args.format)
        ? renderScanOutput(scan, args.format, VERSION, {
            reachability: reachabilityReportEvidence(
              reachability.analysis,
              reachability.vulnerabilities,
            ),
          })
        : serialized({
            scanStatus: scan.status,
            unsupportedTargets: reachability.unsupportedTargets,
            analysis: reachability.analysis,
          }, args.format === "text");
      await emit(args, rendered, io);
      if (reachability.analysis.findings.some((entry) => entry.status === "REACHABLE")) {
        return CLI_EXIT_CODES.POLICY_VIOLATION;
      }
      return scan.status === "complete" && reachability.analysis.coverage.analysisComplete
        ? CLI_EXIT_CODES.SUCCESS
        : CLI_EXIT_CODES.INCOMPLETE;
    }
    if (args.command === "snapshot") {
      requireFormats(args, ["text", "json"]);
      const snapshot = buildSnapshot(scan, args, runtime, undefined, controller.signal);
      await emit(args, serializeSecuritySnapshot(snapshot), io);
      return snapshot.coverage.status === "complete"
        ? CLI_EXIT_CODES.SUCCESS
        : CLI_EXIT_CODES.INCOMPLETE;
    }
    if (args.command === "gate") {
      const gate = await evaluateGate(
        args,
        scan,
        runtime,
        fileSystem,
        controller.signal,
      );
      let baselineDiff: SecuritySnapshotDiff | undefined;
      if (args.baselinePath !== undefined) {
        const baseline = parseSecurityBaselineJson(
          await readSafeTextInput(
            args.baselinePath,
            MAXIMUM_EVIDENCE_BYTES,
            controller.signal,
          ),
          { signal: controller.signal },
        );
        const current = buildSnapshot(
          scan,
          args,
          runtime,
          gate.reportPolicy,
          controller.signal,
        );
        baselineDiff = compareSecurityBaseline(baseline, current, {
          signal: controller.signal,
        });
      }
      await emit(args, renderGate(args, scan, gate, baselineDiff), io);
      return baselineDiff !== undefined && !baselineDiff.complete &&
        gate.exitCode !== CLI_EXIT_CODES.INVALID_CONFIGURATION
        ? CLI_EXIT_CODES.INCOMPLETE
        : gate.exitCode;
    }
    if (args.command !== "scan") {
      throw new CliUsageError(`Unsupported command: ${args.command}`);
    }
    await emit(args, renderScanOutput(scan, args.format, VERSION), io);
    if (scan.status !== "complete") return CLI_EXIT_CODES.INCOMPLETE;
    if (
      args.failOn !== undefined &&
      findingThresholdViolated(scan.results, args.failOn)
    ) return CLI_EXIT_CODES.POLICY_VIOLATION;
    return CLI_EXIT_CODES.SUCCESS;
  } catch (error: unknown) {
    if (error instanceof OfflineAdvisoryDatabaseError) {
      if (
        error.code === "STALE_DATABASE" ||
        error.code === "SUBJECT_NOT_COVERED" ||
        error.code === "CANCELLED"
      ) {
        io.stderr(`Security analysis incomplete: ${safeErrorMessage(error)}\n`);
        return CLI_EXIT_CODES.INCOMPLETE;
      }
      io.stderr(`Configuration error: ${safeErrorMessage(error)}\n`);
      return CLI_EXIT_CODES.INVALID_CONFIGURATION;
    }
    if (
      error instanceof SecuritySnapshotError ||
      error instanceof SecurityBaselineError ||
      error instanceof SecurityHistoryError ||
      error instanceof CycloneDxImportError ||
      error instanceof CycloneDxOperationError
    ) {
      if (error.code === "CANCELLED") {
        io.stderr(`Security analysis incomplete: ${safeErrorMessage(error)}\n`);
        return CLI_EXIT_CODES.INCOMPLETE;
      }
      io.stderr(`Configuration error: ${safeErrorMessage(error)}\n`);
      return CLI_EXIT_CODES.INVALID_CONFIGURATION;
    }
    if (
      error instanceof CliUsageError ||
      (error instanceof CliOutputError && error.code !== "OUTPUT_FAILED")
    ) {
      io.stderr(`Configuration error: ${safeErrorMessage(error)}\n`);
      return CLI_EXIT_CODES.INVALID_CONFIGURATION;
    }
    if (
      controller.signal.aborted ||
      (error instanceof DOMException && error.name === "AbortError")
    ) {
      io.stderr("Security analysis incomplete: operation cancelled.\n");
      return CLI_EXIT_CODES.INCOMPLETE;
    }
    io.stderr(`Internal scanner error: ${safeErrorMessage(error)}\n`);
    return CLI_EXIT_CODES.INTERNAL_ERROR;
  } finally {
    process.removeListener("SIGINT", interrupt);
    process.removeListener("SIGTERM", interrupt);
  }
}

if (require.main === module) {
  void runCli(process.argv.slice(2)).then(
    (exitCode) => {
      process.exitCode = exitCode;
    },
    (error: unknown) => {
      process.stderr.write(`Internal scanner error: ${safeErrorMessage(error)}\n`);
      process.exitCode = CLI_EXIT_CODES.INTERNAL_ERROR;
    },
  );
}

export { classifyScanCoverage };







