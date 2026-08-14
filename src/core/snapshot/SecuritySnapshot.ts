import type { PolicyFindingIntelligence, SecurityGateResult } from "../../policy";
import type { LicenseInventory } from "../license/LicenseIntelligence";
import type { ProvenanceAnalysisResult } from "../provenance/ProvenanceIntelligence";
import type { StaticReachabilityResult } from "../reachability/StaticReachability";
import type { Dependency } from "../../models/Dependency";
import {
  scanResultKnownVulnerabilities,
  type ProviderResult,
  type ScanErrorCode,
  type ScanResult,
} from "../../models/ScanResult";
import type { Severity, Vulnerability } from "../../models/Vulnerability";
import {
  BoundedJsonError,
  canonicalJson,
  deepFreezeJson,
  parseBoundedJson,
  sha256CanonicalJson,
  type JsonValue,
  type ParseBoundedJsonOptions,
} from "../security/BoundedJson";

export const SECURITY_SNAPSHOT_SCHEMA =
  "dependency-auditor/security-snapshot" as const;
export const SECURITY_SNAPSHOT_SCHEMA_VERSION = 1 as const;

export type SnapshotCoverageStatus =
  | "not-scanned"
  | "complete"
  | "partial"
  | "unavailable"
  | "cancelled";
export type SnapshotEvidenceState =
  | "complete"
  | "partial"
  | "unknown"
  | "not-configured";
export type SnapshotKnownExploitation =
  | "known-exploited"
  | "not-known-exploited"
  | "unknown";

export interface SnapshotComponent {
  /** Stable package-coordinate key, independent of occurrence evidence. */
  readonly key: string;
  readonly evidenceHash: string;
  readonly ecosystem: string;
  readonly name: string;
  readonly version: string | null;
  readonly resolution: "resolved" | "unresolved" | "unsupported";
  readonly dependencyTypes: readonly ("direct" | "transitive")[];
  readonly environments: readonly (
    | "production"
    | "development"
    | "optional"
    | "peer"
  )[];
  readonly packageManagers: readonly string[];
  readonly occurrenceCount: number;
}

export interface SnapshotVulnerability {
  /** Unique immutable observation key. */
  readonly key: string;
  /** Provider advisory + component identity, stable across evidence changes. */
  readonly identityKey: string;
  readonly evidenceHash: string;
  readonly componentKey: string;
  readonly componentEvidenceHash: string;
  readonly id: string;
  readonly aliases: readonly string[];
  readonly severity: Severity;
  readonly cvssScore?: number;
  readonly source: string;
  readonly fixedVersions: readonly string[];
  /** True when provider-connected evidence disagreed about a safe fix. */
  readonly fixedVersionConflict: boolean;
  readonly knownExploitation: SnapshotKnownExploitation;
  readonly reachability: "unknown";
}

export interface SnapshotProviderEvidence {
  readonly provider: string;
  readonly status: ProviderResult["status"];
  readonly dependenciesEligible: number;
  readonly dependenciesSubmitted: number;
  readonly successful: number;
  readonly failed: number;
  readonly cacheHits: number;
  readonly staleCacheFallbacks: number;
  readonly vulnerabilitiesFound: number;
}

export interface SnapshotCoverage {
  readonly status: SnapshotCoverageStatus;
  readonly dependencyInventory: SnapshotEvidenceState;
  readonly vulnerabilityAnalysis: SnapshotEvidenceState;
  readonly errorCodes: readonly ScanErrorCode[];
  readonly providers: readonly SnapshotProviderEvidence[];
}

export interface SnapshotPolicyEvidence {
  readonly status: "not-evaluated" | "PASS" | "WARN" | "FAIL";
  readonly complete: boolean;
  readonly coverage: SnapshotCoverageStatus;
  readonly reasonCodes: readonly string[];
}

export interface SecuritySnapshotIntegrity {
  readonly algorithm: "SHA-256";
  readonly digest: string;
}

export interface SnapshotAnalysisSummary {
  readonly totalRecords: number;
  readonly processedRecords: number;
  readonly unknownRecords: number;
  readonly concerningRecords: number;
  /** Digest of normalized evidenced enums/identities; no prose or paths. */
  readonly evidenceHash: string;
}

export interface SnapshotAnalysisEvidence {
  readonly licenses: SnapshotEvidenceState;
  readonly provenance: SnapshotEvidenceState;
  readonly reachability: SnapshotEvidenceState;
  readonly licenseSummary?: SnapshotAnalysisSummary;
  readonly provenanceSummary?: SnapshotAnalysisSummary;
  readonly reachabilitySummary?: SnapshotAnalysisSummary;
}

export interface SecuritySnapshot {
  readonly schema: typeof SECURITY_SNAPSHOT_SCHEMA;
  readonly schemaVersion: typeof SECURITY_SNAPSHOT_SCHEMA_VERSION;
  readonly timestamp: string;
  readonly scanner: Readonly<{
    name: "Dependency Vulnerability Auditor";
    version: string;
  }>;
  readonly workspace: Readonly<{
    identityHash: string;
    rootCount: number;
  }>;
  readonly dependencies: readonly SnapshotComponent[];
  readonly vulnerabilities: readonly SnapshotVulnerability[];
  readonly coverage: SnapshotCoverage;
  readonly policy: SnapshotPolicyEvidence;
  readonly analysis: SnapshotAnalysisEvidence;
  readonly integrity: SecuritySnapshotIntegrity;
}

export interface BuildSecuritySnapshotOptions {
  /** Explicit RFC 3339 UTC timestamp; no implicit clock is used. */
  readonly timestamp: string;
  readonly scannerVersion: string;
  /** Only its SHA-256 digest is retained. */
  readonly workspaceIdentity: string;
  readonly findingIntelligence?: readonly PolicyFindingIntelligence[];
  readonly policy?: SecurityGateResult;
  readonly licenseInventory?: LicenseInventory;
  readonly provenanceAnalysis?: ProvenanceAnalysisResult;
  readonly reachabilityAnalysis?: StaticReachabilityResult;
  readonly signal?: AbortSignal;
  readonly maximumScanResults?: number;
  readonly maximumDependencies?: number;
  readonly maximumVulnerabilities?: number;
}

export type SecuritySnapshotErrorCode =
  | "CANCELLED"
  | "INVALID_INPUT"
  | "LIMIT_EXCEEDED"
  | "INTEGRITY_MISMATCH";

export class SecuritySnapshotError extends Error {
  public constructor(
    public readonly code: SecuritySnapshotErrorCode,
    message: string,
    options: { readonly cause?: unknown } = {},
  ) {
    super(message, options);
    this.name = "SecuritySnapshotError";
  }
}

const MAXIMUM_SCAN_RESULTS = 256;
const MAXIMUM_DEPENDENCIES = 250_000;
const MAXIMUM_VULNERABILITIES = 250_000;
const MAXIMUM_ALIASES = 256;
const MAXIMUM_FIXED_VERSIONS = 256;
const MAXIMUM_INTELLIGENCE = 500_000;
const MAXIMUM_ANALYSIS_RECORDS = 250_000;
const MAXIMUM_TEXT = 4_096;
const MAXIMUM_TOKEN = 512;
const SHA256 = /^[0-9a-f]{64}$/u;
const RFC3339_UTC =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/u;
const UNSAFE =
  /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const SEVERITIES: ReadonlySet<string> = new Set([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "UNKNOWN",
]);
const COVERAGE_STATUSES: ReadonlySet<string> = new Set([
  "not-scanned",
  "complete",
  "partial",
  "unavailable",
  "cancelled",
]);
const EVIDENCE_STATES: ReadonlySet<string> = new Set([
  "complete",
  "partial",
  "unknown",
  "not-configured",
]);
const SCAN_ERROR_CODES: ReadonlySet<string> = new Set([
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
  "CACHE_ERROR",
  "WORKSPACE_ERROR",
]);
const INVENTORY_ERRORS: ReadonlySet<ScanErrorCode> = new Set([
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
  "WORKSPACE_ERROR",
]);

function json(value: unknown): JsonValue {
  return value as JsonValue;
}

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new SecuritySnapshotError(
      "CANCELLED",
      "Security snapshot operation was cancelled",
    );
  }
}

function boundedLimit(
  value: number | undefined,
  fallback: number,
  maximum: number,
  name: string,
): number {
  const selected = value ?? fallback;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > maximum
  ) {
    throw new SecuritySnapshotError(
      "LIMIT_EXCEEDED",
      `${name} is outside the supported safety range`,
    );
  }
  return selected;
}

function safeString(
  value: unknown,
  name: string,
  maximumLength = MAXIMUM_TOKEN,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    value.trim() !== value ||
    UNSAFE.test(value)
  ) {
    throw new SecuritySnapshotError("INVALID_INPUT", `${name} is invalid`);
  }
  return value;
}

function timestamp(value: unknown, name: string): string {
  const selected = safeString(value, name, 128);
  const match = RFC3339_UTC.exec(selected);
  const parsed = Date.parse(selected);
  if (match === null || !Number.isFinite(parsed)) {
    throw new SecuritySnapshotError("INVALID_INPUT", `${name} is invalid`);
  }
  const date = new Date(parsed);
  const expected = match.slice(1, 7).map(Number);
  const actual = [
    date.getUTCFullYear(),
    date.getUTCMonth() + 1,
    date.getUTCDate(),
    date.getUTCHours(),
    date.getUTCMinutes(),
    date.getUTCSeconds(),
  ];
  if (expected.some((part, index) => part !== actual[index])) {
    throw new SecuritySnapshotError("INVALID_INPUT", `${name} is invalid`);
  }
  return selected;
}

function nonNegativeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new SecuritySnapshotError("INVALID_INPUT", `${name} is invalid`);
  }
  return value as number;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function stringSort(values: Iterable<string>): readonly string[] {
  return [...new Set(values)].sort(compareText);
}

function componentCoordinate(
  ecosystem: string,
  name: string,
  version: string | null,
  resolution: SnapshotComponent["resolution"],
): JsonValue {
  return json([ecosystem, name, version, resolution]);
}

function componentKey(
  ecosystem: string,
  name: string,
  version: string | null,
  resolution: SnapshotComponent["resolution"],
): string {
  return sha256CanonicalJson(
    componentCoordinate(ecosystem, name, version, resolution),
  );
}

function dependencyResolution(
  dependency: Dependency,
): SnapshotComponent["resolution"] {
  if (dependency.resolutionStatus === "unsupported") {
    return "unsupported";
  }
  if (
    dependency.resolutionStatus === "unresolved" ||
    dependency.installedVersion.length === 0
  ) {
    return "unresolved";
  }
  return "resolved";
}

interface MutableComponent {
  readonly ecosystem: string;
  readonly name: string;
  readonly version: string | null;
  readonly resolution: SnapshotComponent["resolution"];
  readonly dependencyTypes: Set<"direct" | "transitive">;
  readonly environments: Set<
    "production" | "development" | "optional" | "peer"
  >;
  readonly packageManagers: Set<string>;
  occurrenceCount: number;
}

function snapshotComponents(
  results: readonly ScanResult[],
  maximumDependencies: number,
  signal: AbortSignal | undefined,
): readonly SnapshotComponent[] {
  const components = new Map<string, MutableComponent>();
  let count = 0;
  for (const result of results) {
    if (!Array.isArray(result.dependencies)) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "Scan dependencies must be an array",
      );
    }
    for (const dependency of result.dependencies) {
      count += 1;
      if ((count & 255) === 0) {
        throwIfCancelled(signal);
      }
      if (count > maximumDependencies) {
        throw new SecuritySnapshotError(
          "LIMIT_EXCEEDED",
          "Snapshot dependency input exceeds the configured limit",
        );
      }
      const ecosystem = safeString(dependency.ecosystem, "dependency ecosystem", 64);
      const name = safeString(dependency.name, "dependency name");
      const resolution = dependencyResolution(dependency);
      const version =
        resolution === "resolved"
          ? safeString(dependency.installedVersion, "dependency version", 256)
          : null;
      const key = componentKey(ecosystem, name, version, resolution);
      let component = components.get(key);
      if (component === undefined) {
        component = {
          ecosystem,
          name,
          version,
          resolution,
          dependencyTypes: new Set(),
          environments: new Set(),
          packageManagers: new Set(),
          occurrenceCount: 0,
        };
        components.set(key, component);
      }
      component.occurrenceCount += 1;
      component.dependencyTypes.add(dependency.dependencyType);
      component.environments.add(dependency.environment);
      if (dependency.packageManager !== undefined) {
        component.packageManagers.add(
          safeString(dependency.packageManager, "package manager", 64),
        );
      }
    }
  }
  return [...components.entries()]
    .sort(([left], [right]) => compareText(left, right))
    .map(([key, component]) => {
      const dependencyTypes = Object.freeze(
        [...component.dependencyTypes].sort(compareText),
      );
      const environments = Object.freeze(
        [...component.environments].sort(compareText),
      );
      const packageManagers = Object.freeze(
        [...component.packageManagers].sort(compareText),
      );
      const evidenceHash = sha256CanonicalJson(
        json({
          dependencyTypes,
          environments,
          occurrenceCount: component.occurrenceCount,
          packageManagers,
        }),
      );
      return Object.freeze({
        key,
        evidenceHash,
        ecosystem: component.ecosystem,
        name: component.name,
        version: component.version,
        resolution: component.resolution,
        dependencyTypes,
        environments,
        packageManagers,
        occurrenceCount: component.occurrenceCount,
      });
    });
}

function intelligenceKey(
  advisoryId: string,
  ecosystem: string,
  packageName: string,
  installedVersion: string,
): string {
  return canonicalJson(json([advisoryId, ecosystem, packageName, installedVersion]));
}

function intelligenceIndex(
  entries: readonly PolicyFindingIntelligence[] | undefined,
): ReadonlyMap<string, SnapshotKnownExploitation> {
  const index = new Map<string, SnapshotKnownExploitation>();
  if (entries === undefined) {
    return index;
  }
  if (!Array.isArray(entries) || entries.length > MAXIMUM_INTELLIGENCE) {
    throw new SecuritySnapshotError(
      "LIMIT_EXCEEDED",
      "Finding intelligence exceeds the snapshot safety limit",
    );
  }
  for (const entry of entries) {
    const advisoryId = safeString(entry.advisoryId, "intelligence advisory id");
    const ecosystem = safeString(entry.ecosystem, "intelligence ecosystem", 64);
    const packageName = safeString(entry.packageName, "intelligence package name");
    const installedVersion = safeString(
      entry.installedVersion,
      "intelligence installed version",
      256,
    );
    if (
      entry.knownExploitation !== "known-exploited" &&
      entry.knownExploitation !== "not-known-exploited" &&
      entry.knownExploitation !== "unknown"
    ) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "Known-exploitation evidence is invalid",
      );
    }
    const key = intelligenceKey(
      advisoryId,
      ecosystem,
      packageName,
      installedVersion,
    );
    const previous = index.get(key);
    if (
      previous !== undefined &&
      previous !== entry.knownExploitation
    ) {
      index.set(key, "unknown");
    } else {
      index.set(key, entry.knownExploitation);
    }
  }
  return index;
}

function knownExploitationFor(
  vulnerability: Vulnerability,
  intelligence: ReadonlyMap<string, SnapshotKnownExploitation>,
): SnapshotKnownExploitation {
  const statuses = new Set<SnapshotKnownExploitation>();
  for (const advisoryId of [vulnerability.id, ...vulnerability.aliases]) {
    const status = intelligence.get(
      intelligenceKey(
        advisoryId,
        vulnerability.ecosystem,
        vulnerability.packageName,
        vulnerability.installedVersion,
      ),
    );
    if (status !== undefined) {
      statuses.add(status);
    }
  }
  if (statuses.has("known-exploited")) {
    return "known-exploited";
  }
  if (statuses.size === 1 && statuses.has("not-known-exploited")) {
    return "not-known-exploited";
  }
  return "unknown";
}

function vulnerabilityObservation(
  vulnerability: Vulnerability,
  intelligence: ReadonlyMap<string, SnapshotKnownExploitation>,
  componentEvidence: ReadonlyMap<string, string>,
): SnapshotVulnerability {
  const ecosystem = safeString(vulnerability.ecosystem, "vulnerability ecosystem", 64);
  const packageName = safeString(vulnerability.packageName, "vulnerability package name");
  const installedVersion = safeString(
    vulnerability.installedVersion,
    "vulnerability installed version",
    256,
  );
  const id = safeString(vulnerability.id, "vulnerability id");
  const source = safeString(vulnerability.source, "vulnerability source", 64);
  if (!SEVERITIES.has(vulnerability.severity)) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Vulnerability severity is invalid",
    );
  }
  if (
    vulnerability.cvssScore !== undefined &&
    (typeof vulnerability.cvssScore !== "number" ||
      !Number.isFinite(vulnerability.cvssScore) ||
      vulnerability.cvssScore < 0 ||
      vulnerability.cvssScore > 10)
  ) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Vulnerability CVSS score is invalid",
    );
  }
  if (
    !Array.isArray(vulnerability.aliases) ||
    vulnerability.aliases.length > MAXIMUM_ALIASES
  ) {
    throw new SecuritySnapshotError(
      "LIMIT_EXCEEDED",
      "Vulnerability aliases exceed the snapshot safety limit",
    );
  }
  const aliases = stringSort(
    vulnerability.aliases.map((alias) => safeString(alias, "vulnerability alias")),
  );
  const rawFixedVersions = vulnerability.fixedVersions ??
    (vulnerability.fixedVersion === undefined ? [] : [vulnerability.fixedVersion]);
  if (!Array.isArray(rawFixedVersions) || rawFixedVersions.length > MAXIMUM_FIXED_VERSIONS) {
    throw new SecuritySnapshotError(
      "LIMIT_EXCEEDED",
      "Vulnerability fixed versions exceed the snapshot safety limit",
    );
  }
  const fixedVersions = stringSort(
    rawFixedVersions.map((version) =>
      safeString(version, "vulnerability fixed version", 256),
    ),
  );
  const targetComponentKey = componentKey(
    ecosystem,
    packageName,
    installedVersion,
    "resolved",
  );
  const knownExploitation = knownExploitationFor(vulnerability, intelligence);
  const componentEvidenceHash = componentEvidence.get(targetComponentKey);
  if (componentEvidenceHash === undefined) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Vulnerability does not match an observed resolved dependency",
    );
  }
  const identityPayload = json([
    source,
    id,
    ecosystem,
    packageName,
  ]);
  const identityKey = sha256CanonicalJson(identityPayload);
  const evidencePayload = json({
    aliases,
    componentKey: targetComponentKey,
    componentEvidenceHash,
    cvssScore: vulnerability.cvssScore ?? null,
    fixedVersions,
    fixedVersionConflict: vulnerability.fixedVersionConflict === true,
    knownExploitation,
    severity: vulnerability.severity,
  });
  const evidenceHash = sha256CanonicalJson(evidencePayload);
  const key = sha256CanonicalJson(json([identityKey, evidenceHash]));
  return Object.freeze({
    key,
    identityKey,
    evidenceHash,
    componentKey: targetComponentKey,
    componentEvidenceHash,
    id,
    aliases: Object.freeze(aliases),
    severity: vulnerability.severity,
    ...(vulnerability.cvssScore === undefined
      ? {}
      : { cvssScore: vulnerability.cvssScore }),
    source,
    fixedVersions: Object.freeze(fixedVersions),
    fixedVersionConflict: vulnerability.fixedVersionConflict === true,
    knownExploitation,
    reachability: "unknown" as const,
  });
}

function snapshotVulnerabilities(
  results: readonly ScanResult[],
  maximumVulnerabilities: number,
  intelligence: ReadonlyMap<string, SnapshotKnownExploitation>,
  componentEvidence: ReadonlyMap<string, string>,
  signal: AbortSignal | undefined,
): readonly SnapshotVulnerability[] {
  const findings = new Map<string, SnapshotVulnerability>();
  let count = 0;
  for (const result of results) {
    const completeFindings = scanResultKnownVulnerabilities(result);
    if (!Array.isArray(completeFindings)) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "Scan vulnerabilities must be an array",
      );
    }
    for (const vulnerability of completeFindings) {
      count += 1;
      if ((count & 255) === 0) {
        throwIfCancelled(signal);
      }
      if (count > maximumVulnerabilities) {
        throw new SecuritySnapshotError(
          "LIMIT_EXCEEDED",
          "Snapshot vulnerability input exceeds the configured limit",
        );
      }
      const normalized = vulnerabilityObservation(
        vulnerability,
        intelligence,
        componentEvidence,
      );
      findings.set(normalized.key, normalized);
    }
  }
  return Object.freeze(
    [...findings.values()].sort((left, right) => compareText(left.key, right.key)),
  );
}

function providerEvidence(
  results: readonly ScanResult[],
): readonly SnapshotProviderEvidence[] {
  const providers = new Map<string, SnapshotProviderEvidence>();
  const statusRank: Readonly<Record<ProviderResult["status"], number>> = {
    available: 0,
    partial: 1,
    unavailable: 2,
  };
  for (const result of results) {
    if (!Array.isArray(result.providerResults)) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "Scan provider results must be an array",
      );
    }
    for (const provider of result.providerResults) {
      const name = safeString(provider.provider, "provider name", 64);
      if (
        provider.status !== "available" &&
        provider.status !== "partial" &&
        provider.status !== "unavailable"
      ) {
        throw new SecuritySnapshotError(
          "INVALID_INPUT",
          "Provider status is invalid",
        );
      }
      const providerStatus = provider.status as ProviderResult["status"];
      const values = [
        provider.dependenciesEligible,
        provider.dependenciesSubmitted,
        provider.successful,
        provider.failed,
        provider.cacheHits,
        provider.staleCacheFallbacks,
        provider.vulnerabilitiesFound,
      ];
      for (const value of values) {
        nonNegativeInteger(value, "provider count");
      }
      const previous = providers.get(name);
      const nextStatus =
        previous === undefined ||
        statusRank[providerStatus] > statusRank[previous.status]
          ? providerStatus
          : previous.status;
      const summed = values.map((value, index) => {
        const previousValues =
          previous === undefined
            ? [0, 0, 0, 0, 0, 0, 0]
            : [
                previous.dependenciesEligible,
                previous.dependenciesSubmitted,
                previous.successful,
                previous.failed,
                previous.cacheHits,
                previous.staleCacheFallbacks,
                previous.vulnerabilitiesFound,
              ];
        const result = value + (previousValues[index] ?? 0);
        if (!Number.isSafeInteger(result)) {
          throw new SecuritySnapshotError(
            "LIMIT_EXCEEDED",
            "Aggregated provider count exceeds the safety limit",
          );
        }
        return result;
      });
      providers.set(
        name,
        Object.freeze({
          provider: name,
          status: nextStatus,
          dependenciesEligible: summed[0] ?? 0,
          dependenciesSubmitted: summed[1] ?? 0,
          successful: summed[2] ?? 0,
          failed: summed[3] ?? 0,
          cacheHits: summed[4] ?? 0,
          staleCacheFallbacks: summed[5] ?? 0,
          vulnerabilitiesFound: summed[6] ?? 0,
        }),
      );
    }
  }
  return Object.freeze(
    [...providers.values()].sort((left, right) =>
      compareText(left.provider, right.provider),
    ),
  );
}

function snapshotCoverage(
  results: readonly ScanResult[],
  providers: readonly SnapshotProviderEvidence[],
): SnapshotCoverage {
  if (results.length === 0) {
    return Object.freeze({
      status: "not-scanned" as const,
      dependencyInventory: "unknown" as const,
      vulnerabilityAnalysis: "unknown" as const,
      errorCodes: Object.freeze([]),
      providers,
    });
  }
  const errorCodes = stringSort(
    results.flatMap((result) =>
      result.errors.map((error) => safeString(error.code, "scan error code", 64)),
    ),
  ) as readonly ScanErrorCode[];
  const cancelled = results.some((result) => result.cancelled);
  const inventoryIncomplete = errorCodes.some((code) => INVENTORY_ERRORS.has(code));
  const reportedCoverageGap = results.some((result) => {
    const coverage = [
      ...(result.ecosystemCoverage ?? []),
      ...(result.projectCoverage ?? []),
    ];
    return coverage.some((entry) => {
      const discovered = nonNegativeInteger(entry.discovered, "coverage count");
      const resolved = nonNegativeInteger(entry.resolved, "coverage count");
      const checked = nonNegativeInteger(entry.checked, "coverage count");
      const unresolved = nonNegativeInteger(entry.unresolved, "coverage count");
      const unsupported = nonNegativeInteger(entry.unsupported, "coverage count");
      return (
        discovered < resolved ||
        checked < resolved ||
        unresolved > 0 ||
        unsupported > 0
      );
    });
  });
  const totalScanned = results.reduce((total, result) => {
    const value = nonNegativeInteger(result.dependenciesScanned, "dependencies scanned");
    return total + value;
  }, 0);
  const providerUnavailable =
    totalScanned > 0 &&
    (providers.length === 0 || providers.every((provider) => provider.status === "unavailable"));
  const providerIncomplete = providers.some(
    (provider) => provider.status !== "available" || provider.failed > 0,
  );
  const providerErrors = errorCodes.includes("PROVIDER_ERROR") || errorCodes.includes("CACHE_ERROR");
  const hiddenProviderFindings = results.some((result) => {
    const providerCount = result.providerResults.reduce(
      (total, provider) => total + provider.vulnerabilitiesFound,
      0,
    );
    return providerCount > scanResultKnownVulnerabilities(result).length;
  });
  const status: SnapshotCoverageStatus = cancelled
    ? "cancelled"
    : providerUnavailable
      ? "unavailable"
      : inventoryIncomplete || reportedCoverageGap || providerIncomplete || providerErrors || hiddenProviderFindings
        ? "partial"
        : "complete";
  return Object.freeze({
    status,
    dependencyInventory: cancelled
      ? "unknown"
      : inventoryIncomplete || reportedCoverageGap
        ? "partial"
        : "complete",
    vulnerabilityAnalysis:
      cancelled || providerUnavailable
        ? "unknown"
        : inventoryIncomplete ||
            reportedCoverageGap ||
            providerIncomplete ||
            providerErrors ||
            hiddenProviderFindings
          ? "partial"
          : "complete",
    errorCodes: Object.freeze(errorCodes),
    providers,
  });
}

function snapshotPolicy(
  policy: SecurityGateResult | undefined,
): SnapshotPolicyEvidence {
  if (policy === undefined) {
    return Object.freeze({
      status: "not-evaluated" as const,
      complete: false,
      coverage: "not-scanned" as const,
      reasonCodes: Object.freeze([]),
    });
  }
  if (!COVERAGE_STATUSES.has(policy.coverage)) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Policy coverage is invalid");
  }
  if (policy.status !== "PASS" && policy.status !== "WARN" && policy.status !== "FAIL") {
    throw new SecuritySnapshotError("INVALID_INPUT", "Policy status is invalid");
  }
  if (!Array.isArray(policy.reasons) || policy.reasons.length > 250_000) {
    throw new SecuritySnapshotError(
      "LIMIT_EXCEEDED",
      "Policy reasons exceed the snapshot safety limit",
    );
  }
  return Object.freeze({
    status: policy.status,
    complete: policy.complete,
    coverage: policy.coverage,
    reasonCodes: Object.freeze(
      stringSort(
        policy.reasons.map((reason) =>
          safeString(reason.code, "policy reason code", 64),
        ),
      ),
    ),
  });
}

function analysisState(
  processed: number,
  unknown: number,
  complete: boolean,
  cancelled: boolean,
): SnapshotEvidenceState {
  if (cancelled || processed === 0) {
    return "unknown";
  }
  return complete && unknown === 0 ? "complete" : "partial";
}

function analysisSummary(
  totalRecords: number,
  processedRecords: number,
  unknownRecords: number,
  concerningRecords: number,
  evidence: readonly JsonValue[],
): SnapshotAnalysisSummary {
  for (const [name, value] of [
    ["analysis total records", totalRecords],
    ["analysis processed records", processedRecords],
    ["analysis unknown records", unknownRecords],
    ["analysis concerning records", concerningRecords],
  ] as const) {
    nonNegativeInteger(value, name);
  }
  if (
    processedRecords > totalRecords ||
    unknownRecords > processedRecords ||
    concerningRecords > processedRecords ||
    evidence.length > MAXIMUM_ANALYSIS_RECORDS
  ) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Analysis summary counts are inconsistent",
    );
  }
  const ordered = [...evidence].sort((left, right) =>
    compareText(canonicalJson(left), canonicalJson(right)),
  );
  return Object.freeze({
    totalRecords,
    processedRecords,
    unknownRecords,
    concerningRecords,
    evidenceHash: sha256CanonicalJson(json(ordered)),
  });
}

function licenseSnapshotAnalysis(
  inventory: LicenseInventory | undefined,
  componentKeys: ReadonlySet<string>,
): {
  readonly state: SnapshotEvidenceState;
  readonly summary?: SnapshotAnalysisSummary;
} {
  if (inventory === undefined) {
    return { state: "not-configured" };
  }
  if (
    !Array.isArray(inventory.entries) ||
    inventory.entries.length > MAXIMUM_ANALYSIS_RECORDS
  ) {
    throw new SecuritySnapshotError(
      "LIMIT_EXCEEDED",
      "License analysis exceeds the snapshot safety limit",
    );
  }
  const evidence: JsonValue[] = [];
  let unknown = 0;
  let concerning = 0;
  for (const entry of inventory.entries) {
    const ecosystem = safeString(entry.ecosystem, "license ecosystem", 64);
    const name = safeString(entry.name, "license package name");
    const version = safeString(entry.version, "license package version", 256);
    const key = componentKey(ecosystem, name, version, "resolved");
    if (!componentKeys.has(key)) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "License evidence does not match an observed dependency",
      );
    }
    if (
      entry.detectionStatus !== "DECLARED" &&
      entry.detectionStatus !== "UNKNOWN"
    ) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "License detection status is invalid",
      );
    }
    const outcome = entry.finding.outcome;
    if (
      outcome !== "ALLOWED" &&
      outcome !== "DENIED" &&
      outcome !== "REVIEW_REQUIRED" &&
      outcome !== "UNKNOWN"
    ) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "License policy outcome is invalid",
      );
    }
    if (!Array.isArray(entry.identifiers) || entry.identifiers.length > 64) {
      throw new SecuritySnapshotError(
        "LIMIT_EXCEEDED",
        "License identifiers exceed the snapshot safety limit",
      );
    }
    const identifiers = stringSort(
      entry.identifiers.map((identifier: string) =>
        safeString(identifier, "license identifier", 256),
      ),
    );
    if (entry.detectionStatus === "UNKNOWN" || outcome === "UNKNOWN") {
      unknown += 1;
    }
    if (outcome === "DENIED" || outcome === "REVIEW_REQUIRED") {
      concerning += 1;
    }
    evidence.push(
      json({
        componentKey: key,
        detectionStatus: entry.detectionStatus,
        identifiers,
        outcome,
      }),
    );
  }
  const coverage = inventory.coverage;
  const total = nonNegativeInteger(coverage.totalRecords, "license total records");
  const processed = nonNegativeInteger(
    coverage.processedRecords,
    "license processed records",
  );
  if (processed !== inventory.entries.length) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "License coverage disagrees with its evidence records",
    );
  }
  const complete =
    coverage.analysisComplete &&
    coverage.policyValid &&
    !coverage.truncated &&
    coverage.omittedRecords === 0;
  return {
    state: analysisState(processed, unknown, complete, coverage.cancelled),
    summary: analysisSummary(total, processed, unknown, concerning, evidence),
  };
}

function provenanceSnapshotAnalysis(
  analysis: ProvenanceAnalysisResult | undefined,
  componentKeys: ReadonlySet<string>,
): {
  readonly state: SnapshotEvidenceState;
  readonly summary?: SnapshotAnalysisSummary;
} {
  if (analysis === undefined) {
    return { state: "not-configured" };
  }
  if (
    !Array.isArray(analysis.packages) ||
    analysis.packages.length > MAXIMUM_ANALYSIS_RECORDS
  ) {
    throw new SecuritySnapshotError(
      "LIMIT_EXCEEDED",
      "Provenance analysis exceeds the snapshot safety limit",
    );
  }
  const evidence: JsonValue[] = [];
  let unknown = 0;
  let concerning = 0;
  for (const entry of analysis.packages) {
    const ecosystem = safeString(entry.ecosystem, "provenance ecosystem", 64);
    const name = safeString(entry.packageName, "provenance package name");
    const version = safeString(entry.version, "provenance package version", 256);
    const key = componentKey(ecosystem, name, version, "resolved");
    if (!componentKeys.has(key)) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "Provenance evidence does not match an observed dependency",
      );
    }
    if (
      entry.status !== "SAFE" &&
      entry.status !== "KNOWN" &&
      entry.status !== "SUSPICIOUS" &&
      entry.status !== "UNKNOWN"
    ) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "Provenance status is invalid",
      );
    }
    if (
      entry.sourceKind !== "registry" &&
      entry.sourceKind !== "git" &&
      entry.sourceKind !== "local" &&
      entry.sourceKind !== "url" &&
      entry.sourceKind !== "unknown"
    ) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "Provenance source kind is invalid",
      );
    }
    if (
      entry.integrityState !== "VERIFIED" &&
      entry.integrityState !== "DECLARED" &&
      entry.integrityState !== "MISMATCH" &&
      entry.integrityState !== "UNKNOWN"
    ) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "Provenance integrity state is invalid",
      );
    }
    if (!Array.isArray(entry.anomalies) || entry.anomalies.length > 256) {
      throw new SecuritySnapshotError(
        "LIMIT_EXCEEDED",
        "Provenance anomaly evidence exceeds the snapshot safety limit",
      );
    }
    const signals = stringSort(
      entry.anomalies.map((anomaly: { readonly signal: string }) =>
        safeString(anomaly.signal, "supply-chain signal", 64),
      ),
    );
    if (entry.status === "UNKNOWN") {
      unknown += 1;
    }
    if (entry.status === "SUSPICIOUS") {
      concerning += 1;
    }
    evidence.push(
      json({
        componentKey: key,
        integrityState: entry.integrityState,
        signals,
        sourceKind: entry.sourceKind,
        status: entry.status,
      }),
    );
  }
  const coverage = analysis.coverage;
  const total = nonNegativeInteger(
    coverage.totalRecords,
    "provenance total records",
  );
  const processed = nonNegativeInteger(
    coverage.processedRecords,
    "provenance processed records",
  );
  if (processed !== analysis.packages.length) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Provenance coverage disagrees with its evidence records",
    );
  }
  const complete =
    coverage.analysisComplete &&
    !coverage.truncated &&
    coverage.omittedRecords === 0;
  return {
    state: analysisState(processed, unknown, complete, coverage.cancelled),
    summary: analysisSummary(total, processed, unknown, concerning, evidence),
  };
}

function reachabilitySnapshotAnalysis(
  analysis: StaticReachabilityResult | undefined,
  components: readonly SnapshotComponent[],
): {
  readonly state: SnapshotEvidenceState;
  readonly summary?: SnapshotAnalysisSummary;
} {
  if (analysis === undefined) {
    return { state: "not-configured" };
  }
  if (
    !Array.isArray(analysis.findings) ||
    analysis.findings.length > MAXIMUM_ANALYSIS_RECORDS
  ) {
    throw new SecuritySnapshotError(
      "LIMIT_EXCEEDED",
      "Reachability analysis exceeds the snapshot safety limit",
    );
  }
  const packages = new Set(
    components.map((component) =>
      canonicalJson(json([component.ecosystem, component.name])),
    ),
  );
  const evidence: JsonValue[] = [];
  let unknown = 0;
  let concerning = 0;
  for (const finding of analysis.findings) {
    const ecosystem = safeString(finding.ecosystem, "reachability ecosystem", 64);
    const packageName = safeString(
      finding.packageName,
      "reachability package name",
    );
    if (!packages.has(canonicalJson(json([ecosystem, packageName])))) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "Reachability evidence does not match an observed dependency",
      );
    }
    if (
      finding.status !== "REACHABLE" &&
      finding.status !== "NOT_OBSERVED" &&
      finding.status !== "UNKNOWN"
    ) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "Reachability status is invalid",
      );
    }
    if (
      finding.confidence !== "HIGH" &&
      finding.confidence !== "MEDIUM" &&
      finding.confidence !== "LOW"
    ) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "Reachability confidence is invalid",
      );
    }
    if (
      !Array.isArray(finding.path) ||
      finding.path.length > 512 ||
      !Array.isArray(finding.affectedSymbols) ||
      finding.affectedSymbols.length > 128
    ) {
      throw new SecuritySnapshotError(
        "LIMIT_EXCEEDED",
        "Reachability path or symbol evidence exceeds the snapshot safety limit",
      );
    }
    const targetId = safeString(finding.targetId, "reachability target id");
    const path = finding.path.map((segment: string) =>
      safeString(segment, "reachability path segment", MAXIMUM_TEXT),
    );
    const affectedSymbols = finding.affectedSymbols.map((symbol: string) =>
      safeString(symbol, "reachability affected symbol", 512),
    );
    if (finding.status === "UNKNOWN") {
      unknown += 1;
    }
    if (finding.status === "REACHABLE") {
      concerning += 1;
    }
    evidence.push(
      json({
        confidence: finding.confidence,
        packageIdentityHash: sha256CanonicalJson(
          json([ecosystem, packageName]),
        ),
        pathHash: sha256CanonicalJson(json(path)),
        status: finding.status,
        symbolEvidenceHash: sha256CanonicalJson(
          json([
            affectedSymbols.sort(compareText),
            finding.observedSymbol === undefined
              ? null
              : safeString(
                  finding.observedSymbol,
                  "reachability observed symbol",
                  512,
                ),
          ]),
        ),
        targetIdentityHash: sha256CanonicalJson(json(targetId)),
      }),
    );
  }
  const coverage = analysis.coverage;
  const total = nonNegativeInteger(
    coverage.targetsTotal,
    "reachability total targets",
  );
  const processed = nonNegativeInteger(
    coverage.targetsAnalyzed,
    "reachability analyzed targets",
  );
  if (processed !== analysis.findings.length) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Reachability coverage disagrees with its evidence records",
    );
  }
  const complete =
    coverage.analysisComplete &&
    !coverage.truncated &&
    coverage.sourceFilesInvalid === 0 &&
    coverage.sourceFilesOmitted === 0;
  return {
    state: analysisState(processed, unknown, complete, coverage.cancelled),
    summary: analysisSummary(total, processed, unknown, concerning, evidence),
  };
}

function snapshotAnalysis(
  options: BuildSecuritySnapshotOptions,
  components: readonly SnapshotComponent[],
): SnapshotAnalysisEvidence {
  const componentKeys = new Set(components.map((component) => component.key));
  const licenses = licenseSnapshotAnalysis(
    options.licenseInventory,
    componentKeys,
  );
  const provenance = provenanceSnapshotAnalysis(
    options.provenanceAnalysis,
    componentKeys,
  );
  const reachability = reachabilitySnapshotAnalysis(
    options.reachabilityAnalysis,
    components,
  );
  return Object.freeze({
    licenses: licenses.state,
    provenance: provenance.state,
    reachability: reachability.state,
    ...(licenses.summary === undefined
      ? {}
      : { licenseSummary: licenses.summary }),
    ...(provenance.summary === undefined
      ? {}
      : { provenanceSummary: provenance.summary }),
    ...(reachability.summary === undefined
      ? {}
      : { reachabilitySummary: reachability.summary }),
  });
}

function snapshotPayload(snapshot: SecuritySnapshot): JsonValue {
  return json({
    schema: snapshot.schema,
    schemaVersion: snapshot.schemaVersion,
    timestamp: snapshot.timestamp,
    scanner: snapshot.scanner,
    workspace: snapshot.workspace,
    dependencies: snapshot.dependencies,
    vulnerabilities: snapshot.vulnerabilities,
    coverage: snapshot.coverage,
    policy: snapshot.policy,
    analysis: snapshot.analysis,
  });
}

export function buildSecuritySnapshot(
  scanResults: readonly ScanResult[],
  options: BuildSecuritySnapshotOptions,
): SecuritySnapshot {
  throwIfCancelled(options.signal);
  if (!Array.isArray(scanResults)) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Scan results must be an array");
  }
  const maximumScanResults = boundedLimit(
    options.maximumScanResults,
    MAXIMUM_SCAN_RESULTS,
    MAXIMUM_SCAN_RESULTS,
    "maximumScanResults",
  );
  const maximumDependencies = boundedLimit(
    options.maximumDependencies,
    MAXIMUM_DEPENDENCIES,
    MAXIMUM_DEPENDENCIES,
    "maximumDependencies",
  );
  const maximumVulnerabilities = boundedLimit(
    options.maximumVulnerabilities,
    MAXIMUM_VULNERABILITIES,
    MAXIMUM_VULNERABILITIES,
    "maximumVulnerabilities",
  );
  if (scanResults.length > maximumScanResults) {
    throw new SecuritySnapshotError(
      "LIMIT_EXCEEDED",
      "Snapshot scan-result input exceeds the configured limit",
    );
  }
  const selectedTimestamp = timestamp(options.timestamp, "snapshot timestamp");
  const scannerVersion = safeString(options.scannerVersion, "scanner version", 256);
  const workspaceIdentity = safeString(
    options.workspaceIdentity,
    "workspace identity",
    MAXIMUM_TEXT,
  );
  const intelligence = intelligenceIndex(options.findingIntelligence);
  const dependencies = snapshotComponents(
    scanResults,
    maximumDependencies,
    options.signal,
  );
  const componentEvidence = new Map(
    dependencies.map((component) => [component.key, component.evidenceHash] as const),
  );
  const vulnerabilities = snapshotVulnerabilities(
    scanResults,
    maximumVulnerabilities,
    intelligence,
    componentEvidence,
    options.signal,
  );
  const providers = providerEvidence(scanResults);
  const coverage = snapshotCoverage(scanResults, providers);
  const policy = snapshotPolicy(options.policy);
  const analysis = snapshotAnalysis(options, dependencies);
  const workspaceRoots = new Set(
    scanResults.map((result) =>
      sha256CanonicalJson(json(safeString(result.workspacePath, "workspace path", MAXIMUM_TEXT))),
    ),
  );
  const partial = {
    schema: SECURITY_SNAPSHOT_SCHEMA,
    schemaVersion: SECURITY_SNAPSHOT_SCHEMA_VERSION,
    timestamp: selectedTimestamp,
    scanner: Object.freeze({
      name: "Dependency Vulnerability Auditor" as const,
      version: scannerVersion,
    }),
    workspace: Object.freeze({
      identityHash: sha256CanonicalJson(json(workspaceIdentity)),
      rootCount: workspaceRoots.size,
    }),
    dependencies,
    vulnerabilities,
    coverage,
    policy,
    analysis,
  };
  const integrity = Object.freeze({
    algorithm: "SHA-256" as const,
    digest: sha256CanonicalJson(json(partial)),
  });
  const snapshot = { ...partial, integrity } as SecuritySnapshot;
  throwIfCancelled(options.signal);
  return deepFreezeJson(json(snapshot)) as unknown as SecuritySnapshot;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function expectRecord(
  value: unknown,
  name: string,
  keys: readonly string[],
): Record<string, unknown> {
  if (!isRecord(value) || !exactKeys(value, keys)) {
    throw new SecuritySnapshotError("INVALID_INPUT", `${name} has an invalid shape`);
  }
  return value;
}

function expectStringArray(
  value: unknown,
  name: string,
  maximum: number,
  maximumLength = MAXIMUM_TOKEN,
): readonly string[] {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new SecuritySnapshotError("LIMIT_EXCEEDED", `${name} exceeds its safety limit`);
  }
  const entries = value.map((entry) => safeString(entry, name, maximumLength));
  if (
    entries.some(
      (entry, index) => index > 0 && compareText(entries[index - 1] ?? "", entry) >= 0,
    )
  ) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      `${name} must be deterministically sorted and unique`,
    );
  }
  return Object.freeze(entries);
}

function parseComponent(value: unknown): SnapshotComponent {
  const record = expectRecord(value, "snapshot component", [
    "key",
    "evidenceHash",
    "ecosystem",
    "name",
    "version",
    "resolution",
    "dependencyTypes",
    "environments",
    "packageManagers",
    "occurrenceCount",
  ]);
  const ecosystem = safeString(record.ecosystem, "component ecosystem", 64);
  const name = safeString(record.name, "component name");
  if (
    record.resolution !== "resolved" &&
    record.resolution !== "unresolved" &&
    record.resolution !== "unsupported"
  ) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Component resolution is invalid");
  }
  const version =
    record.version === null
      ? null
      : safeString(record.version, "component version", 256);
  if ((record.resolution === "resolved") !== (version !== null)) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Component resolution and version disagree",
    );
  }
  const key = safeString(record.key, "component key", 64);
  if (!SHA256.test(key) || key !== componentKey(ecosystem, name, version, record.resolution)) {
    throw new SecuritySnapshotError("INTEGRITY_MISMATCH", "Component key is invalid");
  }
  const dependencyTypes = expectStringArray(
    record.dependencyTypes,
    "component dependency types",
    2,
    32,
  );
  if (dependencyTypes.some((entry) => entry !== "direct" && entry !== "transitive")) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Component dependency type is invalid");
  }
  const environments = expectStringArray(
    record.environments,
    "component environments",
    4,
    32,
  );
  if (
    environments.some(
      (entry) =>
        entry !== "production" &&
        entry !== "development" &&
        entry !== "optional" &&
        entry !== "peer",
    )
  ) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Component environment is invalid");
  }
  const packageManagers = expectStringArray(
    record.packageManagers,
    "component package managers",
    64,
    64,
  );
  const occurrenceCount = nonNegativeInteger(
    record.occurrenceCount,
    "component occurrence count",
  );
  if (occurrenceCount < 1) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Component occurrence count must be positive",
    );
  }
  const evidenceHash = safeString(record.evidenceHash, "component evidence hash", 64);
  if (
    !SHA256.test(evidenceHash) ||
    evidenceHash !==
      sha256CanonicalJson(
        json({
          dependencyTypes,
          environments,
          occurrenceCount,
          packageManagers,
        }),
      )
  ) {
    throw new SecuritySnapshotError(
      "INTEGRITY_MISMATCH",
      "Component evidence hash is invalid",
    );
  }
  return Object.freeze({
    key,
    evidenceHash,
    ecosystem,
    name,
    version,
    resolution: record.resolution,
    dependencyTypes: dependencyTypes as SnapshotComponent["dependencyTypes"],
    environments: environments as SnapshotComponent["environments"],
    packageManagers,
    occurrenceCount,
  });
}

function parseVulnerability(value: unknown): SnapshotVulnerability {
  if (!isRecord(value)) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Snapshot vulnerability has an invalid shape");
  }
  const allowed = [
    "key",
    "identityKey",
    "evidenceHash",
    "componentKey",
    "componentEvidenceHash",
    "id",
    "aliases",
    "severity",
    ...(value.cvssScore === undefined ? [] : ["cvssScore"]),
    "source",
    "fixedVersions",
    "fixedVersionConflict",
    "knownExploitation",
    "reachability",
  ];
  if (!exactKeys(value, allowed)) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Snapshot vulnerability has an invalid shape");
  }
  const componentKeyValue = safeString(value.componentKey, "vulnerability component key", 64);
  const componentEvidenceHash = safeString(
    value.componentEvidenceHash,
    "vulnerability component evidence hash",
    64,
  );
  const id = safeString(value.id, "vulnerability id");
  const source = safeString(value.source, "vulnerability source", 64);
  const aliases = expectStringArray(value.aliases, "vulnerability aliases", MAXIMUM_ALIASES);
  const fixedVersions = expectStringArray(
    value.fixedVersions,
    "vulnerability fixed versions",
    MAXIMUM_FIXED_VERSIONS,
    256,
  );
  if (typeof value.severity !== "string" || !SEVERITIES.has(value.severity)) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Vulnerability severity is invalid");
  }
  if (
    value.cvssScore !== undefined &&
    (typeof value.cvssScore !== "number" ||
      !Number.isFinite(value.cvssScore) ||
      value.cvssScore < 0 ||
      value.cvssScore > 10)
  ) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Vulnerability CVSS score is invalid");
  }
  if (
    value.knownExploitation !== "known-exploited" &&
    value.knownExploitation !== "not-known-exploited" &&
    value.knownExploitation !== "unknown"
  ) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Known exploitation is invalid");
  }
  if (value.reachability !== "unknown") {
    throw new SecuritySnapshotError("INVALID_INPUT", "Reachability evidence is invalid");
  }
  if (typeof value.fixedVersionConflict !== "boolean") {
    throw new SecuritySnapshotError("INVALID_INPUT", "Fixed-version conflict evidence is invalid");
  }
  const identityKey = safeString(value.identityKey, "vulnerability identity key", 64);
  const evidenceHash = safeString(value.evidenceHash, "vulnerability evidence hash", 64);
  const key = safeString(value.key, "vulnerability key", 64);
  if (!SHA256.test(componentKeyValue) || !SHA256.test(componentEvidenceHash) || !SHA256.test(identityKey) || !SHA256.test(evidenceHash) || !SHA256.test(key)) {
    throw new SecuritySnapshotError("INTEGRITY_MISMATCH", "Vulnerability hash is invalid");
  }
  const expectedEvidenceHash = sha256CanonicalJson(
    json({
      aliases,
      componentKey: componentKeyValue,
      componentEvidenceHash,
      cvssScore: value.cvssScore ?? null,
      fixedVersions,
      fixedVersionConflict: value.fixedVersionConflict,
      knownExploitation: value.knownExploitation,
      severity: value.severity,
    }),
  );
  if (
    expectedEvidenceHash !== evidenceHash ||
    key !== sha256CanonicalJson(json([identityKey, evidenceHash]))
  ) {
    throw new SecuritySnapshotError("INTEGRITY_MISMATCH", "Vulnerability evidence hash is invalid");
  }
  return Object.freeze({
    key,
    identityKey,
    evidenceHash,
    componentKey: componentKeyValue,
    componentEvidenceHash,
    id,
    aliases,
    severity: value.severity as Severity,
    ...(value.cvssScore === undefined ? {} : { cvssScore: value.cvssScore }),
    source,
    fixedVersions,
    fixedVersionConflict: value.fixedVersionConflict,
    knownExploitation: value.knownExploitation,
    reachability: "unknown" as const,
  });
}

function parseProvider(value: unknown): SnapshotProviderEvidence {
  const record = expectRecord(value, "snapshot provider evidence", [
    "provider",
    "status",
    "dependenciesEligible",
    "dependenciesSubmitted",
    "successful",
    "failed",
    "cacheHits",
    "staleCacheFallbacks",
    "vulnerabilitiesFound",
  ]);
  if (
    record.status !== "available" &&
    record.status !== "partial" &&
    record.status !== "unavailable"
  ) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Provider status is invalid");
  }
  return Object.freeze({
    provider: safeString(record.provider, "provider name", 64),
    status: record.status,
    dependenciesEligible: nonNegativeInteger(record.dependenciesEligible, "provider count"),
    dependenciesSubmitted: nonNegativeInteger(record.dependenciesSubmitted, "provider count"),
    successful: nonNegativeInteger(record.successful, "provider count"),
    failed: nonNegativeInteger(record.failed, "provider count"),
    cacheHits: nonNegativeInteger(record.cacheHits, "provider count"),
    staleCacheFallbacks: nonNegativeInteger(record.staleCacheFallbacks, "provider count"),
    vulnerabilitiesFound: nonNegativeInteger(record.vulnerabilitiesFound, "provider count"),
  });
}

function parseAnalysisSummary(
  value: unknown,
  name: string,
): SnapshotAnalysisSummary {
  const record = expectRecord(value, name, [
    "totalRecords",
    "processedRecords",
    "unknownRecords",
    "concerningRecords",
    "evidenceHash",
  ]);
  const totalRecords = nonNegativeInteger(
    record.totalRecords,
    `${name} total records`,
  );
  const processedRecords = nonNegativeInteger(
    record.processedRecords,
    `${name} processed records`,
  );
  const unknownRecords = nonNegativeInteger(
    record.unknownRecords,
    `${name} unknown records`,
  );
  const concerningRecords = nonNegativeInteger(
    record.concerningRecords,
    `${name} concerning records`,
  );
  const evidenceHash = safeString(
    record.evidenceHash,
    `${name} evidence hash`,
    64,
  );
  if (
    totalRecords > MAXIMUM_ANALYSIS_RECORDS ||
    processedRecords > totalRecords ||
    unknownRecords > processedRecords ||
    concerningRecords > processedRecords ||
    !SHA256.test(evidenceHash)
  ) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      `${name} contains inconsistent evidence counts`,
    );
  }
  return Object.freeze({
    totalRecords,
    processedRecords,
    unknownRecords,
    concerningRecords,
    evidenceHash,
  });
}

function parseSnapshotValue(value: JsonValue): SecuritySnapshot {
  const root = expectRecord(value, "security snapshot", [
    "schema",
    "schemaVersion",
    "timestamp",
    "scanner",
    "workspace",
    "dependencies",
    "vulnerabilities",
    "coverage",
    "policy",
    "analysis",
    "integrity",
  ]);
  if (root.schema !== SECURITY_SNAPSHOT_SCHEMA || root.schemaVersion !== 1) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Security snapshot schema is unsupported");
  }
  const scanner = expectRecord(root.scanner, "snapshot scanner", ["name", "version"]);
  if (scanner.name !== "Dependency Vulnerability Auditor") {
    throw new SecuritySnapshotError("INVALID_INPUT", "Snapshot scanner is invalid");
  }
  const workspace = expectRecord(root.workspace, "snapshot workspace", [
    "identityHash",
    "rootCount",
  ]);
  const identityHash = safeString(workspace.identityHash, "workspace identity hash", 64);
  if (!SHA256.test(identityHash)) {
    throw new SecuritySnapshotError("INTEGRITY_MISMATCH", "Workspace identity hash is invalid");
  }
  if (!Array.isArray(root.dependencies) || root.dependencies.length > MAXIMUM_DEPENDENCIES) {
    throw new SecuritySnapshotError("LIMIT_EXCEEDED", "Snapshot dependencies exceed the safety limit");
  }
  if (!Array.isArray(root.vulnerabilities) || root.vulnerabilities.length > MAXIMUM_VULNERABILITIES) {
    throw new SecuritySnapshotError("LIMIT_EXCEEDED", "Snapshot vulnerabilities exceed the safety limit");
  }
  const dependencies = Object.freeze(root.dependencies.map(parseComponent));
  const dependencyKeys = new Set(dependencies.map((component) => component.key));
  if (dependencyKeys.size !== dependencies.length) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Snapshot contains duplicate components");
  }
  if (
    dependencies.some(
      (component, index) =>
        index > 0 &&
        compareText(dependencies[index - 1]?.key ?? "", component.key) >= 0,
    )
  ) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Snapshot components must be deterministically sorted",
    );
  }
  const vulnerabilities = Object.freeze(root.vulnerabilities.map(parseVulnerability));
  const vulnerabilityKeys = new Set(vulnerabilities.map((finding) => finding.key));
  if (vulnerabilityKeys.size !== vulnerabilities.length) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Snapshot contains duplicate vulnerabilities");
  }
  if (
    vulnerabilities.some(
      (finding, index) =>
        index > 0 &&
        compareText(vulnerabilities[index - 1]?.key ?? "", finding.key) >= 0,
    )
  ) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Snapshot vulnerabilities must be deterministically sorted",
    );
  }
  const componentsByKey = new Map(
    dependencies.map((component) => [component.key, component] as const),
  );
  for (const finding of vulnerabilities) {
    const component = componentsByKey.get(finding.componentKey);
    if (component === undefined) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "Snapshot vulnerability references an unknown component",
      );
    }
    if (finding.componentEvidenceHash !== component.evidenceHash) {
      throw new SecuritySnapshotError(
        "INTEGRITY_MISMATCH",
        "Vulnerability component occurrence evidence is invalid",
      );
    }
    const expectedIdentity = sha256CanonicalJson(
      json([finding.source, finding.id, component.ecosystem, component.name]),
    );
    if (finding.identityKey !== expectedIdentity) {
      throw new SecuritySnapshotError(
        "INTEGRITY_MISMATCH",
        "Vulnerability identity hash is invalid",
      );
    }
  }
  const coverageRecord = expectRecord(root.coverage, "snapshot coverage", [
    "status",
    "dependencyInventory",
    "vulnerabilityAnalysis",
    "errorCodes",
    "providers",
  ]);
  if (
    typeof coverageRecord.status !== "string" ||
    !COVERAGE_STATUSES.has(coverageRecord.status) ||
    typeof coverageRecord.dependencyInventory !== "string" ||
    !EVIDENCE_STATES.has(coverageRecord.dependencyInventory) ||
    typeof coverageRecord.vulnerabilityAnalysis !== "string" ||
    !EVIDENCE_STATES.has(coverageRecord.vulnerabilityAnalysis)
  ) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Snapshot coverage is invalid");
  }
  if (!Array.isArray(coverageRecord.providers) || coverageRecord.providers.length > MAXIMUM_SCAN_RESULTS * 64) {
    throw new SecuritySnapshotError("LIMIT_EXCEEDED", "Snapshot providers exceed the safety limit");
  }
  const errorCodes = expectStringArray(
    coverageRecord.errorCodes,
    "coverage error codes",
    64,
    64,
  );
  if (errorCodes.some((code) => !SCAN_ERROR_CODES.has(code))) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Snapshot coverage contains an unknown error code",
    );
  }
  const parsedProviders = Object.freeze(coverageRecord.providers.map(parseProvider));
  if (
    parsedProviders.some(
      (provider, index) =>
        index > 0 &&
        compareText(
          parsedProviders[index - 1]?.provider ?? "",
          provider.provider,
        ) >= 0,
    )
  ) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Snapshot provider evidence must be deterministically sorted and unique",
    );
  }
  const coverage: SnapshotCoverage = Object.freeze({
    status: coverageRecord.status as SnapshotCoverageStatus,
    dependencyInventory: coverageRecord.dependencyInventory as SnapshotEvidenceState,
    vulnerabilityAnalysis: coverageRecord.vulnerabilityAnalysis as SnapshotEvidenceState,
    errorCodes: errorCodes as readonly ScanErrorCode[],
    providers: parsedProviders,
  });
  const policyRecord = expectRecord(root.policy, "snapshot policy", [
    "status",
    "complete",
    "coverage",
    "reasonCodes",
  ]);
  if (
    (policyRecord.status !== "not-evaluated" &&
      policyRecord.status !== "PASS" &&
      policyRecord.status !== "WARN" &&
      policyRecord.status !== "FAIL") ||
    typeof policyRecord.complete !== "boolean" ||
    typeof policyRecord.coverage !== "string" ||
    !COVERAGE_STATUSES.has(policyRecord.coverage)
  ) {
    throw new SecuritySnapshotError("INVALID_INPUT", "Snapshot policy is invalid");
  }
  const policy: SnapshotPolicyEvidence = Object.freeze({
    status: policyRecord.status,
    complete: policyRecord.complete,
    coverage: policyRecord.coverage as SnapshotCoverageStatus,
    reasonCodes: expectStringArray(policyRecord.reasonCodes, "policy reason codes", 250_000, 64),
  });
  if (!isRecord(root.analysis)) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Snapshot analysis has an invalid shape",
    );
  }
  const analysisRecord = root.analysis;
  const analysisKeys = [
    "licenses",
    "provenance",
    "reachability",
    ...(analysisRecord.licenseSummary === undefined
      ? []
      : ["licenseSummary"]),
    ...(analysisRecord.provenanceSummary === undefined
      ? []
      : ["provenanceSummary"]),
    ...(analysisRecord.reachabilitySummary === undefined
      ? []
      : ["reachabilitySummary"]),
  ];
  if (!exactKeys(analysisRecord, analysisKeys)) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Snapshot analysis has an invalid shape",
    );
  }
  for (const key of ["licenses", "provenance", "reachability"] as const) {
    const value = analysisRecord[key];
    if (typeof value !== "string" || !EVIDENCE_STATES.has(value)) {
      throw new SecuritySnapshotError(
        "INVALID_INPUT",
        "Snapshot analysis state is invalid",
      );
    }
  }
  const licenseSummary =
    analysisRecord.licenseSummary === undefined
      ? undefined
      : parseAnalysisSummary(
          analysisRecord.licenseSummary,
          "license analysis summary",
        );
  const provenanceSummary =
    analysisRecord.provenanceSummary === undefined
      ? undefined
      : parseAnalysisSummary(
          analysisRecord.provenanceSummary,
          "provenance analysis summary",
        );
  const reachabilitySummary =
    analysisRecord.reachabilitySummary === undefined
      ? undefined
      : parseAnalysisSummary(
          analysisRecord.reachabilitySummary,
          "reachability analysis summary",
        );
  if (
    (analysisRecord.licenses === "not-configured") !==
      (licenseSummary === undefined) ||
    (analysisRecord.provenance === "not-configured") !==
      (provenanceSummary === undefined) ||
    (analysisRecord.reachability === "not-configured") !==
      (reachabilitySummary === undefined)
  ) {
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Snapshot analysis state and summary availability disagree",
    );
  }
  const integrityRecord = expectRecord(root.integrity, "snapshot integrity", [
    "algorithm",
    "digest",
  ]);
  const digest = safeString(integrityRecord.digest, "snapshot digest", 64);
  if (integrityRecord.algorithm !== "SHA-256" || !SHA256.test(digest)) {
    throw new SecuritySnapshotError("INTEGRITY_MISMATCH", "Snapshot integrity record is invalid");
  }
  const snapshot: SecuritySnapshot = {
    schema: SECURITY_SNAPSHOT_SCHEMA,
    schemaVersion: SECURITY_SNAPSHOT_SCHEMA_VERSION,
    timestamp: timestamp(root.timestamp, "snapshot timestamp"),
    scanner: Object.freeze({
      name: "Dependency Vulnerability Auditor" as const,
      version: safeString(scanner.version, "scanner version", 256),
    }),
    workspace: Object.freeze({
      identityHash,
      rootCount: (() => {
        const count = nonNegativeInteger(
          workspace.rootCount,
          "workspace root count",
        );
        if (count > MAXIMUM_SCAN_RESULTS) {
          throw new SecuritySnapshotError(
            "LIMIT_EXCEEDED",
            "Workspace root count exceeds the safety limit",
          );
        }
        return count;
      })(),
    }),
    dependencies,
    vulnerabilities,
    coverage,
    policy,
    analysis: Object.freeze({
      licenses: analysisRecord.licenses as SnapshotEvidenceState,
      provenance: analysisRecord.provenance as SnapshotEvidenceState,
      reachability: analysisRecord.reachability as SnapshotEvidenceState,
      ...(licenseSummary === undefined ? {} : { licenseSummary }),
      ...(provenanceSummary === undefined ? {} : { provenanceSummary }),
      ...(reachabilitySummary === undefined ? {} : { reachabilitySummary }),
    }),
    integrity: Object.freeze({ algorithm: "SHA-256" as const, digest }),
  };
  if (sha256CanonicalJson(snapshotPayload(snapshot)) !== digest) {
    throw new SecuritySnapshotError(
      "INTEGRITY_MISMATCH",
      "Security snapshot SHA-256 verification failed",
    );
  }
  return deepFreezeJson(json(snapshot)) as unknown as SecuritySnapshot;
}

export function parseSecuritySnapshotJson(
  text: string,
  options: ParseBoundedJsonOptions = {},
): SecuritySnapshot {
  try {
    return parseSnapshotValue(parseBoundedJson(text, options));
  } catch (error: unknown) {
    if (error instanceof SecuritySnapshotError) {
      throw error;
    }
    if (error instanceof BoundedJsonError) {
      throw new SecuritySnapshotError(
        error.code === "CANCELLED"
          ? "CANCELLED"
          : error.code === "LIMIT_EXCEEDED"
            ? "LIMIT_EXCEEDED"
            : "INVALID_INPUT",
        error.message,
        { cause: error },
      );
    }
    throw new SecuritySnapshotError(
      "INVALID_INPUT",
      "Security snapshot could not be parsed safely",
      { cause: error },
    );
  }
}

export function verifySecuritySnapshot(snapshot: SecuritySnapshot): boolean {
  try {
    const serialized = canonicalJson(json(snapshot));
    parseSecuritySnapshotJson(serialized);
    return true;
  } catch {
    return false;
  }
}

export function serializeSecuritySnapshot(snapshot: SecuritySnapshot): string {
  if (!verifySecuritySnapshot(snapshot)) {
    throw new SecuritySnapshotError(
      "INTEGRITY_MISMATCH",
      "Refusing to serialize an invalid security snapshot",
    );
  }
  return `${canonicalJson(json(snapshot))}\n`;
}
