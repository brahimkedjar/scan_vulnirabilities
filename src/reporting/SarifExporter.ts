import {
  dependencyIsResolved,
  dependencyManifestPath,
  type Dependency,
} from "../models/Dependency";
import type { ScanErrorCode, ScanResult } from "../models/ScanResult";
import type { Severity, Vulnerability } from "../models/Vulnerability";
import {
  canonicalComponentIdentity,
  canonicalComponentIdentityForCoordinate,
  componentCoordinateKey,
  safeRelativeArtifactUri,
  safeWorkspaceRelativePath,
  stableSha256,
} from "../sbom/ComponentIdentity";

export interface SarifScanResult extends ScanResult {
  readonly allVulnerabilities?: readonly Vulnerability[];
}

export interface SarifExportLimits {
  readonly maximumScanResults: number;
  readonly maximumDependencies: number;
  readonly maximumVulnerabilities: number;
  readonly maximumResults: number;
  readonly maximumRules: number;
  readonly maximumOutputBytes: number;
}

export const SARIF_EXPORT_LIMITS: Readonly<SarifExportLimits> = Object.freeze({
  maximumScanResults: 64,
  maximumDependencies: 10_000,
  maximumVulnerabilities: 25_000,
  maximumResults: 25_000,
  maximumRules: 25_000,
  maximumOutputBytes: 64 * 1024 * 1024,
});

export interface SarifExportOptions {
  /** Roots used to produce repository-relative artifact URI references. */
  readonly workspaceRoots?: readonly string[];
  readonly toolVersion?: string;
  readonly signal?: AbortSignal;
  readonly limits?: Partial<SarifExportLimits>;
}

export type SarifExportErrorCode =
  | "CANCELLED"
  | "INVALID_INPUT"
  | "LIMIT_EXCEEDED";

export class SarifExportError extends Error {
  public constructor(
    public readonly code: SarifExportErrorCode,
    message: string,
    options: { readonly cause?: unknown } = {},
  ) {
    super(message, options);
    this.name = "SarifExportError";
  }
}

export type SarifLevel = "error" | "warning" | "note";

export interface SarifReportingDescriptor {
  readonly id: string;
  readonly shortDescription: { readonly text: string };
  readonly helpUri?: string;
  readonly properties: Readonly<
    Record<string, string | number | readonly string[]>
  >;
}

export interface SarifResult {
  readonly ruleId: string;
  readonly ruleIndex: number;
  readonly level: SarifLevel;
  readonly message: { readonly text: string };
  readonly locations: readonly [
    {
      readonly physicalLocation: {
        readonly artifactLocation: { readonly uri: string };
        readonly region?: {
          readonly startLine: number;
          readonly startColumn: 1;
        };
      };
    },
  ];
  readonly partialFingerprints: {
    readonly primaryLocationLineHash: string;
  };
  readonly properties: Readonly<Record<string, string | number | boolean>>;
}

export interface SarifLog {
  readonly $schema: "https://json.schemastore.org/sarif-2.1.0.json";
  readonly version: "2.1.0";
  readonly runs: readonly [
    {
      readonly tool: {
        readonly driver: {
          readonly name: "Dependency Vulnerability Auditor";
          readonly semanticVersion?: string;
          readonly informationUri: string;
          readonly rules: readonly SarifReportingDescriptor[];
        };
      };
      readonly results: readonly SarifResult[];
      readonly invocations?: readonly [
        {
          readonly executionSuccessful: false;
          readonly toolExecutionNotifications: readonly {
            readonly level: "warning";
            readonly message: { readonly text: string };
          }[];
        },
      ];
    },
  ];
}

interface IndexedDependency {
  readonly dependency: Dependency;
  readonly coordinate: string;
  readonly origin?: string;
  readonly path?: readonly string[];
}

interface RuleEvidence {
  readonly id: string;
  readonly providers: Set<string>;
  readonly references: Set<string>;
  readonly scores: number[];
}

interface PendingResult {
  readonly ruleId: string;
  readonly level: SarifLevel;
  readonly message: string;
  readonly uri: string;
  readonly line?: number;
  readonly fingerprint: string;
  readonly properties: Readonly<Record<string, string | number | boolean>>;
}

const LIMIT_KEYS = [
  "maximumScanResults",
  "maximumDependencies",
  "maximumVulnerabilities",
  "maximumResults",
  "maximumRules",
  "maximumOutputBytes",
] as const satisfies readonly (keyof SarifExportLimits)[];
const MAXIMUM_SOURCE_LINE = 10_000_000;
const MAXIMUM_DEPENDENCY_PATH_SEGMENTS = 256;
const UNSAFE_TOKEN =
  /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const UNSAFE_TEXT =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const ABSOLUTE_OR_URI = /^(?:[A-Za-z]:[\\/]|[\\/]|[A-Za-z][A-Za-z0-9+.-]*:)/u;
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

function throwIfCancelled(signal?: AbortSignal): void {
  if (signal?.aborted === true) {
    throw new SarifExportError("CANCELLED", "SARIF export was cancelled");
  }
}

function resolveLimits(
  requested: Partial<SarifExportLimits> | undefined,
): SarifExportLimits {
  const resolved = { ...SARIF_EXPORT_LIMITS };
  for (const key of LIMIT_KEYS) {
    const value = requested?.[key];
    if (value === undefined) {
      continue;
    }
    if (
      !Number.isSafeInteger(value) ||
      value < 1 ||
      value > SARIF_EXPORT_LIMITS[key]
    ) {
      throw new SarifExportError(
        "INVALID_INPUT",
        `${key} is outside the supported safety range`,
      );
    }
    resolved[key] = value;
  }
  return resolved;
}

function requireToken(value: unknown, name: string, maximumLength: number): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    value.trim() !== value ||
    UNSAFE_TOKEN.test(value)
  ) {
    throw new SarifExportError("INVALID_INPUT", `${name} is invalid`);
  }
  return value;
}

function requireText(value: unknown, name: string, maximumLength: number): string {
  if (
    typeof value !== "string" ||
    value.length > maximumLength ||
    UNSAFE_TEXT.test(value)
  ) {
    throw new SarifExportError("INVALID_INPUT", `${name} is invalid`);
  }
  return value;
}

function selectedVulnerabilities(result: SarifScanResult): {
  readonly vulnerabilities: readonly Vulnerability[];
  readonly unfilteredAvailable: boolean;
} {
  const completeCollections: Array<{
    readonly property: string;
    readonly vulnerabilities: readonly Vulnerability[];
  }> = [];
  for (const property of [
    "allVulnerabilities",
    "unfilteredVulnerabilities",
  ] as const) {
    const descriptor = Object.getOwnPropertyDescriptor(result, property);
    if (
      descriptor !== undefined &&
      (descriptor.get !== undefined || descriptor.set !== undefined)
    ) {
      throw new SarifExportError(
        "INVALID_INPUT",
        `${property} must be a data property`,
      );
    }
    if (descriptor?.value !== undefined) {
      const value = descriptor.value as unknown;
      if (!Array.isArray(value)) {
        throw new SarifExportError(
          "INVALID_INPUT",
          `${property} must be an array`,
        );
      }
      completeCollections.push({
        property,
        vulnerabilities: value as readonly Vulnerability[],
      });
    }
  }
  if (!Array.isArray(result.vulnerabilities)) {
    throw new SarifExportError(
      "INVALID_INPUT",
      "vulnerabilities must be an array",
    );
  }
  const first = completeCollections[0];
  const second = completeCollections[1];
  if (
    first !== undefined &&
    second !== undefined &&
    (first.vulnerabilities.length !== second.vulnerabilities.length ||
      first.vulnerabilities.some(
        (vulnerability, index) =>
          vulnerability !== second.vulnerabilities[index],
      ))
  ) {
    throw new SarifExportError(
      "INVALID_INPUT",
      `${first.property} and ${second.property} contain conflicting findings`,
    );
  }
  return first === undefined
    ? { vulnerabilities: result.vulnerabilities, unfilteredAvailable: false }
    : {
        vulnerabilities: first.vulnerabilities,
        unfilteredAvailable: true,
      };
}

function dependencyPath(dependency: Dependency): readonly string[] | undefined {
  const value = dependency.dependencyPath;
  if (value === undefined) {
    return undefined;
  }
  if (value.length > MAXIMUM_DEPENDENCY_PATH_SEGMENTS) {
    throw new SarifExportError(
      "LIMIT_EXCEEDED",
      "A dependency path exceeds the segment safety limit",
    );
  }
  for (const segment of value) {
    requireToken(segment, "dependency path segment", 512);
  }
  return value;
}

function provenanceValue(value: string | undefined, name: string): string {
  return value === undefined ? "" : requireToken(value, name, 4_096);
}

function dependencyOriginKey(dependency: Dependency): string | undefined {
  const manifestPath = dependencyManifestPath(dependency);
  if (manifestPath === undefined && dependency.lockfilePath === undefined) {
    return undefined;
  }
  return JSON.stringify([
    provenanceValue(dependency.workspacePath, "workspace path"),
    provenanceValue(dependency.projectPath, "project path"),
    provenanceValue(manifestPath, "manifest path"),
    provenanceValue(dependency.lockfilePath, "lockfile path"),
    provenanceValue(dependency.packageManager, "package manager"),
  ]);
}

function dependencyOccurrenceKey(dependency: Dependency): string {
  return JSON.stringify([
    provenanceValue(dependency.workspacePath, "workspace path"),
    provenanceValue(dependency.projectPath, "project path"),
    provenanceValue(dependencyManifestPath(dependency), "manifest path"),
    provenanceValue(dependency.lockfilePath, "lockfile path"),
    provenanceValue(dependency.packageManager, "package manager"),
    dependency.ecosystem,
    dependency.name,
    dependency.installedVersion,
    dependency.dependencyType,
    dependency.environment,
    dependencyPath(dependency) ?? [],
  ]);
}

function preferredRuleId(vulnerability: Vulnerability): string {
  const identifiers = [...new Set([vulnerability.id, ...vulnerability.aliases])];
  for (const identifier of identifiers) {
    requireToken(identifier, "vulnerability identifier", 512);
  }
  const cve = identifiers
    .filter((identifier) => /^CVE-/iu.test(identifier))
    .sort((left, right) => left.localeCompare(right, "en"))[0];
  const ghsa = identifiers
    .filter((identifier) => /^GHSA-/iu.test(identifier))
    .sort((left, right) => left.localeCompare(right, "en"))[0];
  const selected = cve ?? ghsa ?? vulnerability.id;
  return /^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,511}$/u.test(selected)
    ? selected
    : `advisory-${stableSha256(selected)}`;
}

function levelForSeverity(severity: Severity): SarifLevel {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "error";
    case "MEDIUM":
    case "UNKNOWN":
      return "warning";
    case "LOW":
      return "note";
  }
}

function validateVulnerability(vulnerability: Vulnerability): void {
  requireToken(vulnerability.id, "vulnerability id", 512);
  requireToken(vulnerability.source, "vulnerability source", 64);
  requireToken(vulnerability.packageName, "vulnerability package name", 512);
  requireToken(vulnerability.ecosystem, "vulnerability ecosystem", 64);
  requireToken(vulnerability.installedVersion, "installed version", 256);
  requireText(vulnerability.summary, "vulnerability summary", 8_192);
  if (
    !["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].includes(
      vulnerability.severity,
    )
  ) {
    throw new SarifExportError(
      "INVALID_INPUT",
      "vulnerability severity is invalid",
    );
  }
  if (vulnerability.aliases.length > 256) {
    throw new SarifExportError(
      "LIMIT_EXCEEDED",
      "vulnerability aliases exceed the safety limit",
    );
  }
  for (const alias of vulnerability.aliases) {
    requireToken(alias, "vulnerability alias", 512);
  }
  if (vulnerability.references.length > 512) {
    throw new SarifExportError(
      "LIMIT_EXCEEDED",
      "vulnerability references exceed the safety limit",
    );
  }
  for (const reference of vulnerability.references) {
    requireToken(reference, "vulnerability reference", 4_096);
    try {
      const url = new URL(reference);
      if (
        url.protocol !== "https:" ||
        url.hostname.length === 0 ||
        url.username.length > 0 ||
        url.password.length > 0
      ) {
        throw new TypeError("unsafe URL");
      }
    } catch {
      throw new SarifExportError(
        "INVALID_INPUT",
        "vulnerability references must be credential-free HTTPS URLs",
      );
    }
  }
  if (
    vulnerability.cvssScore !== undefined &&
    (typeof vulnerability.cvssScore !== "number" ||
      !Number.isFinite(vulnerability.cvssScore) ||
      vulnerability.cvssScore < 0 ||
      vulnerability.cvssScore > 10)
  ) {
    throw new SarifExportError("INVALID_INPUT", "CVSS score is invalid");
  }
  if (vulnerability.fixedVersion !== undefined) {
    requireToken(vulnerability.fixedVersion, "fixed version", 256);
  }
  if (vulnerability.affectedRange !== undefined) {
    requireText(vulnerability.affectedRange, "affected range", 32_768);
  }
}

function normalizedVulnerabilityEvidence(
  vulnerability: Vulnerability,
): string {
  return JSON.stringify({
    affectedRange: vulnerability.affectedRange ?? "",
    aliases: [...vulnerability.aliases].sort(),
    cvssScore: vulnerability.cvssScore ?? null,
    fixedVersion: vulnerability.fixedVersion ?? "",
    references: [...vulnerability.references].sort(),
    severity: vulnerability.severity,
    summary: vulnerability.summary,
  });
}

function displayMessage(
  vulnerability: Vulnerability,
  dependency: Dependency,
  ruleId: string,
): string {
  const summary = vulnerability.summary.replace(/\s+/gu, " ").trim();
  const prefix = summary.length === 0 ? "Known dependency vulnerability" : summary;
  const type = dependency.dependencyType === "direct" ? "direct" : "transitive";
  const message = `${ruleId}: ${prefix}. Affects ${vulnerability.ecosystem} package ${vulnerability.packageName}@${vulnerability.installedVersion} (${type} dependency). Evidence source: ${vulnerability.source}.`;
  return message.length <= 4_096 ? message : `${message.slice(0, 4_093)}...`;
}

function sourceLine(dependency: Dependency): number | undefined {
  const value = dependency.metadata?.sourceLine;
  if (value === undefined) {
    return undefined;
  }
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > MAXIMUM_SOURCE_LINE
  ) {
    throw new SarifExportError(
      "INVALID_INPUT",
      "Dependency sourceLine metadata is invalid",
    );
  }
  return value;
}

function fingerprintPath(
  pathSegments: readonly string[],
  workspaceRoots: readonly string[],
): readonly string[] {
  return pathSegments.map((segment) => {
    if (!ABSOLUTE_OR_URI.test(segment)) {
      return segment;
    }
    return (
      safeWorkspaceRelativePath(segment, workspaceRoots) ??
      `opaque-path-${stableSha256(segment)}`
    );
  });
}

function coverageIsIncomplete(
  result: SarifScanResult,
  selectedCount: number,
): boolean {
  const providerCount = result.providerResults.reduce(
    (total, provider) => total + provider.vulnerabilitiesFound,
    0,
  );
  return (
    result.cancelled ||
    result.errors.some((error) => COVERAGE_ERROR_CODES.has(error.code)) ||
    result.providerResults.some((provider) => provider.status !== "available") ||
    (result.dependenciesScanned > 0 && result.providerResults.length === 0) ||
    providerCount !== selectedCount ||
    (result.projectCoverage ?? result.ecosystemCoverage ?? []).some(
      (coverage) =>
        coverage.unresolved > 0 ||
        coverage.unsupported > 0 ||
        coverage.checked < coverage.resolved,
    )
  );
}

function outputByteLength(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

export function buildSarifLog(
  scanResults: readonly SarifScanResult[],
  options: SarifExportOptions = {},
): SarifLog {
  const limits = resolveLimits(options.limits);
  throwIfCancelled(options.signal);
  if (
    scanResults.length === 0 ||
    scanResults.length > limits.maximumScanResults
  ) {
    throw new SarifExportError(
      scanResults.length === 0 ? "INVALID_INPUT" : "LIMIT_EXCEEDED",
      "Scan result count is outside the supported safety range",
    );
  }
  if (options.toolVersion !== undefined) {
    requireToken(options.toolVersion, "tool version", 256);
  }
  const workspaceRoots = options.workspaceRoots ?? [];
  if (workspaceRoots.length > 64) {
    throw new SarifExportError(
      "LIMIT_EXCEEDED",
      "Workspace root count exceeds the safety limit",
    );
  }
  const totalDependencies = scanResults.reduce(
    (total, result) => total + result.dependencies.length,
    0,
  );
  if (totalDependencies > limits.maximumDependencies) {
    throw new SarifExportError(
      "LIMIT_EXCEEDED",
      "Dependency input exceeds the SARIF export limit",
    );
  }

  const pendingResults = new Map<string, PendingResult>();
  const ruleEvidence = new Map<string, RuleEvidence>();
  const vulnerabilityEvidence = new Map<string, string>();
  let vulnerabilityCount = 0;
  let omittedOccurrences = 0;
  let incompleteCoverage = false;

  for (const scanResult of scanResults) {
    throwIfCancelled(options.signal);
    if (!Array.isArray(scanResult.dependencies)) {
      throw new SarifExportError(
        "INVALID_INPUT",
        "dependencies must be an array",
      );
    }
    const dependenciesByCoordinate = new Map<string, IndexedDependency[]>();
    const directByPath = new Map<string, Map<string, Dependency>>();
    for (const dependency of scanResult.dependencies) {
      throwIfCancelled(options.signal);
      if (!dependencyIsResolved(dependency)) {
        continue;
      }
      let coordinate: string;
      try {
        coordinate = componentCoordinateKey(
          canonicalComponentIdentity(dependency),
        );
      } catch (error: unknown) {
        throw new SarifExportError(
          "INVALID_INPUT",
          "A resolved dependency has no safe canonical package identity",
          { cause: error },
        );
      }
      const origin = dependencyOriginKey(dependency);
      const path = dependencyPath(dependency);
      const entry: IndexedDependency = {
        dependency,
        coordinate,
        ...(origin === undefined ? {} : { origin }),
        ...(path === undefined ? {} : { path }),
      };
      const matching = dependenciesByCoordinate.get(coordinate) ?? [];
      matching.push(entry);
      dependenciesByCoordinate.set(coordinate, matching);
      if (
        dependency.dependencyType === "direct" &&
        origin !== undefined &&
        path !== undefined &&
        path.length > 0
      ) {
        const key = JSON.stringify([origin, path]);
        const owners = directByPath.get(key) ?? new Map<string, Dependency>();
        owners.set(dependencyOccurrenceKey(dependency), dependency);
        directByPath.set(key, owners);
      }
    }

    const selected = selectedVulnerabilities(scanResult);
    vulnerabilityCount += selected.vulnerabilities.length;
    if (vulnerabilityCount > limits.maximumVulnerabilities) {
      throw new SarifExportError(
        "LIMIT_EXCEEDED",
        "Vulnerability input exceeds the SARIF export limit",
      );
    }
    incompleteCoverage ||= coverageIsIncomplete(
      scanResult,
      selected.vulnerabilities.length,
    );

    for (const vulnerability of selected.vulnerabilities) {
      throwIfCancelled(options.signal);
      validateVulnerability(vulnerability);
      let coordinate: string;
      try {
        coordinate = componentCoordinateKey(
          canonicalComponentIdentityForCoordinate(
            vulnerability.ecosystem,
            vulnerability.packageName,
            vulnerability.installedVersion,
          ),
        );
      } catch (error: unknown) {
        throw new SarifExportError(
          "INVALID_INPUT",
          "A vulnerability has no safe canonical package identity",
          { cause: error },
        );
      }
      const evidenceKey = JSON.stringify([
        vulnerability.source,
        vulnerability.id,
        coordinate,
      ]);
      const normalizedEvidence = normalizedVulnerabilityEvidence(vulnerability);
      const previousEvidence = vulnerabilityEvidence.get(evidenceKey);
      if (
        previousEvidence !== undefined &&
        previousEvidence !== normalizedEvidence
      ) {
        throw new SarifExportError(
          "INVALID_INPUT",
          "Conflicting vulnerability evidence cannot be merged silently",
        );
      }
      vulnerabilityEvidence.set(evidenceKey, normalizedEvidence);
      const matching = dependenciesByCoordinate.get(coordinate) ?? [];
      if (matching.length === 0) {
        omittedOccurrences += 1;
        continue;
      }
      const ruleId = preferredRuleId(vulnerability);
      for (const occurrence of matching) {
        throwIfCancelled(options.signal);
        let target = occurrence.dependency;
        if (
          occurrence.dependency.dependencyType === "transitive" &&
          !(
            occurrence.dependency.packageManager === "go" &&
            occurrence.dependency.metadata?.manifestSection === "require" &&
            occurrence.dependency.manifestName !== undefined
          ) &&
          occurrence.origin !== undefined &&
          occurrence.path !== undefined
        ) {
          for (
            let prefixLength = occurrence.path.length - 1;
            prefixLength > 0;
            prefixLength -= 1
          ) {
            const candidates = directByPath.get(
              JSON.stringify([
                occurrence.origin,
                occurrence.path.slice(0, prefixLength),
              ]),
            );
            if (candidates?.size === 1) {
              target = candidates.values().next().value as Dependency;
              break;
            }
          }
        }
        const rawLocation =
          dependencyManifestPath(target) ??
          dependencyManifestPath(occurrence.dependency) ??
          target.lockfilePath ??
          occurrence.dependency.lockfilePath;
        const uri = safeRelativeArtifactUri(rawLocation, workspaceRoots);
        if (uri === undefined) {
          omittedOccurrences += 1;
          continue;
        }
        const path = fingerprintPath(occurrence.path ?? [], workspaceRoots);
        const line = sourceLine(target);
        const fingerprint = stableSha256(
          JSON.stringify([
            "dependency-auditor-sarif-fingerprint-v1",
            ruleId,
            vulnerability.source,
            vulnerability.id,
            coordinate,
            uri,
            occurrence.dependency.dependencyType,
            occurrence.dependency.environment,
            occurrence.dependency.packageManager ?? "",
            path,
            line ?? 0,
          ]),
        );
        if (!pendingResults.has(fingerprint)) {
          if (pendingResults.size >= limits.maximumResults) {
            throw new SarifExportError(
              "LIMIT_EXCEEDED",
              "Result count exceeds the SARIF export limit",
            );
          }
          const properties: Record<string, string | number | boolean> = {
            "dependency-auditor/advisory-id": vulnerability.id,
            "dependency-auditor/provider": vulnerability.source,
            "dependency-auditor/ecosystem": vulnerability.ecosystem,
            "dependency-auditor/package": vulnerability.packageName,
            "dependency-auditor/installed-version":
              vulnerability.installedVersion,
            "dependency-auditor/dependency-type":
              occurrence.dependency.dependencyType,
            "dependency-auditor/environment": occurrence.dependency.environment,
            "dependency-auditor/path-depth": occurrence.path?.length ?? 0,
          };
          if (vulnerability.cvssScore !== undefined) {
            properties["dependency-auditor/cvss-score"] =
              vulnerability.cvssScore;
          }
          if (vulnerability.fixedVersion !== undefined) {
            properties["dependency-auditor/fixed-version"] =
              vulnerability.fixedVersion;
          }
          if (vulnerability.affectedRange !== undefined) {
            properties["dependency-auditor/affected-range"] =
              vulnerability.affectedRange;
          }
          pendingResults.set(fingerprint, {
            ruleId,
            level: levelForSeverity(vulnerability.severity),
            message: displayMessage(
              vulnerability,
              occurrence.dependency,
              ruleId,
            ),
            uri,
            ...(line === undefined ? {} : { line }),
            fingerprint,
            properties,
          });
        }
        let evidence = ruleEvidence.get(ruleId);
        if (evidence === undefined) {
          if (ruleEvidence.size >= limits.maximumRules) {
            throw new SarifExportError(
              "LIMIT_EXCEEDED",
              "Rule count exceeds the SARIF export limit",
            );
          }
          evidence = {
            id: ruleId,
            providers: new Set(),
            references: new Set(),
            scores: [],
          };
          ruleEvidence.set(ruleId, evidence);
        }
        evidence.providers.add(vulnerability.source);
        for (const reference of vulnerability.references) {
          evidence.references.add(reference);
        }
        if (vulnerability.cvssScore !== undefined) {
          evidence.scores.push(vulnerability.cvssScore);
        }
      }
    }
  }

  const rules: SarifReportingDescriptor[] = [...ruleEvidence.values()]
    .sort((left, right) => left.id.localeCompare(right.id, "en"))
    .map((evidence) => {
      const references = [...evidence.references].sort();
      const scores = [...evidence.scores].sort((left, right) => right - left);
      const properties: Record<string, string | number | readonly string[]> = {
        tags: ["security", "supply-chain", "dependency"],
        "dependency-auditor/providers": [...evidence.providers].sort(),
      };
      if (scores[0] !== undefined) {
        properties["security-severity"] = scores[0].toFixed(1);
      }
      return {
        id: evidence.id,
        shortDescription: {
          text: `Known dependency vulnerability ${evidence.id}`,
        },
        ...(references[0] === undefined ? {} : { helpUri: references[0] }),
        properties,
      };
    });
  const ruleIndexes = new Map(
    rules.map((rule, index) => [rule.id, index] as const),
  );
  const results: SarifResult[] = [...pendingResults.values()]
    .sort(
      (left, right) =>
        left.ruleId.localeCompare(right.ruleId, "en") ||
        left.uri.localeCompare(right.uri, "en") ||
        left.fingerprint.localeCompare(right.fingerprint, "en"),
    )
    .map((result) => {
      const ruleIndex = ruleIndexes.get(result.ruleId);
      if (ruleIndex === undefined) {
        throw new SarifExportError(
          "INVALID_INPUT",
          "A SARIF result has no reporting rule",
        );
      }
      return {
        ruleId: result.ruleId,
        ruleIndex,
        level: result.level,
        message: { text: result.message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: result.uri },
              ...(result.line === undefined
                ? {}
                : {
                    region: {
                      startLine: result.line,
                      startColumn: 1 as const,
                    },
                  }),
            },
          },
        ],
        partialFingerprints: {
          primaryLocationLineHash: `${result.fingerprint}:1`,
        },
        properties: result.properties,
      };
    });
  const notifications: Array<{
    readonly level: "warning";
    readonly message: { readonly text: string };
  }> = [];
  if (omittedOccurrences > 0) {
    notifications.push({
      level: "warning",
      message: {
        text: `${omittedOccurrences.toString()} dependency vulnerability occurrence(s) were omitted because no safe workspace-relative artifact location was available.`,
      },
    });
  }
  if (incompleteCoverage) {
    notifications.push({
      level: "warning",
      message: {
        text: "The source scan reported incomplete dependency or vulnerability coverage; absence of additional SARIF results must not be interpreted as clean coverage.",
      },
    });
  }
  const driver = {
    name: "Dependency Vulnerability Auditor" as const,
    ...(options.toolVersion === undefined
      ? {}
      : { semanticVersion: options.toolVersion }),
    informationUri:
      "https://github.com/brahimkedjar/scan_vulnirabilities",
    rules,
  };
  const run = {
    tool: { driver },
    results,
    ...(notifications.length === 0
      ? {}
      : {
          invocations: [
            {
              executionSuccessful: false as const,
              toolExecutionNotifications: notifications,
            },
          ] as const,
        }),
  };
  const log: SarifLog = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [run],
  };
  throwIfCancelled(options.signal);
  if (outputByteLength(log) > limits.maximumOutputBytes) {
    throw new SarifExportError(
      "LIMIT_EXCEEDED",
      "SARIF output exceeds the byte safety limit",
    );
  }
  return log;
}

export function exportSarifJson(
  scanResults: readonly SarifScanResult[],
  options: SarifExportOptions = {},
): string {
  const log = buildSarifLog(scanResults, options);
  throwIfCancelled(options.signal);
  return `${JSON.stringify(log, null, 2)}\n`;
}
