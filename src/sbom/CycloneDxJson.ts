import {
  dependencyIsResolved,
  dependencyManifestPath,
  type Dependency,
} from "../models/Dependency";
import type {
  ScanErrorCode,
  ScanResult,
} from "../models/ScanResult";
import type { Severity, Vulnerability } from "../models/Vulnerability";
import {
  canonicalComponentIdentity,
  canonicalComponentIdentityForCoordinate,
  componentBomRef,
  componentCoordinateKey,
  componentDisplayIdentity,
  packageUrlForIdentity,
  safeWorkspaceRelativePath,
  stableSha256,
  type CanonicalComponentIdentity,
} from "./ComponentIdentity";
import {
  CYCLONE_DX_EXPORT_LIMITS,
  SbomExportError,
  type CycloneDxAggregate,
  type CycloneDxBom,
  type CycloneDxComponent,
  type CycloneDxComposition,
  type CycloneDxDependencyRelationship,
  type CycloneDxExportLimits,
  type CycloneDxJsonExportOptions,
  type CycloneDxOccurrence,
  type CycloneDxProperty,
  type CycloneDxVulnerability,
  type SbomScanResult,
} from "./SbomModels";

const RFC3339_UTC =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/u;
const UUID_URN =
  /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const UNSAFE_TOKEN =
  /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const UNSAFE_TEXT =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const MAXIMUM_SOURCE_LINE = 10_000_000;
const MAXIMUM_DEPENDENCY_PATH_SEGMENTS = 256;

const INVENTORY_ERROR_CODES: ReadonlySet<ScanErrorCode> = new Set([
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

const LIMIT_KEYS = [
  "maximumScanResults",
  "maximumDependencies",
  "maximumComponents",
  "maximumOccurrences",
  "maximumRelationships",
  "maximumVulnerabilities",
  "maximumOutputBytes",
] as const satisfies readonly (keyof CycloneDxExportLimits)[];

interface ComponentEntry {
  readonly identity: CanonicalComponentIdentity;
  readonly ref: string;
  readonly purl: string;
  readonly occurrences: Map<string, CycloneDxOccurrence>;
  readonly dependencyTypes: Set<Dependency["dependencyType"]>;
  readonly environments: Set<Dependency["environment"]>;
}

interface PreparedDependency {
  readonly dependency: Dependency;
  readonly coordinate: string;
  readonly ref: string;
}

function throwIfCancelled(signal?: AbortSignal): void {
  if (signal?.aborted === true) {
    throw new SbomExportError("CANCELLED", "CycloneDX export was cancelled");
  }
}

function resolveLimits(
  requested: Partial<CycloneDxExportLimits> | undefined,
): CycloneDxExportLimits {
  const resolved = { ...CYCLONE_DX_EXPORT_LIMITS };
  for (const key of LIMIT_KEYS) {
    const value = requested?.[key];
    if (value === undefined) {
      continue;
    }
    if (
      !Number.isSafeInteger(value) ||
      value < 1 ||
      value > CYCLONE_DX_EXPORT_LIMITS[key]
    ) {
      throw new SbomExportError(
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
    throw new SbomExportError("INVALID_INPUT", `${name} is invalid`);
  }
  return value;
}

function requireText(value: unknown, name: string, maximumLength: number): string {
  if (
    typeof value !== "string" ||
    value.length > maximumLength ||
    UNSAFE_TEXT.test(value)
  ) {
    throw new SbomExportError("INVALID_INPUT", `${name} is invalid`);
  }
  return value;
}

function validateTimestamp(timestamp: string, name = "timestamp"): void {
  const match = RFC3339_UTC.exec(timestamp);
  const parsed = Date.parse(timestamp);
  if (match === null || !Number.isFinite(parsed)) {
    throw new SbomExportError(
      "INVALID_INPUT",
      `${name} must be a valid RFC 3339 UTC value`,
    );
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
    throw new SbomExportError(
      "INVALID_INPUT",
      `${name} must be a valid RFC 3339 UTC value`,
    );
  }
}

function selectedVulnerabilities(result: SbomScanResult): {
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
      throw new SbomExportError(
        "INVALID_INPUT",
        `${property} must be a data property`,
      );
    }
    if (descriptor?.value !== undefined) {
      const value = descriptor.value as unknown;
      if (!Array.isArray(value)) {
        throw new SbomExportError(
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
    throw new SbomExportError(
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
    throw new SbomExportError(
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
    throw new SbomExportError(
      "LIMIT_EXCEEDED",
      "A dependency path exceeds the segment safety limit",
    );
  }
  for (const segment of value) {
    requireToken(segment, "dependency path segment", 512);
  }
  return value;
}

function requireProvenanceValue(
  value: string | undefined,
  name: string,
): string {
  return value === undefined ? "" : requireToken(value, name, 4_096);
}

function dependencyOriginKey(dependency: Dependency): string | undefined {
  const manifestPath = dependencyManifestPath(dependency);
  const lockfilePath = dependency.lockfilePath;
  const projectPath = dependency.projectPath;
  if (manifestPath === undefined && lockfilePath === undefined) {
    return undefined;
  }
  return JSON.stringify([
    requireProvenanceValue(dependency.workspacePath, "workspace path"),
    requireProvenanceValue(projectPath, "project path"),
    requireProvenanceValue(manifestPath, "manifest path"),
    requireProvenanceValue(lockfilePath, "lockfile path"),
    requireProvenanceValue(dependency.packageManager, "package manager"),
  ]);
}

function occurrenceForDependency(
  dependency: Dependency,
  coordinate: string,
  workspaceRoots: readonly string[],
): CycloneDxOccurrence | undefined {
  const location = safeWorkspaceRelativePath(
    dependencyManifestPath(dependency) ?? dependency.lockfilePath,
    workspaceRoots,
  );
  if (location === undefined) {
    return undefined;
  }
  const rawLine = dependency.metadata?.sourceLine;
  let line: number | undefined;
  if (rawLine !== undefined) {
    if (
      typeof rawLine !== "number" ||
      !Number.isSafeInteger(rawLine) ||
      rawLine < 1 ||
      rawLine > MAXIMUM_SOURCE_LINE
    ) {
      throw new SbomExportError(
        "INVALID_INPUT",
        "Dependency sourceLine metadata is invalid",
      );
    }
    line = rawLine;
  }
  const path = dependencyPath(dependency) ?? [];
  const occurrenceIdentity = JSON.stringify([
    coordinate,
    location,
    line ?? 0,
    dependency.dependencyType,
    dependency.environment,
    path,
  ]);
  return {
    "bom-ref": `urn:dependency-auditor:occurrence:sha256:${stableSha256(occurrenceIdentity)}`,
    location,
    ...(line === undefined ? {} : { line }),
  };
}

function componentProperties(entry: ComponentEntry): CycloneDxProperty[] {
  return [
    {
      name: "dependency-auditor:ecosystem",
      value: entry.identity.ecosystem,
    },
    ...[...entry.dependencyTypes]
      .sort()
      .map((value) => ({
        name: "dependency-auditor:dependency-type",
        value,
      })),
    ...[...entry.environments]
      .sort()
      .map((value) => ({
        name: "dependency-auditor:environment",
        value,
      })),
  ];
}

function componentFromEntry(entry: ComponentEntry): CycloneDxComponent {
  const display = componentDisplayIdentity(entry.identity);
  const occurrences = [...entry.occurrences.values()].sort((left, right) =>
    left["bom-ref"].localeCompare(right["bom-ref"], "en"),
  );
  return {
    type: "library",
    "bom-ref": entry.ref,
    ...(display.group === undefined ? {} : { group: display.group }),
    name: display.name,
    version: entry.identity.version,
    purl: entry.purl,
    ...(occurrences.length === 0
      ? {}
      : { evidence: { occurrences } }),
    properties: componentProperties(entry),
  };
}

function severityValue(
  severity: Severity,
): "critical" | "high" | "medium" | "low" | "unknown" {
  return severity.toLowerCase() as
    | "critical"
    | "high"
    | "medium"
    | "low"
    | "unknown";
}

function validHttpsReference(value: string): boolean {
  if (value.length === 0 || value.length > 4_096 || UNSAFE_TOKEN.test(value)) {
    return false;
  }
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.hostname.length > 0 &&
      url.username.length === 0 &&
      url.password.length === 0
    );
  } catch {
    return false;
  }
}

function normalizedVulnerabilityEvidence(vulnerability: Vulnerability): string {
  return JSON.stringify({
    aliases: [...vulnerability.aliases].sort(),
    affectedRange: vulnerability.affectedRange ?? "",
    cvssScore: vulnerability.cvssScore ?? null,
    fixedVersion: vulnerability.fixedVersion ?? "",
    fixedVersionConflict: vulnerability.fixedVersionConflict ?? false,
    fixedVersions: [...(vulnerability.fixedVersions ?? [])].sort(),
    modified: vulnerability.modified ?? "",
    published: vulnerability.published ?? "",
    references: [...vulnerability.references].sort(),
    severity: vulnerability.severity,
    summary: vulnerability.summary,
  });
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
    throw new SbomExportError(
      "INVALID_INPUT",
      "vulnerability severity is invalid",
    );
  }
  if (vulnerability.aliases.length > 256) {
    throw new SbomExportError(
      "LIMIT_EXCEEDED",
      "vulnerability aliases exceed the safety limit",
    );
  }
  for (const alias of vulnerability.aliases) {
    requireToken(alias, "vulnerability alias", 512);
  }
  if (vulnerability.references.length > 512) {
    throw new SbomExportError(
      "LIMIT_EXCEEDED",
      "vulnerability references exceed the safety limit",
    );
  }
  if (!vulnerability.references.every(validHttpsReference)) {
    throw new SbomExportError(
      "INVALID_INPUT",
      "vulnerability references must be credential-free HTTPS URLs",
    );
  }
  if (
    vulnerability.cvssScore !== undefined &&
    (typeof vulnerability.cvssScore !== "number" ||
      !Number.isFinite(vulnerability.cvssScore) ||
      vulnerability.cvssScore < 0 ||
      vulnerability.cvssScore > 10)
  ) {
    throw new SbomExportError("INVALID_INPUT", "CVSS score is invalid");
  }
  if ((vulnerability.fixedVersions?.length ?? 0) > 512) {
    throw new SbomExportError(
      "LIMIT_EXCEEDED",
      "fixed versions exceed the safety limit",
    );
  }
  for (const fixedVersion of vulnerability.fixedVersions ?? []) {
    requireToken(fixedVersion, "fixed version", 256);
  }
  if (vulnerability.fixedVersion !== undefined) {
    requireToken(vulnerability.fixedVersion, "fixed version", 256);
  }
  if (vulnerability.affectedRange !== undefined) {
    requireText(vulnerability.affectedRange, "affected range", 32_768);
  }
  if (vulnerability.published !== undefined) {
    validateTimestamp(vulnerability.published, "vulnerability published");
  }
  if (vulnerability.modified !== undefined) {
    validateTimestamp(vulnerability.modified, "vulnerability modified");
  }
}

function vulnerabilityProperties(
  vulnerability: Vulnerability,
): CycloneDxProperty[] {
  return [
    ...[...new Set(vulnerability.aliases)]
      .sort()
      .map((alias) => ({
        name: "dependency-auditor:alias",
        value: alias,
      })),
    ...(vulnerability.affectedRange === undefined
      ? []
      : [
          {
            name: "dependency-auditor:affected-range",
            value: vulnerability.affectedRange,
          },
        ]),
    ...[...new Set(vulnerability.fixedVersions ?? [])]
      .sort()
      .map((version) => ({
        name: "dependency-auditor:fixed-version",
        value: version,
      })),
    ...(vulnerability.fixedVersionConflict === true
      ? [
          {
            name: "dependency-auditor:fixed-version-conflict",
            value: "true",
          },
        ]
      : []),
  ];
}

function toCycloneDxVulnerability(
  vulnerability: Vulnerability,
  coordinate: string,
  componentRef: string,
): CycloneDxVulnerability {
  const source = { name: vulnerability.source };
  const references = [...new Set(vulnerability.references)].sort();
  const properties = vulnerabilityProperties(vulnerability);
  return {
    "bom-ref": `urn:dependency-auditor:vulnerability:sha256:${stableSha256(
      JSON.stringify([vulnerability.source, vulnerability.id, coordinate]),
    )}`,
    id: vulnerability.id,
    source,
    ratings: [
      {
        source,
        ...(vulnerability.cvssScore === undefined
          ? {}
          : { score: vulnerability.cvssScore }),
        severity: severityValue(vulnerability.severity),
      },
    ],
    description: vulnerability.summary,
    ...(references.length === 0
      ? {}
      : { advisories: references.map((url) => ({ url })) }),
    ...(vulnerability.published === undefined
      ? {}
      : { published: vulnerability.published }),
    ...(vulnerability.modified === undefined
      ? {}
      : { updated: vulnerability.modified }),
    affects: [
      {
        ref: componentRef,
        versions: [
          {
            version: vulnerability.installedVersion,
            status: "affected",
          },
        ],
      },
    ],
    ...(properties.length === 0 ? {} : { properties }),
  };
}

function inventoryAggregate(results: readonly ScanResult[]): CycloneDxAggregate {
  if (results.some((result) => result.cancelled)) {
    return "unknown";
  }
  const coverages = results.flatMap(
    (result) => result.projectCoverage ?? result.ecosystemCoverage ?? [],
  );
  if (coverages.length === 0) {
    return "unknown";
  }
  if (
    results.some((result) =>
      result.errors.some((error) => INVENTORY_ERROR_CODES.has(error.code)),
    ) ||
    coverages.some(
      (coverage) => coverage.unresolved > 0 || coverage.unsupported > 0,
    )
  ) {
    return "incomplete";
  }
  return "complete";
}

function vulnerabilityAggregate(
  results: readonly SbomScanResult[],
  selectedCounts: readonly number[],
): CycloneDxAggregate {
  if (results.some((result) => result.cancelled)) {
    return "unknown";
  }
  const providers = results.flatMap((result) => result.providerResults);
  const eligibleProviders = providers.filter(
    (provider) => provider.dependenciesEligible > 0,
  );
  if (
    (results.some((result) => result.dependenciesScanned > 0) &&
      providers.length === 0) ||
    (eligibleProviders.length > 0 &&
      eligibleProviders.every(
        (provider) =>
          provider.status === "unavailable" ||
          (provider.successful === 0 && provider.failed > 0),
      ))
  ) {
    return "unknown";
  }
  const filteredEvidenceMissing = results.some((result, index) => {
    const providerFindings = result.providerResults.reduce(
      (total, provider) => total + provider.vulnerabilitiesFound,
      0,
    );
    return providerFindings !== (selectedCounts[index] ?? 0);
  });
  const coverageGap = results.some((result) =>
    (result.projectCoverage ?? result.ecosystemCoverage ?? []).some(
      (coverage) => coverage.checked < coverage.resolved,
    ),
  );
  if (
    filteredEvidenceMissing ||
    coverageGap ||
    providers.some((provider) => provider.status !== "available") ||
    results.some((result) =>
      result.errors.some((error) => error.code === "PROVIDER_ERROR"),
    )
  ) {
    return "incomplete";
  }
  return providers.length === 0 ? "unknown" : "complete";
}

function outputByteLength(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

export function buildCycloneDxBom(
  results: readonly SbomScanResult[],
  options: CycloneDxJsonExportOptions,
): CycloneDxBom {
  const limits = resolveLimits(options.limits);
  throwIfCancelled(options.signal);
  if (results.length === 0 || results.length > limits.maximumScanResults) {
    throw new SbomExportError(
      results.length === 0 ? "INVALID_INPUT" : "LIMIT_EXCEEDED",
      "Scan result count is outside the supported safety range",
    );
  }
  validateTimestamp(options.timestamp);
  if (!UUID_URN.test(options.serialNumber)) {
    throw new SbomExportError(
      "INVALID_INPUT",
      "serialNumber must be a canonical lower-case UUID URN",
    );
  }
  if (options.toolVersion !== undefined) {
    requireToken(options.toolVersion, "tool version", 256);
  }
  const workspaceRoots = options.workspaceRoots ?? [];
  if (workspaceRoots.length > 64) {
    throw new SbomExportError(
      "LIMIT_EXCEEDED",
      "Workspace root count exceeds the safety limit",
    );
  }

  const dependencyCount = results.reduce(
    (total, result) => total + result.dependencies.length,
    0,
  );
  if (dependencyCount > limits.maximumDependencies) {
    throw new SbomExportError(
      "LIMIT_EXCEEDED",
      "Dependency input exceeds the CycloneDX export limit",
    );
  }

  const components = new Map<string, ComponentEntry>();
  const preparedDependencies: PreparedDependency[] = [];
  let occurrenceCount = 0;
  for (const result of results) {
    if (!Array.isArray(result.dependencies)) {
      throw new SbomExportError(
        "INVALID_INPUT",
        "dependencies must be an array",
      );
    }
    for (const dependency of result.dependencies) {
      throwIfCancelled(options.signal);
      if (!dependencyIsResolved(dependency)) {
        continue;
      }
      let identity: CanonicalComponentIdentity;
      try {
        identity = canonicalComponentIdentity(dependency);
      } catch (error: unknown) {
        throw new SbomExportError(
          "INVALID_INPUT",
          "A resolved dependency has no safe canonical package identity",
          { cause: error },
        );
      }
      const coordinate = componentCoordinateKey(identity);
      let component = components.get(coordinate);
      if (component === undefined) {
        if (components.size >= limits.maximumComponents) {
          throw new SbomExportError(
            "LIMIT_EXCEEDED",
            "Component count exceeds the CycloneDX export limit",
          );
        }
        component = {
          identity,
          ref: componentBomRef(identity),
          purl: packageUrlForIdentity(identity),
          occurrences: new Map(),
          dependencyTypes: new Set(),
          environments: new Set(),
        };
        components.set(coordinate, component);
      }
      component.dependencyTypes.add(dependency.dependencyType);
      component.environments.add(dependency.environment);
      const occurrence = occurrenceForDependency(
        dependency,
        coordinate,
        workspaceRoots,
      );
      if (
        occurrence !== undefined &&
        !component.occurrences.has(occurrence["bom-ref"])
      ) {
        occurrenceCount += 1;
        if (occurrenceCount > limits.maximumOccurrences) {
          throw new SbomExportError(
            "LIMIT_EXCEEDED",
            "Occurrence count exceeds the CycloneDX export limit",
          );
        }
        component.occurrences.set(occurrence["bom-ref"], occurrence);
      }
      preparedDependencies.push({
        dependency,
        coordinate,
        ref: component.ref,
      });
    }
  }

  const pathOwners = new Map<string, Set<string>>();
  for (const prepared of preparedDependencies) {
    throwIfCancelled(options.signal);
    const origin = dependencyOriginKey(prepared.dependency);
    const path = dependencyPath(prepared.dependency);
    if (origin === undefined || path === undefined || path.length === 0) {
      continue;
    }
    const key = JSON.stringify([origin, path]);
    const owners = pathOwners.get(key) ?? new Set<string>();
    owners.add(prepared.coordinate);
    pathOwners.set(key, owners);
  }

  const edges = new Map<string, Set<string>>();
  let relationshipCount = 0;
  for (const prepared of preparedDependencies) {
    throwIfCancelled(options.signal);
    const origin = dependencyOriginKey(prepared.dependency);
    const path = dependencyPath(prepared.dependency);
    if (origin === undefined || path === undefined || path.length < 2) {
      continue;
    }
    const parentCoordinates = pathOwners.get(
      JSON.stringify([origin, path.slice(0, -1)]),
    );
    if (parentCoordinates?.size !== 1) {
      continue;
    }
    const parentCoordinate = parentCoordinates.values().next().value as
      | string
      | undefined;
    const parent =
      parentCoordinate === undefined
        ? undefined
        : components.get(parentCoordinate);
    if (parent === undefined || parent.ref === prepared.ref) {
      continue;
    }
    const children = edges.get(parent.ref) ?? new Set<string>();
    if (!children.has(prepared.ref)) {
      relationshipCount += 1;
      if (relationshipCount > limits.maximumRelationships) {
        throw new SbomExportError(
          "LIMIT_EXCEEDED",
          "Relationship count exceeds the CycloneDX export limit",
        );
      }
      children.add(prepared.ref);
      edges.set(parent.ref, children);
    }
  }

  const selectedCounts: number[] = [];
  const unfilteredAvailable: boolean[] = [];
  const normalizedVulnerabilities = new Map<
    string,
    { readonly evidence: string; readonly value: CycloneDxVulnerability }
  >();
  let vulnerabilityInputCount = 0;
  for (const result of results) {
    const selected = selectedVulnerabilities(result);
    selectedCounts.push(selected.vulnerabilities.length);
    unfilteredAvailable.push(selected.unfilteredAvailable);
    vulnerabilityInputCount += selected.vulnerabilities.length;
    if (vulnerabilityInputCount > limits.maximumVulnerabilities) {
      throw new SbomExportError(
        "LIMIT_EXCEEDED",
        "Vulnerability input exceeds the CycloneDX export limit",
      );
    }
    for (const vulnerability of selected.vulnerabilities) {
      throwIfCancelled(options.signal);
      validateVulnerability(vulnerability);
      let identity: CanonicalComponentIdentity;
      try {
        identity = canonicalComponentIdentityForCoordinate(
          vulnerability.ecosystem,
          vulnerability.packageName,
          vulnerability.installedVersion,
        );
      } catch (error: unknown) {
        throw new SbomExportError(
          "INVALID_INPUT",
          "A vulnerability has no safe canonical package identity",
          { cause: error },
        );
      }
      const coordinate = componentCoordinateKey(identity);
      const component = components.get(coordinate);
      if (component === undefined) {
        throw new SbomExportError(
          "INVALID_INPUT",
          "A vulnerability does not match a resolved dependency component",
        );
      }
      const key = JSON.stringify([
        vulnerability.source,
        vulnerability.id,
        coordinate,
      ]);
      const evidence = normalizedVulnerabilityEvidence(vulnerability);
      const existing = normalizedVulnerabilities.get(key);
      if (existing !== undefined) {
        if (existing.evidence !== evidence) {
          throw new SbomExportError(
            "INVALID_INPUT",
            "Conflicting vulnerability evidence cannot be merged silently",
          );
        }
        continue;
      }
      normalizedVulnerabilities.set(key, {
        evidence,
        value: toCycloneDxVulnerability(
          vulnerability,
          coordinate,
          component.ref,
        ),
      });
    }
  }

  const componentValues = [...components.values()]
    .map(componentFromEntry)
    .sort((left, right) => left["bom-ref"].localeCompare(right["bom-ref"], "en"));
  const dependencyRelationships: CycloneDxDependencyRelationship[] =
    componentValues.map((component) => {
      const dependsOn = [...(edges.get(component["bom-ref"]) ?? [])].sort();
      return {
        ref: component["bom-ref"],
        ...(dependsOn.length === 0 ? {} : { dependsOn }),
      };
    });
  const vulnerabilityValues = [...normalizedVulnerabilities.values()]
    .map((entry) => entry.value)
    .sort((left, right) => left["bom-ref"].localeCompare(right["bom-ref"], "en"));
  const compositions: CycloneDxComposition[] = [
    {
      "bom-ref": "dependency-auditor:composition:dependencies",
      aggregate: inventoryAggregate(results),
      dependencies: componentValues.map((component) => component["bom-ref"]),
    },
    {
      "bom-ref": "dependency-auditor:composition:vulnerabilities",
      aggregate: vulnerabilityAggregate(results, selectedCounts),
      vulnerabilities: vulnerabilityValues.map(
        (vulnerability) => vulnerability["bom-ref"],
      ),
    },
  ];
  const tool = {
    type: "application" as const,
    name: "Dependency Vulnerability Auditor" as const,
    ...(options.toolVersion === undefined
      ? {}
      : { version: options.toolVersion }),
  };
  const bom: CycloneDxBom = {
    $schema: "https://cyclonedx.org/schema/bom-1.6.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: options.serialNumber,
    version: 1,
    metadata: {
      timestamp: options.timestamp,
      lifecycles: [{ phase: "pre-build" }],
      tools: { components: [tool] },
    },
    components: componentValues,
    dependencies: dependencyRelationships,
    vulnerabilities: vulnerabilityValues,
    compositions,
  };
  throwIfCancelled(options.signal);
  if (outputByteLength(bom) > limits.maximumOutputBytes) {
    throw new SbomExportError(
      "LIMIT_EXCEEDED",
      "CycloneDX output exceeds the byte safety limit",
    );
  }
  return bom;
}

export function exportCycloneDxJson(
  results: readonly SbomScanResult[],
  options: CycloneDxJsonExportOptions,
): string {
  const bom = buildCycloneDxBom(results, options);
  throwIfCancelled(options.signal);
  return `${JSON.stringify(bom, null, 2)}\n`;
}
