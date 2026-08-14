import {
  boundedEvidenceText,
  boundedOpaqueId,
  boundedPositiveLimit,
  compareText,
  freezeStrings,
  isAnalysisCancelled,
} from "../evidence/EvidenceControls";

export type ProvenanceStatus = "SAFE" | "KNOWN" | "SUSPICIOUS" | "UNKNOWN";
export type ProvenanceConfidence = "HIGH" | "MEDIUM" | "LOW";
export type PackageSourceKind = "registry" | "git" | "local" | "url" | "unknown";
export type IntegrityVerification = "verified" | "mismatch" | "unverified";

export type SupplyChainSignal =
  | "PACKAGE_NAME_MISMATCH"
  | "REPOSITORY_MISMATCH"
  | "UNEXPECTED_REGISTRY"
  | "UNUSUAL_SOURCE"
  | "GIT_REPLACES_REGISTRY"
  | "LOCAL_PATH_DEPENDENCY"
  | "INTEGRITY_MISMATCH"
  | "INVALID_INTEGRITY_EVIDENCE"
  | "UNSIGNED_OR_UNVERIFIABLE"
  | "MAINTAINER_CHANGE"
  | "REPOSITORY_CHANGE"
  | "SOURCE_URL_CHANGE"
  | "TYPOSQUATTING_PATTERN"
  | "NEW_PACKAGE"
  | "MAJOR_VERSION_JUMP"
  | "DEPENDENCY_EXPLOSION"
  | "INSTALL_SCRIPT_PRESENT"
  | "SUSPICIOUS_EXTERNAL_URL"
  | "INTEGRITY_CHANGE";

export interface PreviousPackageMetadata {
  readonly repository?: string;
  readonly sourceUrl?: string;
  readonly integrity?: string;
  readonly maintainers?: readonly string[];
  readonly version?: string;
  readonly dependencyCount?: number;
}

export interface PackageProvenanceInput {
  readonly dependencyId: string;
  readonly packageName: string;
  readonly metadataPackageName?: string;
  readonly ecosystem: string;
  readonly version: string;
  readonly packageUrl?: string;
  readonly sourceKind?: PackageSourceKind;
  readonly registry?: string;
  readonly repository?: string;
  readonly expectedRepository?: string;
  readonly homepage?: string;
  readonly sourceUrl?: string;
  readonly resolvedUrl?: string;
  readonly downloadSource?: string;
  readonly lockfileSource?: string;
  readonly integrity?: string;
  /** Verification is explicit caller evidence; this analyzer never reads package bytes. */
  readonly integrityVerification?: IntegrityVerification;
  readonly signatureStatus?: "signed" | "unsigned" | "unverifiable" | "unknown";
  readonly publisher?: string;
  readonly maintainers?: readonly string[];
  readonly registryPackageExpected?: boolean;
  readonly publishedAgeDays?: number;
  readonly dependencyCount?: number;
  readonly hasInstallScript?: boolean;
  readonly previous?: PreviousPackageMetadata;
}

export interface SupplyChainAnomaly {
  readonly signal: SupplyChainSignal;
  readonly evidence: string;
  readonly confidence: ProvenanceConfidence;
  readonly limitations: readonly string[];
  /** An anomaly is investigation evidence, never a vulnerability/malware verdict. */
  readonly securityVerdict: "NOT_ESTABLISHED";
}

export interface PackageProvenanceEvidence {
  readonly dependencyId: string;
  readonly packageName: string;
  readonly ecosystem: string;
  readonly version: string;
  readonly status: ProvenanceStatus;
  readonly sourceKind: PackageSourceKind;
  readonly registryOrigin?: string;
  readonly registryCanonical: boolean;
  readonly integrityState: "VERIFIED" | "DECLARED" | "MISMATCH" | "UNKNOWN";
  readonly explicitFields: readonly string[];
  readonly anomalies: readonly SupplyChainAnomaly[];
  readonly anomaliesObserved?: number;
  readonly anomaliesTruncated?: boolean;
  readonly limitations: readonly string[];
  readonly malicious: "NOT_DETERMINED";
}

export interface ProvenanceCoverage {
  readonly totalRecords: number;
  readonly processedRecords: number;
  readonly omittedRecords: number;
  readonly safeRecords: number;
  readonly knownRecords: number;
  readonly suspiciousRecords: number;
  readonly unknownRecords: number;
  readonly anomaliesObserved?: number;
  readonly anomaliesEmitted?: number;
  readonly anomaliesOmitted?: number;
  readonly truncated: boolean;
  readonly cancelled: boolean;
  readonly analysisComplete: boolean;
}

export interface ProvenanceAnalysisResult {
  readonly packages: readonly PackageProvenanceEvidence[];
  readonly anomalies: readonly SupplyChainAnomaly[];
  readonly coverage: ProvenanceCoverage;
}

export interface ProvenanceAnalysisOptions {
  readonly expectedRegistries?: Readonly<Record<string, readonly string[]>>;
  readonly allowedSourceOrigins?: Readonly<Record<string, readonly string[]>>;
  readonly protectedPackageNames?: readonly string[];
  readonly maximumRecords?: number;
  readonly maximumAnomalies?: number;
  readonly maximumProtectedNames?: number;
  readonly newPackageMaximumAgeDays?: number;
  readonly signal?: AbortSignal;
}

const HARD_MAXIMUM_RECORDS = 100_000;
const HARD_MAXIMUM_ANOMALIES = 100_000;
const HARD_MAXIMUM_PROTECTED_NAMES = 10_000;
const MAXIMUM_IDENTITY = 256;
const MAXIMUM_URL = 2_048;
const MAXIMUM_MAINTAINERS = 128;

const CANONICAL_REGISTRIES: Readonly<Record<string, readonly string[]>> =
  Object.freeze({
    npm: Object.freeze(["https://registry.npmjs.org"]),
    pypi: Object.freeze(["https://pypi.org"]),
    maven: Object.freeze(["https://repo.maven.apache.org"]),
    nuget: Object.freeze(["https://api.nuget.org"]),
    crates: Object.freeze(["https://crates.io"]),
    cargo: Object.freeze(["https://crates.io"]),
    go: Object.freeze(["https://proxy.golang.org"]),
    packagist: Object.freeze(["https://repo.packagist.org"]),
    composer: Object.freeze(["https://repo.packagist.org"]),
  });

interface SafeUrl {
  readonly origin: string;
  readonly identity: string;
}

function safeHttpsUrl(value: unknown): SafeUrl | undefined {
  const text = boundedEvidenceText(value, MAXIMUM_URL);
  if (text === undefined) {
    return undefined;
  }
  try {
    const parsed = new URL(text.startsWith("git+https://") ? text.slice(4) : text);
    if (
      parsed.protocol !== "https:" ||
      parsed.username.length > 0 ||
      parsed.password.length > 0
    ) {
      return undefined;
    }
    const pathname = parsed.pathname.replace(/\/+$/u, "");
    return {
      origin: parsed.origin.toLowerCase(),
      identity: `${parsed.origin.toLowerCase()}${pathname.toLowerCase()}`,
    };
  } catch {
    return undefined;
  }
}

function ecosystemKey(value: unknown): string {
  return (boundedEvidenceText(value, MAXIMUM_IDENTITY) ?? "unknown").toLowerCase();
}

function configuredOrigins(
  ecosystem: string,
  configured: Readonly<Record<string, readonly string[]>> | undefined,
  fallback: Readonly<Record<string, readonly string[]>>,
): readonly string[] {
  const raw =
    typeof configured === "object" &&
    configured !== null &&
    Object.prototype.hasOwnProperty.call(configured, ecosystem)
      ? configured[ecosystem]
      : fallback[ecosystem];
  const origins = new Set<string>();
  for (const value of Array.isArray(raw) ? raw.slice(0, 32) : []) {
    const parsed = safeHttpsUrl(value);
    if (parsed !== undefined) {
      origins.add(parsed.origin);
    }
  }
  return Object.freeze([...origins].sort(compareText));
}

function validIntegrity(value: unknown): boolean {
  const text = boundedEvidenceText(value, 1_024);
  if (text === undefined) {
    return false;
  }
  if (/^(?:sha256:[a-fA-F0-9]{64}|sha512:[a-fA-F0-9]{128})$/u.test(text)) {
    return true;
  }
  const tokens = text.split(/\s+/u);
  if (tokens.length === 0 || tokens.length > 8) {
    return false;
  }
  return tokens.every((token) => {
    const match = /^(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})$/u.exec(token);
    if (match === null) {
      return false;
    }
    const expected = match[1] === "sha256" ? 44 : match[1] === "sha384" ? 64 : 88;
    return match[2]?.length === expected;
  });
}

function safeIdentity(value: unknown): string {
  return boundedOpaqueId(value, MAXIMUM_IDENTITY) ?? "UNKNOWN";
}

function normalizedNames(values: readonly string[] | undefined): readonly string[] {
  const names = new Set<string>();
  for (const value of values?.slice(0, MAXIMUM_MAINTAINERS) ?? []) {
    const safe = boundedEvidenceText(value, MAXIMUM_IDENTITY);
    if (safe !== undefined) {
      names.add(safe.toLowerCase());
    }
  }
  return Object.freeze([...names].sort(compareText));
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function packageLeaf(value: string): string {
  const slash = value.lastIndexOf("/");
  return (slash >= 0 ? value.slice(slash + 1) : value).toLowerCase();
}

function editDistanceAtMostOne(left: string, right: string): boolean {
  if (left === right || Math.abs(left.length - right.length) > 1) {
    return false;
  }
  let leftIndex = 0;
  let rightIndex = 0;
  let edits = 0;
  while (leftIndex < left.length && rightIndex < right.length) {
    if (left[leftIndex] === right[rightIndex]) {
      leftIndex += 1;
      rightIndex += 1;
      continue;
    }
    edits += 1;
    if (edits > 1) {
      return false;
    }
    if (left.length > right.length) {
      leftIndex += 1;
    } else if (right.length > left.length) {
      rightIndex += 1;
    } else {
      leftIndex += 1;
      rightIndex += 1;
    }
  }
  edits += left.length - leftIndex + (right.length - rightIndex);
  return edits === 1;
}

function majorVersion(value: unknown): number | undefined {
  const text = boundedEvidenceText(value, 128);
  const match = text === undefined ? null : /^(?:v)?(\d+)\./u.exec(text);
  if (match?.[1] === undefined) {
    return undefined;
  }
  const major = Number(match[1]);
  return Number.isSafeInteger(major) ? major : undefined;
}

function anomaly(
  signal: SupplyChainSignal,
  evidence: string,
  confidence: ProvenanceConfidence,
  limitation: string,
): SupplyChainAnomaly {
  return Object.freeze({
    signal,
    evidence,
    confidence,
    limitations: freezeStrings([limitation]),
    securityVerdict: "NOT_ESTABLISHED",
  });
}

function addUrlSignal(
  anomalies: SupplyChainAnomaly[],
  value: unknown,
  label: string,
  allowedOrigins: readonly string[],
): void {
  if (value === undefined) {
    return;
  }
  const parsed = safeHttpsUrl(value);
  if (parsed === undefined || (allowedOrigins.length > 0 && !allowedOrigins.includes(parsed.origin))) {
    anomalies.push(
      anomaly(
        "SUSPICIOUS_EXTERNAL_URL",
        `${label} metadata is non-HTTPS, credential-bearing, invalid, or outside the configured origin allowlist.`,
        "MEDIUM",
        "URL metadata was inspected but never contacted; an unusual URL is not proof of malicious behavior.",
      ),
    );
  }
}

function analyzePackage(
  input: PackageProvenanceInput,
  options: ProvenanceAnalysisOptions,
  protectedNames: readonly string[],
  maximumAnomalies: number,
): PackageProvenanceEvidence {
  const ecosystem = ecosystemKey(input.ecosystem);
  const packageName = safeIdentity(input.packageName);
  const sourceKind: PackageSourceKind =
    input.sourceKind === "registry" ||
    input.sourceKind === "git" ||
    input.sourceKind === "local" ||
    input.sourceKind === "url" ||
    input.sourceKind === "unknown"
      ? input.sourceKind
      : "unknown";
  const canonicalOrigins = configuredOrigins(
    ecosystem,
    undefined,
    CANONICAL_REGISTRIES,
  );
  const expectedOrigins = configuredOrigins(ecosystem, options.expectedRegistries, CANONICAL_REGISTRIES);
  const sourceOrigins = configuredOrigins(ecosystem, options.allowedSourceOrigins, Object.freeze({}));
  const registry = safeHttpsUrl(input.registry);
  const registryCanonical = registry !== undefined && canonicalOrigins.includes(registry.origin);
  const registryExpected = registry !== undefined && expectedOrigins.includes(registry.origin);
  const integrityValid = validIntegrity(input.integrity);
  const integrityState =
    input.integrityVerification === "mismatch"
      ? "MISMATCH"
      : input.integrityVerification === "verified" && integrityValid
        ? "VERIFIED"
        : integrityValid
          ? "DECLARED"
          : "UNKNOWN";
  const anomalies: SupplyChainAnomaly[] = [];
  const metadataName = boundedEvidenceText(input.metadataPackageName, MAXIMUM_IDENTITY);
  if (metadataName !== undefined && metadataName !== packageName) {
    anomalies.push(anomaly("PACKAGE_NAME_MISMATCH", "Dependency identity and package metadata name differ.", "HIGH", "Aliases and ecosystem normalization can cause legitimate name differences."));
  }
  if (registry !== undefined && expectedOrigins.length > 0 && !registryExpected) {
    anomalies.push(anomaly("UNEXPECTED_REGISTRY", "Registry origin does not match the canonical/configured registry for this ecosystem.", "HIGH", "Private or mirrored registries can be legitimate and require local policy context."));
  } else if (input.registry !== undefined && registry === undefined) {
    anomalies.push(anomaly("SUSPICIOUS_EXTERNAL_URL", "Registry metadata is non-HTTPS, credential-bearing, or invalid.", "HIGH", "The URL was parsed locally and was never contacted."));
  }
  if (input.sourceKind !== undefined && sourceKind === "unknown" && input.sourceKind !== "unknown") {
    anomalies.push(anomaly("UNUSUAL_SOURCE", "Dependency source-kind metadata is unsupported.", "MEDIUM", "Unsupported source metadata may require an ecosystem-specific normalizer."));
  }
  if (sourceKind === "local") {
    anomalies.push(anomaly("LOCAL_PATH_DEPENDENCY", "Dependency metadata explicitly identifies a local path source.", "HIGH", "Local dependencies may be intentional; package contents were not inspected."));
  } else if (sourceKind === "git" && input.registryPackageExpected === true) {
    anomalies.push(anomaly("GIT_REPLACES_REGISTRY", "A Git source replaces a dependency expected from a registry.", "HIGH", "Git dependencies may be intentional; repository contents were not downloaded or executed."));
  } else if (sourceKind === "git" || sourceKind === "url") {
    anomalies.push(anomaly("UNUSUAL_SOURCE", `Dependency uses an explicit ${sourceKind} source instead of a proven canonical registry artifact.`, "MEDIUM", "Non-registry sources are not inherently unsafe."));
  }
  if (input.integrityVerification === "mismatch") {
    anomalies.push(anomaly("INTEGRITY_MISMATCH", "Caller-supplied integrity verification reports a mismatch.", "HIGH", "The analyzer did not read package bytes and relies on explicit verification evidence."));
  } else if (input.integrityVerification === "verified" && !integrityValid) {
    anomalies.push(anomaly("INVALID_INTEGRITY_EVIDENCE", "Integrity is marked verified but the declared digest syntax is unsupported or invalid.", "HIGH", "Unsupported integrity formats may require an ecosystem-specific verifier."));
  }
  if (input.signatureStatus === "unsigned" || input.signatureStatus === "unverifiable") {
    anomalies.push(anomaly("UNSIGNED_OR_UNVERIFIABLE", `Package signature metadata is explicitly ${input.signatureStatus}.`, "MEDIUM", "Signature availability and requirements vary by ecosystem."));
  }
  const repository = safeHttpsUrl(input.repository);
  const expectedRepository = safeHttpsUrl(input.expectedRepository);
  if (expectedRepository !== undefined && (repository === undefined || repository.identity !== expectedRepository.identity)) {
    anomalies.push(anomaly("REPOSITORY_MISMATCH", "Observed repository metadata does not match explicit expected repository metadata.", "MEDIUM", "Repository migrations and mirrors can be legitimate."));
  }
  const previousRepository = safeHttpsUrl(input.previous?.repository);
  if (repository !== undefined && previousRepository !== undefined && repository.identity !== previousRepository.identity) {
    anomalies.push(anomaly("REPOSITORY_CHANGE", "Repository identity changed from the supplied previous metadata.", "MEDIUM", "No provider history was fetched; caller-supplied snapshots define the comparison."));
  }
  const sourceUrl = safeHttpsUrl(input.sourceUrl);
  const previousSourceUrl = safeHttpsUrl(input.previous?.sourceUrl);
  if (sourceUrl !== undefined && previousSourceUrl !== undefined && sourceUrl.identity !== previousSourceUrl.identity) {
    anomalies.push(anomaly("SOURCE_URL_CHANGE", "Source URL identity changed from the supplied previous metadata.", "MEDIUM", "Source hosting changes can be legitimate."));
  }
  const maintainers = normalizedNames(input.maintainers);
  const previousMaintainers = normalizedNames(input.previous?.maintainers);
  if (maintainers.length > 0 && previousMaintainers.length > 0 && !sameStrings(maintainers, previousMaintainers)) {
    anomalies.push(anomaly("MAINTAINER_CHANGE", "The bounded maintainer set differs from supplied previous metadata.", "LOW", "Maintainer transitions are not malicious by themselves and provider history was not fetched."));
  }
  if (integrityValid && validIntegrity(input.previous?.integrity) && input.integrity !== input.previous?.integrity) {
    anomalies.push(anomaly("INTEGRITY_CHANGE", "Integrity metadata changed from the supplied previous record.", "MEDIUM", "A digest normally changes with package bytes or version; version context must be reviewed."));
  }
  const leaf = packageLeaf(packageName);
  if (leaf.length >= 4 && protectedNames.some((candidate) => editDistanceAtMostOne(leaf, packageLeaf(candidate)))) {
    anomalies.push(anomaly("TYPOSQUATTING_PATTERN", "Package name is one edit away from a caller-supplied protected package name.", "LOW", "String similarity alone is weak evidence and never establishes intent."));
  }
  const maximumAge = boundedPositiveLimit(options.newPackageMaximumAgeDays, 14, 365);
  if (typeof input.publishedAgeDays === "number" && Number.isFinite(input.publishedAgeDays) && input.publishedAgeDays >= 0 && input.publishedAgeDays <= maximumAge) {
    anomalies.push(anomaly("NEW_PACKAGE", "Caller-supplied publication age is within the configured new-package window.", "LOW", "New packages are not inherently unsafe and publication time was not independently verified."));
  }
  const previousMajor = majorVersion(input.previous?.version);
  const currentMajor = majorVersion(input.version);
  if (previousMajor !== undefined && currentMajor !== undefined && currentMajor > previousMajor + 1) {
    anomalies.push(anomaly("MAJOR_VERSION_JUMP", "Package version increased by more than one major version from supplied previous metadata.", "LOW", "Versioning conventions vary and a major jump is not a security finding."));
  }
  if (
    typeof input.dependencyCount === "number" &&
    Number.isSafeInteger(input.dependencyCount) &&
    input.dependencyCount >= 0 &&
    typeof input.previous?.dependencyCount === "number" &&
    Number.isSafeInteger(input.previous.dependencyCount) &&
    input.previous.dependencyCount >= 0 &&
    input.dependencyCount > Math.max(input.previous.dependencyCount * 2, input.previous.dependencyCount + 20)
  ) {
    anomalies.push(anomaly("DEPENDENCY_EXPLOSION", "Declared dependency count more than doubled and increased by over twenty from supplied previous metadata.", "LOW", "Graph changes may be legitimate and dependency contents were not inspected."));
  }
  if (input.hasInstallScript === true) {
    anomalies.push(anomaly("INSTALL_SCRIPT_PRESENT", "Metadata reports at least one install-time script.", "LOW", "The script was not read or executed; install scripts are common and not inherently unsafe."));
  }
  addUrlSignal(anomalies, input.homepage, "Homepage", sourceOrigins);
  addUrlSignal(anomalies, input.sourceUrl, "Source URL", sourceOrigins);
  addUrlSignal(anomalies, input.resolvedUrl, "Resolved URL", sourceOrigins);
  addUrlSignal(anomalies, input.downloadSource, "Download source", sourceOrigins);
  const uniqueAnomalies = [...new Map(anomalies.map((item) => [item.signal, item])).values()].sort((left, right) => compareText(left.signal, right.signal));
  const emittedAnomalies = uniqueAnomalies.slice(0, maximumAnomalies);
  const explicitFields = [
    ["registry", input.registry], ["repository", input.repository], ["homepage", input.homepage],
    ["sourceUrl", input.sourceUrl], ["resolvedUrl", input.resolvedUrl], ["downloadSource", input.downloadSource],
    ["lockfileSource", input.lockfileSource], ["packageUrl", input.packageUrl], ["integrity", input.integrity],
    ["publisher", input.publisher], ["maintainers", input.maintainers?.length],
  ].filter((entry) => entry[1] !== undefined).map((entry) => String(entry[0])).sort(compareText);
  const limitations = ["Provenance is based only on bounded caller-supplied metadata; no registry, repository, URL, signature, or package content was contacted or executed."];
  if (integrityState !== "VERIFIED") {
    limitations.push("Artifact integrity was not proven by valid explicit verification evidence.");
  }
  if (canonicalOrigins.length === 0) {
    limitations.push("No canonical/configured registry origin is known for this ecosystem.");
  }
  const status: ProvenanceStatus =
    uniqueAnomalies.length > 0
      ? "SUSPICIOUS"
      : sourceKind === "registry" && registryCanonical && integrityState === "VERIFIED"
        ? "SAFE"
        : explicitFields.length > 0 || sourceKind !== "unknown"
          ? "KNOWN"
          : "UNKNOWN";
  return Object.freeze({
    dependencyId: safeIdentity(input.dependencyId), packageName, ecosystem: safeIdentity(input.ecosystem),
    version: safeIdentity(input.version), status, sourceKind,
    ...(registry === undefined ? {} : { registryOrigin: registry.origin }),
    registryCanonical, integrityState, explicitFields: freezeStrings(explicitFields),
    anomalies: Object.freeze(emittedAnomalies),
    anomaliesObserved: uniqueAnomalies.length,
    anomaliesTruncated: emittedAnomalies.length < uniqueAnomalies.length,
    limitations: freezeStrings(limitations), malicious: "NOT_DETERMINED",
  });
}

export function analyzeProvenance(
  inputs: readonly PackageProvenanceInput[],
  options: ProvenanceAnalysisOptions = {},
): ProvenanceAnalysisResult {
  const maximumRecords = boundedPositiveLimit(options.maximumRecords, 10_000, HARD_MAXIMUM_RECORDS);
  const maximumAnomalies = boundedPositiveLimit(options.maximumAnomalies, 20_000, HARD_MAXIMUM_ANOMALIES);
  const protectedLimit = boundedPositiveLimit(options.maximumProtectedNames, 1_000, HARD_MAXIMUM_PROTECTED_NAMES);
  const protectedNames = (Array.isArray(options.protectedPackageNames) ? options.protectedPackageNames : []).slice(0, protectedLimit)
    .map((value) => boundedEvidenceText(value, MAXIMUM_IDENTITY))
    .filter((value): value is string => value !== undefined)
    .sort(compareText);
  const packages: PackageProvenanceEvidence[] = [];
  let remainingAnomalies = maximumAnomalies;
  let cancelled = isAnalysisCancelled(options.signal);
  for (let index = 0; !cancelled && index < Math.min(inputs.length, maximumRecords); index += 1) {
    const input = inputs[index];
    if (input !== undefined) {
      const evidence = analyzePackage(
        input,
        options,
        protectedNames,
        remainingAnomalies,
      );
      packages.push(evidence);
      remainingAnomalies = Math.max(
        0,
        remainingAnomalies - evidence.anomalies.length,
      );
    }
    cancelled = isAnalysisCancelled(options.signal);
  }
  packages.sort((left, right) => compareText(JSON.stringify([left.ecosystem, left.packageName, left.version, left.dependencyId]), JSON.stringify([right.ecosystem, right.packageName, right.version, right.dependencyId])));
  const allAnomalies = packages.flatMap((item) => item.anomalies);
  const anomaliesObserved = packages.reduce(
    (total, item) => total + (item.anomaliesObserved ?? item.anomalies.length),
    0,
  );
  const anomalies = allAnomalies;
  const truncated =
    (inputs.length > packages.length && !cancelled) ||
    anomaliesObserved > anomalies.length;
  const count = (status: ProvenanceStatus): number => packages.filter((item) => item.status === status).length;
  const coverage = Object.freeze({
    totalRecords: inputs.length, processedRecords: packages.length, omittedRecords: inputs.length - packages.length,
    safeRecords: count("SAFE"), knownRecords: count("KNOWN"), suspiciousRecords: count("SUSPICIOUS"), unknownRecords: count("UNKNOWN"),
    anomaliesObserved,
    anomaliesEmitted: anomalies.length,
    anomaliesOmitted: anomaliesObserved - anomalies.length,
    truncated, cancelled, analysisComplete: !truncated && !cancelled,
  });
  return Object.freeze({ packages: Object.freeze(packages), anomalies: Object.freeze(anomalies), coverage });
}
