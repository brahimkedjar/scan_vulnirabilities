import {
  dependencyManifestPath,
  type Dependency,
} from "../../models/Dependency";
import {
  scanResultKnownVulnerabilities,
  type ScanResult,
} from "../../models/ScanResult";
import type { Vulnerability } from "../../models/Vulnerability";
import type { SecurityGateResult } from "../../policy";
import { safeWorkspaceRelativePath } from "../../sbom/ComponentIdentity";
import { classifyScanCoverage } from "../../services/ScanResultStore";
import { canonicalJson, type JsonValue } from "../security/BoundedJson";

export type SecurityReportFormat = "json" | "html" | "markdown" | "csv";

export interface SecurityReportLicenseEvidence {
  readonly ecosystem: string;
  readonly packageName: string;
  readonly version: string;
  readonly expression?: string;
  readonly status: "ALLOWED" | "DENIED" | "REVIEW_REQUIRED" | "UNKNOWN";
  readonly evidenceSource?: string;
}

export interface SecurityReportProvenanceEvidence {
  readonly ecosystem: string;
  readonly packageName: string;
  readonly version: string;
  readonly status: "SAFE" | "KNOWN" | "SUSPICIOUS" | "UNKNOWN";
  readonly evidence: readonly string[];
  readonly limitations: readonly string[];
}

export interface SecurityReportReachabilityEvidence {
  readonly ecosystem: string;
  readonly packageName: string;
  readonly version: string;
  readonly status: "REACHABLE" | "NOT_OBSERVED" | "UNKNOWN";
  readonly confidence: "HIGH" | "MEDIUM" | "LOW";
  readonly path?: readonly string[];
  readonly limitations: readonly string[];
}

export interface SecurityReportAnomalyEvidence {
  readonly ecosystem: string;
  readonly packageName: string;
  readonly version: string;
  readonly signal: string;
  readonly confidence: "HIGH" | "MEDIUM" | "LOW";
  readonly evidence: readonly string[];
  readonly limitations: readonly string[];
}

export interface SecurityReportKnownExploitationEvidence {
  readonly advisoryId: string;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly installedVersion: string;
  readonly status:
    | "known-exploited"
    | "not-known-exploited"
    | "unknown";
  readonly source: string;
}

export interface SecurityReportRemediationEvidence {
  readonly advisoryId: string;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly installedVersion: string;
  readonly strategy: "UPGRADE_DIRECT" | "UPGRADE_PARENT" | "MANUAL_REVIEW" | "NO_KNOWN_FIX";
  readonly recommendedVersion?: string;
  readonly reason: string;
  readonly risk: "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";
}

export interface SecurityReportDiffEvidence {
  readonly status: "COMPLETE" | "INCOMPLETE";
  readonly addedDependencies: number;
  readonly removedDependencies: number;
  readonly changedDependencies: number;
  readonly newVulnerabilities: number;
  readonly resolvedVulnerabilities: number;
  readonly unknownAbsences: number;
}

export interface SecurityReportOptions {
  readonly generatedAt: string;
  readonly toolVersion: string;
  readonly workspaceRoots?: readonly string[];
  readonly title?: string;
  readonly policy?: SecurityGateResult;
  readonly licenses?: readonly SecurityReportLicenseEvidence[];
  readonly provenance?: readonly SecurityReportProvenanceEvidence[];
  readonly reachability?: readonly SecurityReportReachabilityEvidence[];
  readonly anomalies?: readonly SecurityReportAnomalyEvidence[];
  readonly knownExploitation?: readonly SecurityReportKnownExploitationEvidence[];
  readonly remediation?: readonly SecurityReportRemediationEvidence[];
  readonly diff?: SecurityReportDiffEvidence;
  readonly signal?: AbortSignal;
  readonly maximumDependencies?: number;
  readonly maximumFindings?: number;
  readonly maximumEvidenceRecords?: number;
  readonly maximumOutputBytes?: number;
}

export interface SecurityReportSummary {
  readonly dependencies: number;
  readonly findings: number;
  readonly critical: number;
  readonly high: number;
  readonly kev: number;
  readonly kevCoverage: "complete" | "unknown";
  readonly reachable: number;
  readonly deniedLicenses: number;
  readonly suspiciousProvenance: number;
  readonly anomalies: number;
  readonly coverage: "complete" | "incomplete";
}

interface SecurityReportDependency {
  readonly ecosystem: string;
  readonly name: string;
  readonly version: string;
  readonly dependencyType: string;
  readonly environment: string;
  readonly packageManager?: string;
  readonly location?: string;
}

interface SecurityReportFinding {
  readonly id: string;
  readonly aliases: readonly string[];
  readonly ecosystem: string;
  readonly packageName: string;
  readonly installedVersion: string;
  readonly severity: string;
  readonly cvssScore?: number;
  readonly source: string;
  readonly fixedVersions: readonly string[];
  readonly fixedVersionConflict: boolean;
  readonly location?: string;
}

export interface SecurityReportModel {
  readonly schemaVersion: 1;
  readonly generatedAt: string;
  readonly tool: { readonly name: "Dependency Vulnerability Auditor"; readonly version: string };
  readonly title: string;
  readonly summary: SecurityReportSummary;
  readonly dependencies: readonly SecurityReportDependency[];
  readonly vulnerabilities: readonly SecurityReportFinding[];
  readonly providers: readonly {
    provider: string;
    status: string;
    submitted: number;
    successful: number;
    failed: number;
    findings: number;
  }[];
  readonly policy?: SecurityGateResult;
  readonly licenses: readonly SecurityReportLicenseEvidence[];
  readonly provenance: readonly SecurityReportProvenanceEvidence[];
  readonly reachability: readonly SecurityReportReachabilityEvidence[];
  readonly anomalies: readonly SecurityReportAnomalyEvidence[];
  readonly knownExploitation: readonly SecurityReportKnownExploitationEvidence[];
  readonly remediation: readonly SecurityReportRemediationEvidence[];
  readonly diff?: SecurityReportDiffEvidence;
  readonly limitations: readonly string[];
}

const HARD_MAXIMUM_DEPENDENCIES = 100_000;
const HARD_MAXIMUM_FINDINGS = 100_000;
const HARD_MAXIMUM_EVIDENCE = 100_000;
const HARD_MAXIMUM_OUTPUT_BYTES = 64 * 1024 * 1024;
const MAXIMUM_TEXT = 4_096;
const MAXIMUM_EVIDENCE_TEXT = 2_048;
const UNSAFE_TEXT =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/gu;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u;

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new Error("Security report generation was cancelled");
  }
}

function boundedLimit(
  value: number | undefined,
  fallback: number,
  hardMaximum: number,
  label: string,
): number {
  const selected = value ?? fallback;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > hardMaximum
  ) {
    throw new RangeError(`${label} is outside the supported safety range`);
  }
  return selected;
}

function safeText(value: string, maximum = MAXIMUM_TEXT): string {
  const normalized = value.replace(UNSAFE_TEXT, "�").trim();
  if (normalized.length === 0) {
    return "UNKNOWN";
  }
  return normalized.length <= maximum
    ? normalized
    : `${normalized.slice(0, Math.max(0, maximum - 1))}…`;
}

function safeArray(
  values: readonly string[],
  maximumItems = 256,
  maximumText = MAXIMUM_EVIDENCE_TEXT,
): readonly string[] {
  return Object.freeze(
    [...new Set(values.slice(0, maximumItems).map((value) => safeText(value, maximumText)))]
      .sort((left, right) => left.localeCompare(right, "en")),
  );
}

function coordinateKey(
  value: Pick<Dependency, "ecosystem" | "name" | "installedVersion">,
): string;
function coordinateKey(
  value: Pick<Vulnerability, "ecosystem" | "packageName" | "installedVersion">,
): string;
function coordinateKey(
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

function dependencyKey(dependency: SecurityReportDependency): string {
  return JSON.stringify([
    dependency.ecosystem,
    dependency.name,
    dependency.version,
    dependency.dependencyType,
    dependency.environment,
    dependency.packageManager ?? "",
    dependency.location ?? "",
  ]);
}

function findingKey(finding: SecurityReportFinding): string {
  return JSON.stringify([
    finding.source,
    finding.id,
    finding.ecosystem,
    finding.packageName,
    finding.installedVersion,
    finding.location ?? "",
  ]);
}

function reportLocation(
  dependency: Dependency,
  workspaceRoots: readonly string[],
): string | undefined {
  return safeWorkspaceRelativePath(
    dependencyManifestPath(dependency),
    workspaceRoots,
  );
}

function validateTimestamp(value: string): string {
  if (!RFC3339.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new TypeError("generatedAt must be an RFC 3339 UTC timestamp");
  }
  return value;
}

function normalizeLicense(
  entry: SecurityReportLicenseEvidence,
): SecurityReportLicenseEvidence {
  return Object.freeze({
    ecosystem: safeText(entry.ecosystem, 64),
    packageName: safeText(entry.packageName, 1024),
    version: safeText(entry.version, 256),
    ...(entry.expression === undefined
      ? {}
      : { expression: safeText(entry.expression, 1024) }),
    status: entry.status,
    ...(entry.evidenceSource === undefined
      ? {}
      : { evidenceSource: safeText(entry.evidenceSource, 256) }),
  });
}

function normalizeProvenance(
  entry: SecurityReportProvenanceEvidence,
): SecurityReportProvenanceEvidence {
  return Object.freeze({
    ecosystem: safeText(entry.ecosystem, 64),
    packageName: safeText(entry.packageName, 1024),
    version: safeText(entry.version, 256),
    status: entry.status,
    evidence: safeArray(entry.evidence),
    limitations: safeArray(entry.limitations),
  });
}

function normalizeReachability(
  entry: SecurityReportReachabilityEvidence,
): SecurityReportReachabilityEvidence {
  return Object.freeze({
    ecosystem: safeText(entry.ecosystem, 64),
    packageName: safeText(entry.packageName, 1024),
    version: safeText(entry.version, 256),
    status: entry.status,
    confidence: entry.confidence,
    ...(entry.path === undefined ? {} : { path: safeArray(entry.path, 128) }),
    limitations: safeArray(entry.limitations),
  });
}

function normalizeAnomaly(
  entry: SecurityReportAnomalyEvidence,
): SecurityReportAnomalyEvidence {
  return Object.freeze({
    ecosystem: safeText(entry.ecosystem, 64),
    packageName: safeText(entry.packageName, 1024),
    version: safeText(entry.version, 256),
    signal: safeText(entry.signal, 256),
    confidence: entry.confidence,
    evidence: safeArray(entry.evidence),
    limitations: safeArray(entry.limitations),
  });
}

function normalizeRemediation(
  entry: SecurityReportRemediationEvidence,
): SecurityReportRemediationEvidence {
  return Object.freeze({
    advisoryId: safeText(entry.advisoryId, 512),
    ecosystem: safeText(entry.ecosystem, 64),
    packageName: safeText(entry.packageName, 1024),
    installedVersion: safeText(entry.installedVersion, 256),
    strategy: entry.strategy,
    ...(entry.recommendedVersion === undefined
      ? {}
      : { recommendedVersion: safeText(entry.recommendedVersion, 256) }),
    reason: safeText(entry.reason, MAXIMUM_EVIDENCE_TEXT),
    risk: entry.risk,
  });
}

function compareEvidence(
  left: { ecosystem: string; packageName: string; version: string },
  right: { ecosystem: string; packageName: string; version: string },
): number {
  return (
    left.ecosystem.localeCompare(right.ecosystem, "en") ||
    left.packageName.localeCompare(right.packageName, "en") ||
    left.version.localeCompare(right.version, "en")
  );
}

function totalEvidence(options: SecurityReportOptions): number {
  return (
    (options.licenses?.length ?? 0) +
    (options.provenance?.length ?? 0) +
    (options.reachability?.length ?? 0) +
    (options.anomalies?.length ?? 0) +
    (options.knownExploitation?.length ?? 0) +
    (options.remediation?.length ?? 0)
  );
}

export function buildSecurityReport(
  results: readonly ScanResult[],
  options: SecurityReportOptions,
): SecurityReportModel {
  throwIfCancelled(options.signal);
  const maximumDependencies = boundedLimit(
    options.maximumDependencies,
    10_000,
    HARD_MAXIMUM_DEPENDENCIES,
    "maximumDependencies",
  );
  const maximumFindings = boundedLimit(
    options.maximumFindings,
    50_000,
    HARD_MAXIMUM_FINDINGS,
    "maximumFindings",
  );
  const maximumEvidence = boundedLimit(
    options.maximumEvidenceRecords,
    50_000,
    HARD_MAXIMUM_EVIDENCE,
    "maximumEvidenceRecords",
  );
  if (totalEvidence(options) > maximumEvidence) {
    throw new RangeError("Security report evidence exceeds the configured limit");
  }
  const workspaceRoots = options.workspaceRoots ?? [];
  const dependencies = new Map<string, SecurityReportDependency>();
  const dependenciesByCoordinate = new Map<string, Dependency[]>();
  for (const result of results) {
    for (const dependency of result.dependencies) {
      if ((dependencies.size & 255) === 0) {
        throwIfCancelled(options.signal);
      }
      const location = reportLocation(dependency, workspaceRoots);
      const normalized: SecurityReportDependency = Object.freeze({
        ecosystem: safeText(dependency.ecosystem, 64),
        name: safeText(dependency.name, 1024),
        version: dependency.installedVersion.length === 0
          ? "UNRESOLVED"
          : safeText(dependency.installedVersion, 256),
        dependencyType: dependency.dependencyType,
        environment: dependency.environment,
        ...(dependency.packageManager === undefined
          ? {}
          : { packageManager: safeText(dependency.packageManager, 64) }),
        ...(location === undefined ? {} : { location }),
      });
      dependencies.set(dependencyKey(normalized), normalized);
      const coordinate = coordinateKey(dependency);
      const occurrences = dependenciesByCoordinate.get(coordinate) ?? [];
      occurrences.push(dependency);
      dependenciesByCoordinate.set(coordinate, occurrences);
      if (dependencies.size > maximumDependencies) {
        throw new RangeError("Security report dependencies exceed the configured limit");
      }
    }
  }
  const findings = new Map<string, SecurityReportFinding>();
  for (const result of results) {
    for (const vulnerability of scanResultKnownVulnerabilities(result)) {
      const occurrences = dependenciesByCoordinate.get(coordinateKey(vulnerability));
      const matching = occurrences === undefined || occurrences.length === 0
        ? [undefined]
        : occurrences;
      for (const occurrence of matching) {
        const location = occurrence === undefined
          ? undefined
          : reportLocation(occurrence, workspaceRoots);
        const normalized: SecurityReportFinding = Object.freeze({
          id: safeText(vulnerability.id, 512),
          aliases: safeArray(vulnerability.aliases, 256, 512),
          ecosystem: safeText(vulnerability.ecosystem, 64),
          packageName: safeText(vulnerability.packageName, 1024),
          installedVersion: safeText(vulnerability.installedVersion, 256),
          severity: vulnerability.severity,
          ...(vulnerability.cvssScore === undefined
            ? {}
            : { cvssScore: vulnerability.cvssScore }),
          source: safeText(vulnerability.source, 64),
          fixedVersions: safeArray(
            vulnerability.fixedVersions ??
              (vulnerability.fixedVersion === undefined
                ? []
                : [vulnerability.fixedVersion]),
            256,
            256,
          ),
          fixedVersionConflict: vulnerability.fixedVersionConflict === true,
          ...(location === undefined ? {} : { location }),
        });
        findings.set(findingKey(normalized), normalized);
        if (findings.size > maximumFindings) {
          throw new RangeError("Security report findings exceed the configured limit");
        }
      }
    }
  }
  const providerMap = new Map<string, SecurityReportModel["providers"][number]>();
  for (const result of results) {
    for (const provider of result.providerResults) {
      const current = providerMap.get(provider.provider);
      providerMap.set(provider.provider, Object.freeze({
        provider: safeText(provider.provider, 64),
        status:
          current?.status === "unavailable" || provider.status === "unavailable"
            ? "unavailable"
            : current?.status === "partial" || provider.status === "partial"
              ? "partial"
              : "available",
        submitted: (current?.submitted ?? 0) + provider.dependenciesSubmitted,
        successful: (current?.successful ?? 0) + provider.successful,
        failed: (current?.failed ?? 0) + provider.failed,
        findings: (current?.findings ?? 0) + provider.vulnerabilitiesFound,
      }));
    }
  }
  const licenses = Object.freeze(
    (options.licenses ?? []).map(normalizeLicense).sort(compareEvidence),
  );
  const provenance = Object.freeze(
    (options.provenance ?? []).map(normalizeProvenance).sort(compareEvidence),
  );
  const reachability = Object.freeze(
    (options.reachability ?? []).map(normalizeReachability).sort(compareEvidence),
  );
  const anomalies = Object.freeze(
    (options.anomalies ?? []).map(normalizeAnomaly).sort(
      (left, right) =>
        compareEvidence(left, right) || left.signal.localeCompare(right.signal, "en"),
    ),
  );
  const knownExploitation = Object.freeze(
    (options.knownExploitation ?? []).map((entry) => Object.freeze({
      advisoryId: safeText(entry.advisoryId, 512),
      ecosystem: safeText(entry.ecosystem, 64),
      packageName: safeText(entry.packageName, 1024),
      installedVersion: safeText(entry.installedVersion, 256),
      status: entry.status,
      source: safeText(entry.source, 128),
    })).sort(
      (left, right) =>
        left.ecosystem.localeCompare(right.ecosystem, "en") ||
        left.packageName.localeCompare(right.packageName, "en") ||
        left.installedVersion.localeCompare(right.installedVersion, "en") ||
        left.advisoryId.localeCompare(right.advisoryId, "en"),
    ),
  );
  const remediation = Object.freeze(
    (options.remediation ?? []).map(normalizeRemediation).sort(
      (left, right) =>
        left.ecosystem.localeCompare(right.ecosystem, "en") ||
        left.packageName.localeCompare(right.packageName, "en") ||
        left.installedVersion.localeCompare(right.installedVersion, "en") ||
        left.advisoryId.localeCompare(right.advisoryId, "en"),
    ),
  );
  const vulnerabilityRows = Object.freeze(
    [...findings.values()].sort((left, right) => findingKey(left).localeCompare(findingKey(right), "en")),
  );
  const dependencyRows = Object.freeze(
    [...dependencies.values()].sort((left, right) => dependencyKey(left).localeCompare(dependencyKey(right), "en")),
  );
  const coverageComplete = classifyScanCoverage(results) === "complete";
  const providerMismatch = [...providerMap.values()].some(
    (provider) => provider.findings > vulnerabilityRows.length,
  );
  const summary: SecurityReportSummary = Object.freeze({
    dependencies: dependencyRows.length,
    findings: vulnerabilityRows.length,
    critical: vulnerabilityRows.filter((entry) => entry.severity === "CRITICAL").length,
    high: vulnerabilityRows.filter((entry) => entry.severity === "HIGH").length,
    kev: knownExploitation.filter((entry) => entry.status === "known-exploited").length,
    kevCoverage:
      knownExploitation.length > 0 &&
      knownExploitation.every((entry) => entry.status !== "unknown")
        ? "complete"
        : "unknown",
    reachable: reachability.filter((entry) => entry.status === "REACHABLE").length,
    deniedLicenses: licenses.filter((entry) => entry.status === "DENIED").length,
    suspiciousProvenance: provenance.filter((entry) => entry.status === "SUSPICIOUS").length,
    anomalies: anomalies.length,
    coverage: coverageComplete && !providerMismatch ? "complete" : "incomplete",
  });
  const limitations = [
    ...(licenses.length === 0 ? ["License evidence was not supplied; license state is UNKNOWN."] : []),
    ...(provenance.length === 0 ? ["Provenance evidence was not supplied; provenance state is UNKNOWN."] : []),
    ...(reachability.length === 0 ? ["Static reachability evidence was not supplied; reachability is UNKNOWN."] : []),
    ...(summary.kevCoverage === "unknown" ? ["Known-exploitation evidence is incomplete or unavailable; KEV status is UNKNOWN."] : []),
    ...(summary.coverage === "incomplete" ? ["Security coverage is incomplete; zero findings is not a clean result."] : []),
    "Anomaly signals are evidence for review and are not malware classifications.",
  ];
  return Object.freeze({
    schemaVersion: 1 as const,
    generatedAt: validateTimestamp(options.generatedAt),
    tool: Object.freeze({
      name: "Dependency Vulnerability Auditor" as const,
      version: safeText(options.toolVersion, 64),
    }),
    title: safeText(options.title ?? "Dependency Security Report", 256),
    summary,
    dependencies: dependencyRows,
    vulnerabilities: vulnerabilityRows,
    providers: Object.freeze(
      [...providerMap.values()].sort((left, right) => left.provider.localeCompare(right.provider, "en")),
    ),
    ...(options.policy === undefined ? {} : { policy: options.policy }),
    licenses,
    provenance,
    reachability,
    anomalies,
    knownExploitation,
    remediation,
    ...(options.diff === undefined ? {} : { diff: Object.freeze({ ...options.diff }) }),
    limitations: Object.freeze(limitations),
  });
}

function asJsonValue(model: SecurityReportModel): JsonValue {
  return JSON.parse(JSON.stringify(model)) as JsonValue;
}

function enforceOutputLimit(
  output: string,
  maximumOutputBytes: number | undefined,
): string {
  const limit = boundedLimit(
    maximumOutputBytes,
    32 * 1024 * 1024,
    HARD_MAXIMUM_OUTPUT_BYTES,
    "maximumOutputBytes",
  );
  if (Buffer.byteLength(output, "utf8") > limit) {
    throw new RangeError("The generated security report exceeds the output limit");
  }
  return output;
}

function markdown(value: string): string {
  return safeText(value).replace(/([\\`*_[\]{}()#+.!|<>-])/gu, "\\$1");
}

function html(value: string): string {
  return safeText(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function csv(value: string): string {
  const normalized = safeText(value);
  const formulaSafe = /^[=+\-@]/u.test(normalized) ? `'${normalized}` : normalized;
  return `"${formulaSafe.replaceAll('"', '""')}"`;
}

export function exportSecurityReportJson(
  model: SecurityReportModel,
  maximumOutputBytes?: number,
): string {
  return enforceOutputLimit(
    `${canonicalJson(asJsonValue(model))}\n`,
    maximumOutputBytes,
  );
}

export function exportSecurityReportMarkdown(
  model: SecurityReportModel,
  maximumOutputBytes?: number,
): string {
  const lines = [
    `# ${markdown(model.title)}`,
    "",
    `Generated: ${markdown(model.generatedAt)}`,
    "",
    "## Executive summary",
    "",
    `- Coverage: **${model.summary.coverage.toUpperCase()}**`,
    `- Dependencies: ${model.summary.dependencies.toString()}`,
    `- Known findings: ${model.summary.findings.toString()}`,
    `- Critical / High: ${model.summary.critical.toString()} / ${model.summary.high.toString()}`,
    `- Known exploited: ${model.summary.kev.toString()} (coverage: ${model.summary.kevCoverage})`,
    `- Reachable observations: ${model.summary.reachable.toString()}`,
    `- Denied license findings: ${model.summary.deniedLicenses.toString()}`,
    `- Suspicious provenance findings: ${model.summary.suspiciousProvenance.toString()}`,
    "",
    "## Vulnerabilities",
    "",
    "| Severity | Advisory | Package | Version | Location | Fixed evidence |",
    "| --- | --- | --- | --- | --- | --- |",
    ...model.vulnerabilities.map((entry) =>
      `| ${markdown(entry.severity)} | ${markdown(entry.id)} | ${markdown(`${entry.ecosystem}/${entry.packageName}`)} | ${markdown(entry.installedVersion)} | ${markdown(entry.location ?? "UNKNOWN")} | ${markdown(entry.fixedVersions.join(", ") || "NO KNOWN FIX")} |`,
    ),
    "",
    "## Coverage and limitations",
    "",
    ...model.limitations.map((entry) => `- ${markdown(entry)}`),
    "",
  ];
  return enforceOutputLimit(lines.join("\n"), maximumOutputBytes);
}

export function exportSecurityReportCsv(
  model: SecurityReportModel,
  maximumOutputBytes?: number,
): string {
  const rows = [
    ["recordType", "ecosystem", "package", "version", "severityOrStatus", "identifier", "location"],
    ...model.dependencies.map((entry) => [
      "dependency",
      entry.ecosystem,
      entry.name,
      entry.version,
      entry.dependencyType,
      entry.environment,
      entry.location ?? "",
    ]),
    ...model.vulnerabilities.map((entry) => [
      "vulnerability",
      entry.ecosystem,
      entry.packageName,
      entry.installedVersion,
      entry.severity,
      entry.id,
      entry.location ?? "",
    ]),
    ...model.licenses.map((entry) => [
      "license",
      entry.ecosystem,
      entry.packageName,
      entry.version,
      entry.status,
      entry.expression ?? "UNKNOWN",
      "",
    ]),
  ];
  return enforceOutputLimit(
    `${rows.map((row) => row.map(csv).join(",")).join("\r\n")}\r\n`,
    maximumOutputBytes,
  );
}

export function exportSecurityReportHtml(
  model: SecurityReportModel,
  maximumOutputBytes?: number,
): string {
  const vulnerabilityRows = model.vulnerabilities.map((entry) =>
    `<tr><td>${html(entry.severity)}</td><td>${html(entry.id)}</td><td>${html(`${entry.ecosystem}/${entry.packageName}`)}</td><td>${html(entry.installedVersion)}</td><td>${html(entry.location ?? "UNKNOWN")}</td><td>${html(entry.fixedVersions.join(", ") || "NO KNOWN FIX")}</td></tr>`,
  ).join("");
  const limitations = model.limitations.map((entry) => `<li>${html(entry)}</li>`).join("");
  const document = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${html(model.title)}</title></head><body><header><h1>${html(model.title)}</h1><p>Generated ${html(model.generatedAt)}</p></header><main><section><h2>Executive summary</h2><dl><dt>Coverage</dt><dd>${html(model.summary.coverage.toUpperCase())}</dd><dt>Dependencies</dt><dd>${model.summary.dependencies.toString()}</dd><dt>Known findings</dt><dd>${model.summary.findings.toString()}</dd><dt>Critical / High</dt><dd>${model.summary.critical.toString()} / ${model.summary.high.toString()}</dd><dt>Known exploited</dt><dd>${model.summary.kev.toString()} (coverage: ${html(model.summary.kevCoverage)})</dd><dt>Reachable observations</dt><dd>${model.summary.reachable.toString()}</dd><dt>Denied licenses</dt><dd>${model.summary.deniedLicenses.toString()}</dd><dt>Suspicious provenance</dt><dd>${model.summary.suspiciousProvenance.toString()}</dd></dl></section><section><h2>Vulnerabilities</h2><table><thead><tr><th>Severity</th><th>Advisory</th><th>Package</th><th>Version</th><th>Location</th><th>Fixed evidence</th></tr></thead><tbody>${vulnerabilityRows}</tbody></table></section><section><h2>Coverage and limitations</h2><ul>${limitations}</ul></section></main></body></html>`;
  return enforceOutputLimit(document, maximumOutputBytes);
}

export function exportSecurityReport(
  model: SecurityReportModel,
  format: SecurityReportFormat,
  maximumOutputBytes?: number,
): string {
  switch (format) {
    case "json":
      return exportSecurityReportJson(model, maximumOutputBytes);
    case "html":
      return exportSecurityReportHtml(model, maximumOutputBytes);
    case "markdown":
      return exportSecurityReportMarkdown(model, maximumOutputBytes);
    case "csv":
      return exportSecurityReportCsv(model, maximumOutputBytes);
  }
}
