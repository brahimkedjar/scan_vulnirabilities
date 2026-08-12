import {
  dependencyManifestPath,
  type Dependency,
} from "../models/Dependency";
import type { ScanResult } from "../models/ScanResult";
import type { Severity, Vulnerability } from "../models/Vulnerability";
import type { RetainedVulnerabilityFinding } from "../services/ScanResultStore";
import type {
  RemediationAnalysisResult,
  RemediationRecommendation,
} from "../remediation/RemediationModels";
import { dependencyOccurrenceKey } from "../remediation/DependencyPathAnalyzer";

export type DiagnosticLevel = "error" | "warning" | "information";

export interface DependencyDiagnosticPlan {
  readonly targetDependency: Dependency;
  readonly vulnerability: Vulnerability;
  readonly level: DiagnosticLevel;
  readonly identifier: string;
  readonly message: string;
  readonly dependencyPath?: string;
}

const DEFAULT_MAXIMUM_DIAGNOSTICS = 2_000;
const MAXIMUM_DIAGNOSTIC_VALUE_LENGTH = 512;
const CONTROL_CHARACTERS =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/gu;

function boundedValue(value: string): string {
  const sanitized = value
    .replaceAll("\r", " ")
    .replaceAll("\n", " ")
    .replaceAll("\t", " ")
    .replace(CONTROL_CHARACTERS, "�");
  return sanitized.length <= MAXIMUM_DIAGNOSTIC_VALUE_LENGTH
    ? sanitized
    : `${sanitized.slice(0, MAXIMUM_DIAGNOSTIC_VALUE_LENGTH - 1)}…`;
}

export function diagnosticLevelForSeverity(
  severity: Severity,
): DiagnosticLevel {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "error";
    case "MEDIUM":
      return "warning";
    case "LOW":
    case "UNKNOWN":
      return "information";
  }
}

export function preferredVulnerabilityIdentifier(
  vulnerability: Vulnerability,
): string {
  return boundedValue(
    vulnerability.aliases.find((alias) => alias.startsWith("CVE-")) ??
      vulnerability.aliases.find((alias) => alias.startsWith("GHSA-")) ??
      vulnerability.id,
  );
}

function coordinate(
  ecosystem: string,
  name: string,
  version: string,
): string {
  return `${ecosystem}\u0000${name}\u0000${version}`;
}

function originCoordinate(dependency: Dependency): string | undefined {
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
  return JSON.stringify([
    manifestPath,
    application,
    directEntry,
  ]);
}

function findDiagnosticTarget(
  dependency: Dependency,
  directByOrigin: ReadonlyMap<string, Dependency>,
): Dependency | undefined {
  if (dependency.dependencyType === "direct") {
    return dependency;
  }
  // Go's `// indirect` requirements are transitive in dependency semantics,
  // but they are still explicit, safely locatable declarations in go.mod.
  if (
    dependency.packageManager === "go" &&
    dependency.metadata?.manifestSection === "require" &&
    dependency.manifestName !== undefined &&
    dependencyManifestPath(dependency) !== undefined
  ) {
    return dependency;
  }
  const origin = originCoordinate(dependency);
  return origin === undefined ? undefined : directByOrigin.get(origin);
}

function formatDependencyPath(dependency: Dependency): string | undefined {
  if (dependency.dependencyPath === undefined) {
    return undefined;
  }
  return boundedValue(dependency.dependencyPath.map(boundedValue).join(" → "));
}

function messageForPlan(
  target: Dependency,
  dependency: Dependency,
  vulnerability: Vulnerability,
  identifier: string,
  dependencyPath: string | undefined,
  remediation: RemediationRecommendation | undefined,
): string {
  const packageIdentity = `${boundedValue(vulnerability.packageName)}@${boundedValue(vulnerability.installedVersion)}`;
  const ecosystem = boundedValue(vulnerability.ecosystem);
  const fixed = boundedValue(
    remediation?.recommendedVersion ??
      vulnerability.fixedVersion ??
      (vulnerability.fixedVersions?.length === 1
        ? vulnerability.fixedVersions[0]
        : undefined) ??
      (vulnerability.fixedVersions === undefined ||
      vulnerability.fixedVersions.length === 0
        ? "No known fixed version"
        : "Multiple provider values; manual review required"),
  );
  const remediationText = remediationMessage(target, dependency, remediation);
  if (dependency.dependencyType === "direct" || target === dependency) {
    return `${packageIdentity} (${ecosystem} dependency) — ${vulnerability.severity} vulnerability\n${identifier}\nFixed version: ${fixed}${remediationText}`;
  }
  const introducer = boundedValue(target.manifestName ?? target.name);
  const pathLine =
    dependencyPath === undefined ? "" : `\nPath: ${dependencyPath}`;
  return `${introducer} introduces vulnerable ${packageIdentity} (${ecosystem} dependency) — ${vulnerability.severity}\n${identifier}${pathLine}\nFixed version: ${fixed}${remediationText}`;
}

function remediationLookup(
  analysis: RemediationAnalysisResult | undefined,
): ReadonlyMap<string, readonly RemediationRecommendation[]> {
  const lookup = new Map<string, RemediationRecommendation[]>();
  for (const recommendation of analysis?.recommendations ?? []) {
    const key = dependencyOccurrenceKey(recommendation.dependency);
    const entries = lookup.get(key);
    if (entries === undefined) {
      lookup.set(key, [recommendation]);
    } else {
      entries.push(recommendation);
    }
  }
  return lookup;
}

function recommendationFor(
  dependency: Dependency,
  vulnerability: Vulnerability,
  lookup: ReadonlyMap<string, readonly RemediationRecommendation[]>,
): RemediationRecommendation | undefined {
  const matches = (lookup.get(dependencyOccurrenceKey(dependency)) ?? []).filter(
    (recommendation) =>
      recommendation.vulnerabilityIds.includes(vulnerability.id),
  );
  return matches.length === 1 ? matches[0] : undefined;
}

function remediationMessage(
  target: Dependency,
  dependency: Dependency,
  remediation: RemediationRecommendation | undefined,
): string {
  if (remediation === undefined) {
    return "";
  }
  const candidate =
    remediation.recommendedVersion === undefined
      ? undefined
      : boundedValue(remediation.recommendedVersion);
  switch (remediation.strategy) {
    case "upgrade-direct":
      return candidate === undefined
        ? "\nManual review required."
        : `\nKnown fixed version: ${candidate}.\nRecommended upgrade: ${candidate}.`;
    case "upgrade-parent": {
      const parent = boundedValue(target.manifestName ?? target.name);
      return candidate === undefined
        ? "\nTransitive dependency.\nReview the parent dependency for a compatible release."
        : `\nKnown fixed version: ${candidate}.\nTransitive dependency.\nReview parent dependency ${parent} for a compatible release that resolves the remediation candidate ${candidate}.`;
    }
    case "upgrade-transitive":
      return candidate === undefined
        ? "\nTransitive dependency.\nManual review required."
        : `\nKnown fixed version: ${candidate}.\nTransitive dependency.\nReview an ecosystem-supported resolution that selects the remediation candidate ${candidate}.`;
    case "no-fixed-version":
      return "\nNo known fixed version. Manual review required.";
    case "unresolved":
      return "\nUnable to calculate a remediation target because the dependency version is unresolved.";
    case "manual-review":
      return dependency.dependencyType === "transitive"
        ? "\nTransitive dependency.\nManual review required; no safe parent upgrade was established."
        : "\nManual review required; no single remediation candidate was established.";
  }
}

export function buildDependencyDiagnosticPlans(
  scanResults: readonly ScanResult[],
  maximumDiagnostics = DEFAULT_MAXIMUM_DIAGNOSTICS,
  remediationAnalysis?: RemediationAnalysisResult,
): readonly DependencyDiagnosticPlan[] {
  if (!Number.isSafeInteger(maximumDiagnostics) || maximumDiagnostics < 0) {
    throw new RangeError("maximumDiagnostics must be a non-negative integer");
  }
  const plans: DependencyDiagnosticPlan[] = [];
  const seen = new Set<string>();
  const remediations = remediationLookup(remediationAnalysis);

  for (const scanResult of scanResults) {
    const directByOrigin = new Map<string, Dependency>();
    const dependenciesByCoordinate = new Map<string, Dependency[]>();
    for (const dependency of scanResult.dependencies) {
      const key = coordinate(
        dependency.ecosystem,
        dependency.name,
        dependency.installedVersion,
      );
      const matching = dependenciesByCoordinate.get(key) ?? [];
      matching.push(dependency);
      dependenciesByCoordinate.set(key, matching);
      if (dependency.dependencyType === "direct") {
        const origin = originCoordinate(dependency);
        if (origin !== undefined && !directByOrigin.has(origin)) {
          directByOrigin.set(origin, dependency);
        }
      }
    }

    for (const vulnerability of scanResult.vulnerabilities) {
      const matchingDependencies =
        dependenciesByCoordinate.get(
          coordinate(
            vulnerability.ecosystem,
            vulnerability.packageName,
            vulnerability.installedVersion,
          ),
        ) ?? [];
      for (const dependency of matchingDependencies) {
        if (plans.length >= maximumDiagnostics) {
          return plans;
        }
        const target = findDiagnosticTarget(dependency, directByOrigin);
        const targetManifestPath =
          target === undefined ? undefined : dependencyManifestPath(target);
        if (
          target === undefined ||
          targetManifestPath === undefined ||
          targetManifestPath.length === 0
        ) {
          continue;
        }
        const identifier = preferredVulnerabilityIdentifier(vulnerability);
        const key = JSON.stringify([
          targetManifestPath,
          target.manifestName ?? target.name,
          vulnerability.source,
          vulnerability.id,
          vulnerability.packageName,
          vulnerability.installedVersion,
        ]);
        if (seen.has(key)) {
          continue;
        }
        seen.add(key);
        const dependencyPath = formatDependencyPath(dependency);
        const remediation = recommendationFor(
          dependency,
          vulnerability,
          remediations,
        );
        plans.push({
          targetDependency: target,
          vulnerability,
          level: diagnosticLevelForSeverity(vulnerability.severity),
          identifier,
          message: messageForPlan(
            target,
            dependency,
            vulnerability,
            identifier,
            dependencyPath,
            remediation,
          ),
          ...(dependencyPath === undefined ? {} : { dependencyPath }),
        });
      }
    }
  }
  return plans;
}

/**
 * Builds finding-only diagnostics for evidence retained from the last complete
 * scan. These plans never contribute provider or coverage totals and are
 * visibly marked as not reconfirmed by the latest partial attempt.
 */
export function buildRetainedDependencyDiagnosticPlans(
  retainedFindings: readonly RetainedVulnerabilityFinding[],
  maximumDiagnostics = DEFAULT_MAXIMUM_DIAGNOSTICS,
): readonly DependencyDiagnosticPlan[] {
  if (!Number.isSafeInteger(maximumDiagnostics) || maximumDiagnostics < 0) {
    throw new RangeError("maximumDiagnostics must be a non-negative integer");
  }
  if (maximumDiagnostics === 0 || retainedFindings.length === 0) {
    return [];
  }
  const retainedResults: ScanResult[] = retainedFindings.map((finding) => ({
    workspacePath: finding.workspacePaths[0] ?? "retained-evidence",
    scannedAt: finding.lastConfirmedAt,
    durationMs: 0,
    packageManagers: [],
    dependenciesScanned: 0,
    vulnerableDependencies: 0,
    vulnerabilities: [finding.vulnerability],
    dependencies: finding.dependencies,
    errors: [],
    providerResults: [],
    cancelled: false,
  }));
  const confirmationByVulnerability = new Map(
    retainedFindings.map(
      (finding) => [finding.vulnerability, finding.lastConfirmedAt] as const,
    ),
  );
  return buildDependencyDiagnosticPlans(
    retainedResults,
    maximumDiagnostics,
  ).map((plan) => ({
    ...plan,
    message: `${plan.message}\nHistorical evidence: last confirmed ${boundedValue(confirmationByVulnerability.get(plan.vulnerability) ?? "during the last complete scan")}; not reconfirmed by the latest partial scan.`,
  }));
}
