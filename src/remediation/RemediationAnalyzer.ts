import {
  dependencyIsResolved,
  dependencyManifestPath,
  type Dependency,
} from "../models/Dependency";
import type { ScanResult } from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import { classifyScanCoverage } from "../services/ScanResultStore";
import {
  mapDependencyToOsv,
  mapEcosystem,
  normalizePypiName,
  type SupportedOsvEcosystem,
} from "../vulnerability/EcosystemMapper";
import {
  analyzeDependencyPath,
  dependencyOccurrenceKey,
} from "./DependencyPathAnalyzer";
import type { RemediationAnalysisSource } from "./RemediationAnalysisSource";
import { remediationConfidence } from "./RemediationConfidence";
import type {
  RemediationAnalysisOptions,
  RemediationAnalysisResult,
  RemediationEvidence,
  RemediationRecommendation,
  RemediationStrategy,
} from "./RemediationModels";
import {
  remediationDisplayValue,
  remediationReason,
} from "./RemediationReason";
import {
  intersectFixedVersions,
  selectRecommendedVersion,
} from "./VersionRecommendation";
import { analyzeVersionRisk } from "./VersionRiskAnalyzer";

const HARD_MAXIMUM_DEPENDENCY_OCCURRENCES = 10_000;
const HARD_MAXIMUM_VULNERABILITY_RECORDS = 50_000;
const HARD_MAXIMUM_FINDING_OCCURRENCE_ASSOCIATIONS = 100_000;
const MAXIMUM_EVIDENCE_RECORDS = 100;
const MAXIMUM_FIXED_VERSIONS = 32;

interface FindingRecord {
  readonly key: string;
  readonly vulnerability: Vulnerability;
}

interface AnalysisOccurrence {
  readonly key: string;
  readonly constraintCoordinate: string;
  readonly dependency: Dependency;
  readonly allDependencies: readonly Dependency[];
  readonly findings: Map<string, FindingRecord>;
  readonly synthetic: boolean;
}

interface CategorizedRecommendation {
  readonly recommendation: RemediationRecommendation;
  readonly findingKeys: readonly string[];
}

function boundedOption(
  value: number | undefined,
  maximum: number,
  name: string,
): number {
  const selected = value ?? maximum;
  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > maximum
  ) {
    throw new RangeError(`${name} must be between 1 and ${maximum.toString()}`);
  }
  return selected;
}

function vulnerabilityKey(vulnerability: Vulnerability): string {
  return JSON.stringify([
    vulnerability.source,
    vulnerability.id,
    vulnerability.ecosystem,
    vulnerability.packageName,
    vulnerability.installedVersion,
  ]);
}

function resultKey(result: ScanResult): string {
  return JSON.stringify([result.workspacePath, result.scannedAt]);
}

function canonicalDependencyCoordinate(dependency: Dependency): string {
  const mapped = mapDependencyToOsv(dependency);
  return mapped.supported
    ? JSON.stringify([
        mapped.identity.ecosystem,
        mapped.identity.packageName,
        mapped.identity.version,
      ])
    : JSON.stringify([
        mapEcosystem(dependency.ecosystem) ?? dependency.ecosystem,
        dependency.ecosystem.toLowerCase() === "pypi"
          ? normalizePypiName(dependency.name)
          : dependency.name,
        dependency.installedVersion,
      ]);
}

function vulnerabilityCoordinate(vulnerability: Vulnerability): string {
  return JSON.stringify([
    vulnerability.ecosystem,
    vulnerability.ecosystem === "PyPI"
      ? normalizePypiName(vulnerability.packageName)
      : vulnerability.packageName,
    vulnerability.installedVersion,
  ]);
}

function syntheticDependency(vulnerability: Vulnerability): Dependency {
  return {
    name: vulnerability.packageName,
    ecosystem: vulnerability.ecosystem,
    installedVersion: vulnerability.installedVersion,
    resolutionStatus:
      vulnerability.installedVersion.length === 0 ? "unresolved" : "resolved",
    dependencyType: "transitive",
    environment: "production",
    dependencyPath: [
      `${vulnerability.packageName}@${vulnerability.installedVersion}`,
    ],
    metadata: { relationshipDetail: "dependency-graph-unavailable" },
  };
}

function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted ?? false;
}

function authoritativeFixedVersions(
  vulnerability: Vulnerability,
): readonly string[] {
  const values =
    vulnerability.fixedVersions ??
    (vulnerability.fixedVersion === undefined
      ? []
      : [vulnerability.fixedVersion]);
  return [...new Set(values)].slice(0, MAXIMUM_FIXED_VERSIONS);
}

function remediationCandidates(
  vulnerability: Vulnerability,
): readonly string[] {
  return vulnerability.remediationCandidates === undefined
    ? authoritativeFixedVersions(vulnerability)
    : [...new Set(vulnerability.remediationCandidates)].slice(
        0,
        MAXIMUM_FIXED_VERSIONS,
      );
}

function stableUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) =>
    left.localeCompare(right, "en"),
  );
}

function evidenceFor(
  dependency: Dependency,
  vulnerabilities: readonly Vulnerability[],
  fixedVersions: readonly string[],
  strategy: RemediationStrategy,
  parent: Dependency | undefined,
): readonly RemediationEvidence[] {
  const evidence: RemediationEvidence[] = [];
  for (const vulnerability of vulnerabilities.slice(0, MAXIMUM_EVIDENCE_RECORDS)) {
    const reported = authoritativeFixedVersions(vulnerability);
    evidence.push({
      source: "osv",
      description:
        reported.length === 0
          ? `${remediationDisplayValue(vulnerability.id)} has no fixed version reported by OSV.`
          : `OSV reports fixed-version event${reported.length === 1 ? "" : "s"} ${reported
              .map((version) => remediationDisplayValue(version, 256))
              .join(", ")} for ${remediationDisplayValue(vulnerability.id)}.`,
    });
  }
  if (dependency.dependencyPath !== undefined) {
    evidence.push({
      source: "dependency-graph",
      description: `Stored dependency path: ${dependency.dependencyPath
        .slice(0, 128)
        .map((segment) => remediationDisplayValue(segment, 256))
        .join(" → ")}${dependency.dependencyPath.length > 128 ? " → …" : ""}.`,
    });
  }
  if (dependency.lockfilePath !== undefined) {
    evidence.push({
      source: "lockfile",
      description: `Resolved version ${remediationDisplayValue(dependency.installedVersion, 256)} was obtained from stored lock state.`,
    });
  }
  if (dependencyManifestPath(dependency) !== undefined) {
    evidence.push({
      source: "manifest",
      description:
        dependency.dependencyType === "direct"
          ? `${remediationDisplayValue(dependency.manifestName ?? dependency.name)} is declared directly in the owning manifest.`
          : "The owning manifest identifies the dependency project, but the vulnerable package is transitive.",
    });
  }
  if (strategy === "upgrade-parent" && parent !== undefined) {
    evidence.push({
      source: "dependency-graph",
      description: `${remediationDisplayValue(parent.manifestName ?? parent.name)} is the unambiguous direct dependency prefix on the stored path; no future parent version was inferred.`,
    });
  }
  if (fixedVersions.length > 0 && vulnerabilities.length > 1) {
    evidence.push({
      source: "osv",
      description: `The exact shared provider-listed candidate set is ${fixedVersions
        .map((version) => remediationDisplayValue(version, 256))
        .join(", ")}.`,
    });
  }
  return Object.freeze(evidence.slice(0, MAXIMUM_EVIDENCE_RECORDS));
}

function providerEvidenceComplete(vulnerabilities: readonly Vulnerability[]): boolean {
  return vulnerabilities.every(
    (vulnerability) =>
      vulnerability.fixedVersions !== undefined &&
      vulnerability.remediationCandidates !== undefined &&
      vulnerability.fixedVersionConflict !== true,
  );
}

function categoryForStrategy(
  strategy: RemediationStrategy,
): "remediable" | "no-fix" | "manual" | "unresolved" {
  switch (strategy) {
    case "upgrade-direct":
    case "upgrade-parent":
    case "upgrade-transitive":
      return "remediable";
    case "no-fixed-version":
      return "no-fix";
    case "unresolved":
      return "unresolved";
    case "manual-review":
      return "manual";
  }
}

function buildRecommendation(
  occurrence: AnalysisOccurrence,
  coverageComplete: boolean,
  constraintsComplete: boolean,
): RemediationRecommendation {
  const dependency = occurrence.dependency;
  const findings = [...occurrence.findings.values()].sort((left, right) =>
    left.key.localeCompare(right.key, "en"),
  );
  const vulnerabilities = findings.map((finding) => finding.vulnerability);
  const vulnerabilityIds = stableUnique(
    vulnerabilities.map((vulnerability) => vulnerability.id),
  );
  const authoritativeVersions = stableUnique(
    vulnerabilities.flatMap(authoritativeFixedVersions),
  );
  const authoritativeVersionSet = new Set(authoritativeVersions);
  // Runtime validation enforces this invariant for provider/cache data. Keep
  // the analyzer fail-closed as well because it is also a public local API and
  // can receive hand-built ScanResult objects directly.
  const fixedVersionSets = vulnerabilities.map((vulnerability) =>
    remediationCandidates(vulnerability).filter((candidate) =>
      authoritativeVersionSet.has(candidate),
    ),
  );
  const sharedFixedVersions = intersectFixedVersions(fixedVersionSets);
  const mapped = mapDependencyToOsv(dependency);
  const ecosystem: SupportedOsvEcosystem | undefined = mapped.supported
    ? mapped.identity.ecosystem
    : mapEcosystem(dependency.ecosystem);
  const pathAnalysis = analyzeDependencyPath(
    dependency,
    occurrence.allDependencies,
  );
  const hasProviderConflict = vulnerabilities.some(
    (vulnerability) => vulnerability.fixedVersionConflict === true,
  );
  const resolved = dependencyIsResolved(dependency);
  let strategy: RemediationStrategy;
  let recommendedVersion: string | undefined;
  let conflict:
    | "provider"
    | "constraints"
    | "version"
    | "incomplete"
    | undefined;

  if (!resolved) {
    strategy = "unresolved";
  } else if (!constraintsComplete) {
    strategy = "manual-review";
    conflict = "incomplete";
  } else if (hasProviderConflict) {
    strategy = "manual-review";
    conflict = "provider";
  } else if (authoritativeVersions.length === 0) {
    strategy = "no-fixed-version";
  } else if (
    fixedVersionSets.some((values) => values.length === 0) ||
    sharedFixedVersions.length === 0
  ) {
    strategy = "manual-review";
    conflict = "constraints";
  } else if (!mapped.supported || ecosystem === undefined) {
    strategy = "manual-review";
    conflict = "version";
  } else {
    const selection = selectRecommendedVersion(
      ecosystem,
      dependency.installedVersion,
      sharedFixedVersions,
    );
    if (selection.kind !== "selected" || selection.version === undefined) {
      strategy = "manual-review";
      conflict = "version";
    } else if (occurrence.synthetic) {
      strategy = "manual-review";
      recommendedVersion = undefined;
    } else if (pathAnalysis.direct) {
      strategy = "upgrade-direct";
      recommendedVersion = selection.version;
    } else if (pathAnalysis.parentProven) {
      strategy = "upgrade-parent";
      recommendedVersion = selection.version;
    } else {
      strategy = "manual-review";
      recommendedVersion = undefined;
    }
  }

  const confidence = remediationConfidence({
    strategy,
    exactResolvedIdentity: mapped.supported && !occurrence.synthetic,
    coverageComplete,
    providerEvidenceComplete: providerEvidenceComplete(vulnerabilities),
  });
  const reasonInput = {
    strategy,
    dependency,
    ...(recommendedVersion === undefined ? {} : { recommendedVersion }),
    ...(pathAnalysis.directParent === undefined
      ? {}
      : { parent: pathAnalysis.directParent }),
    multipleVulnerabilities: vulnerabilities.length > 1,
    ...(conflict === undefined ? {} : { conflict }),
  } as const;
  const evidence = evidenceFor(
    dependency,
    vulnerabilities,
    sharedFixedVersions,
    strategy,
    pathAnalysis.directParent,
  );
  const recommendation: RemediationRecommendation = {
    recommendationKey: JSON.stringify([
      occurrence.key,
      findings.map((finding) => finding.key),
    ]),
    vulnerabilityId: vulnerabilityIds[0] ?? "UNKNOWN",
    vulnerabilityIds: Object.freeze(vulnerabilityIds),
    dependency,
    currentVersion: dependency.installedVersion,
    ...(recommendedVersion === undefined ? {} : { recommendedVersion }),
    fixedVersions: Object.freeze(authoritativeVersions),
    strategy,
    confidence,
    dependencyPath: pathAnalysis.dependencyPath,
    directDependency: pathAnalysis.direct,
    breakingChangeRisk:
      ecosystem === undefined
        ? "unknown"
        : analyzeVersionRisk(
            ecosystem,
            dependency.installedVersion,
            recommendedVersion,
          ),
    reason: remediationReason(reasonInput),
    evidence,
  };
  return Object.freeze(recommendation);
}

function emptyResult(
  totalVulnerabilities: number,
  analysisComplete: boolean,
): RemediationAnalysisResult {
  return Object.freeze({
    recommendations: Object.freeze([]),
    remediable: Object.freeze([]),
    noFix: Object.freeze([]),
    manualReview: Object.freeze([]),
    unresolved: Object.freeze([]),
    summary: Object.freeze({
      totalVulnerabilities,
      remediable: 0,
      noKnownFix: 0,
      manualReview: totalVulnerabilities,
      unresolved: 0,
      remediationCoveragePercent: 0,
      analysisComplete,
    }),
  });
}

export class RemediationAnalyzer implements RemediationAnalysisSource {
  public analyze(
    scanResults: readonly ScanResult[],
    options: RemediationAnalysisOptions = {},
  ): RemediationAnalysisResult {
    const maximumDependencies = boundedOption(
      options.maximumDependencyOccurrences,
      HARD_MAXIMUM_DEPENDENCY_OCCURRENCES,
      "maximumDependencyOccurrences",
    );
    const maximumVulnerabilities = boundedOption(
      options.maximumVulnerabilityRecords,
      HARD_MAXIMUM_VULNERABILITY_RECORDS,
      "maximumVulnerabilityRecords",
    );
    const maximumAssociations = boundedOption(
      options.maximumFindingOccurrenceAssociations,
      HARD_MAXIMUM_FINDING_OCCURRENCE_ASSOCIATIONS,
      "maximumFindingOccurrenceAssociations",
    );
    const totalVulnerabilities = scanResults.reduce(
      (total, result) =>
        Math.min(
          Number.MAX_SAFE_INTEGER,
          total + result.vulnerabilities.length,
        ),
      0,
    );
    if (isAborted(options.signal)) {
      return emptyResult(totalVulnerabilities, false);
    }

    const sortedResults = [...scanResults].sort((left, right) =>
      resultKey(left).localeCompare(resultKey(right), "en"),
    );
    const occurrences = new Map<string, AnalysisOccurrence>();
    const incompleteFindingKeys = new Set<string>();
    const incompleteConstraintCoordinates = new Set<string>();
    let dependencyLimitReached = false;
    let vulnerabilityLimitReached = false;
    let associationLimitReached = false;
    let cancelled = false;
    let remainingVulnerabilityBudget = maximumVulnerabilities;
    let retainedDependencyCount = 0;
    let findingOccurrenceAssociations = 0;

    for (const result of sortedResults) {
      if (isAborted(options.signal)) {
        cancelled = true;
        break;
      }
      const sortedDependencies = [...result.dependencies].sort((left, right) =>
        dependencyOccurrenceKey(left).localeCompare(
          dependencyOccurrenceKey(right),
          "en",
        ),
      );
      const retainedDependencies = sortedDependencies.slice(
        0,
        Math.max(0, maximumDependencies - retainedDependencyCount),
      );
      retainedDependencyCount += retainedDependencies.length;
      if (retainedDependencies.length < sortedDependencies.length) {
        dependencyLimitReached = true;
      }
      const omittedCoordinates = new Set(
        sortedDependencies
          .slice(retainedDependencies.length)
          .map(canonicalDependencyCoordinate),
      );
      const dependenciesByCoordinate = new Map<string, Dependency[]>();
      for (const dependency of retainedDependencies) {
        const coordinate = canonicalDependencyCoordinate(dependency);
        const entries = dependenciesByCoordinate.get(coordinate) ?? [];
        entries.push(dependency);
        dependenciesByCoordinate.set(coordinate, entries);
      }

      const sortedVulnerabilities = [...result.vulnerabilities].sort(
        (left, right) => vulnerabilityKey(left).localeCompare(vulnerabilityKey(right), "en"),
      );
      const visibleVulnerabilities = sortedVulnerabilities.slice(
        0,
        remainingVulnerabilityBudget,
      );
      if (visibleVulnerabilities.length < sortedVulnerabilities.length) {
        vulnerabilityLimitReached = true;
        for (const omitted of sortedVulnerabilities.slice(
          visibleVulnerabilities.length,
        )) {
          incompleteConstraintCoordinates.add(
            JSON.stringify([
              resultKey(result),
              vulnerabilityCoordinate(omitted),
            ]),
          );
        }
      }
      remainingVulnerabilityBudget -= visibleVulnerabilities.length;
      for (let index = 0; index < visibleVulnerabilities.length; index += 1) {
        if (isAborted(options.signal)) {
          cancelled = true;
          break;
        }
        const vulnerability = visibleVulnerabilities[index];
        if (vulnerability === undefined) {
          continue;
        }
        const findingKey = JSON.stringify([
          resultKey(result),
          vulnerabilityKey(vulnerability),
          index,
        ]);
        if (omittedCoordinates.has(vulnerabilityCoordinate(vulnerability))) {
          incompleteFindingKeys.add(findingKey);
        }
        const finding: FindingRecord = { key: findingKey, vulnerability };
        const constraintCoordinate = JSON.stringify([
          resultKey(result),
          vulnerabilityCoordinate(vulnerability),
        ]);
        const matching =
          dependenciesByCoordinate.get(vulnerabilityCoordinate(vulnerability)) ?? [];
        const dependencies =
          matching.length === 0 ? [syntheticDependency(vulnerability)] : matching;
        if (findingOccurrenceAssociations >= maximumAssociations) {
          associationLimitReached = true;
          incompleteConstraintCoordinates.add(constraintCoordinate);
          incompleteFindingKeys.add(findingKey);
          continue;
        }
        for (const dependency of dependencies) {
          if (findingOccurrenceAssociations >= maximumAssociations) {
            associationLimitReached = true;
            incompleteConstraintCoordinates.add(constraintCoordinate);
            incompleteFindingKeys.add(findingKey);
            break;
          }
          const synthetic = matching.length === 0;
          const key = JSON.stringify([
            resultKey(result),
            synthetic ? "unmatched" : "dependency",
            synthetic ? findingKey : dependencyOccurrenceKey(dependency),
          ]);
          let occurrence = occurrences.get(key);
          if (occurrence === undefined) {
            if (occurrences.size >= maximumDependencies) {
              dependencyLimitReached = true;
              incompleteFindingKeys.add(findingKey);
              continue;
            }
            occurrence = {
              key,
              constraintCoordinate,
              dependency,
              allDependencies: retainedDependencies,
              findings: new Map(),
              synthetic,
            };
            occurrences.set(key, occurrence);
          }
          if (!occurrence.findings.has(findingKey)) {
            occurrence.findings.set(findingKey, finding);
            findingOccurrenceAssociations += 1;
          }
        }
      }
      if (cancelled || remainingVulnerabilityBudget === 0) {
        if (
          sortedResults.some((candidate) => candidate !== result) ||
          visibleVulnerabilities.length < sortedVulnerabilities.length
        ) {
          vulnerabilityLimitReached = !cancelled;
        }
        break;
      }
    }

    const coverageComplete = classifyScanCoverage(scanResults) === "complete";
    const categorized: CategorizedRecommendation[] = [];
    for (const occurrence of [...occurrences.values()].sort((left, right) =>
      left.key.localeCompare(right.key, "en"),
    )) {
      if (isAborted(options.signal)) {
        cancelled = true;
        break;
      }
      categorized.push({
        recommendation: buildRecommendation(
          occurrence,
          coverageComplete,
          !incompleteConstraintCoordinates.has(occurrence.constraintCoordinate),
        ),
        findingKeys: [...occurrence.findings.keys()],
      });
    }

    const recommendations = categorized.map((entry) => entry.recommendation);
    const remediable = recommendations.filter(
      (recommendation) => categoryForStrategy(recommendation.strategy) === "remediable",
    );
    const noFix = recommendations.filter(
      (recommendation) => categoryForStrategy(recommendation.strategy) === "no-fix",
    );
    const manualReview = recommendations.filter(
      (recommendation) => categoryForStrategy(recommendation.strategy) === "manual",
    );
    const unresolved = recommendations.filter(
      (recommendation) => categoryForStrategy(recommendation.strategy) === "unresolved",
    );

    const categoriesByFinding = new Map<
      string,
      Set<"remediable" | "no-fix" | "manual" | "unresolved">
    >();
    for (const entry of categorized) {
      const category = categoryForStrategy(entry.recommendation.strategy);
      for (const findingKey of entry.findingKeys) {
        const values = categoriesByFinding.get(findingKey) ?? new Set();
        values.add(category);
        categoriesByFinding.set(findingKey, values);
      }
    }
    for (const findingKey of incompleteFindingKeys) {
      const values = categoriesByFinding.get(findingKey) ?? new Set();
      values.add("manual");
      categoriesByFinding.set(findingKey, values);
    }
    let remediableCount = 0;
    let noFixCount = 0;
    let unresolvedCount = 0;
    let manualCount = Math.max(0, totalVulnerabilities - categoriesByFinding.size);
    for (const values of categoriesByFinding.values()) {
      if (values.size === 1 && values.has("remediable")) {
        remediableCount += 1;
      } else if (values.size === 1 && values.has("no-fix")) {
        noFixCount += 1;
      } else if (values.size === 1 && values.has("unresolved")) {
        unresolvedCount += 1;
      } else {
        manualCount += 1;
      }
    }
    const analysisComplete =
      coverageComplete &&
      !dependencyLimitReached &&
      !vulnerabilityLimitReached &&
      !associationLimitReached &&
      !cancelled;
    const result: RemediationAnalysisResult = {
      recommendations: Object.freeze(recommendations),
      remediable: Object.freeze(remediable),
      noFix: Object.freeze(noFix),
      manualReview: Object.freeze(manualReview),
      unresolved: Object.freeze(unresolved),
      summary: Object.freeze({
        totalVulnerabilities,
        remediable: remediableCount,
        noKnownFix: noFixCount,
        manualReview: manualCount,
        unresolved: unresolvedCount,
        remediationCoveragePercent:
          totalVulnerabilities === 0
            ? 0
            : Math.floor((remediableCount * 100) / totalVulnerabilities),
        analysisComplete,
      }),
    };
    return Object.freeze(result);
  }
}
