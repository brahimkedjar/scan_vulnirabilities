import {
  dependencyIsResolved,
  dependencyManifestPath,
  type Dependency,
} from "../models/Dependency";
import type { ProjectCoverage, ScanResult } from "../models/ScanResult";
import type { Severity, Vulnerability } from "../models/Vulnerability";
import type {
  RemediationAnalysisResult,
  RemediationRecommendation,
} from "../remediation/RemediationModels";
import { dependencyOccurrenceKey } from "../remediation/DependencyPathAnalyzer";
import {
  type RetainedVulnerabilityFinding,
  type ScanCoverage,
  vulnerabilityFindingKey,
} from "../services/ScanResultStore";
import {
  countSuppressedVulnerabilities,
  scanCoverageIsComplete,
} from "../status/statusModel";
import type { VulnerabilityIdentity } from "../webview/vulnerabilityDetailsRenderer";
import type {
  RemediationApplySnapshot,
  RemediationCapabilityView,
} from "../webview/webviewTypes";

export type { VulnerabilityIdentity } from "../webview/vulnerabilityDetailsRenderer";

export type InformationIcon = "check" | "info" | "warning";

export interface InformationTreeNode {
  readonly kind: "information";
  readonly id: string;
  readonly label: string;
  readonly description?: string;
  readonly icon: InformationIcon;
}

export interface VulnerabilityTreeNode {
  readonly kind: "vulnerability";
  readonly id: string;
  readonly label: string;
  readonly description: string;
  readonly tooltip: string;
  readonly severity: Severity;
  readonly identity: VulnerabilityIdentity;
  readonly children: readonly InformationTreeNode[];
}

export interface DependencyTreeNode {
  readonly kind: "dependency";
  readonly id: string;
  readonly label: string;
  readonly description: string;
  readonly dependencyType: Dependency["dependencyType"] | "unknown";
  readonly detailsIdentity: VulnerabilityIdentity;
  readonly children: readonly (VulnerabilityTreeNode | InformationTreeNode)[];
}

export interface SeverityTreeNode {
  readonly kind: "severity";
  readonly id: string;
  readonly label: string;
  readonly severity: Severity;
  readonly count: number;
  readonly children: readonly (DependencyTreeNode | InformationTreeNode)[];
}

export interface EcosystemTreeNode {
  readonly kind: "ecosystem";
  readonly id: string;
  readonly label: string;
  readonly description: string;
  readonly ecosystem: string;
  readonly children: readonly (SeverityTreeNode | InformationTreeNode)[];
}

export interface WorkspaceTreeNode {
  readonly kind: "workspace";
  readonly id: string;
  readonly label: string;
  readonly description: string;
  readonly workspacePath: string;
  readonly projectPath: string;
  readonly children: readonly EcosystemTreeNode[];
}

export interface RetainedFindingsTreeNode {
  readonly kind: "retained-findings";
  readonly id: string;
  readonly label: string;
  readonly description: string;
  readonly count: number;
  readonly children: readonly (SeverityTreeNode | InformationTreeNode)[];
}

export type VulnerabilityTreeNodeModel =
  | WorkspaceTreeNode
  | RetainedFindingsTreeNode
  | EcosystemTreeNode
  | SeverityTreeNode
  | DependencyTreeNode
  | VulnerabilityTreeNode
  | InformationTreeNode;

export interface VulnerabilityTreeModel {
  readonly roots: readonly VulnerabilityTreeNodeModel[];
  readonly coverageComplete: boolean;
  readonly dependenciesScanned: number;
  readonly vulnerabilityCount: number;
  /** Finding-only evidence; excluded from current counts and coverage. */
  readonly retainedFindingCount: number;
  readonly suppressedVulnerabilityCount: number;
  readonly noKnownVulnerabilitiesCount: number;
}

export interface VulnerabilityTreeOptions {
  readonly hasWorkspace?: boolean;
  readonly latestAttemptCoverage?: ScanCoverage;
  readonly retainedFindings?: readonly RetainedVulnerabilityFinding[];
  readonly retainedFindingsTruncated?: boolean;
  readonly maximumDependenciesPerSeverity?: number;
  readonly maximumVulnerabilitiesPerDependency?: number;
  /** Current-scan analysis only; retained evidence is intentionally excluded. */
  readonly remediationAnalysis?: RemediationAnalysisResult;
  /** Session-only apply state keyed by exact recommendation identity. */
  readonly remediationApply?: RemediationApplySnapshot;
}

interface DependencyMetadata {
  readonly dependencies: Dependency[];
}

interface MutableDependencyGroup {
  readonly key: string;
  readonly workspacePath: string;
  readonly projectPath?: string;
  readonly includeOccurrenceIdentity?: boolean;
  readonly packageName: string;
  readonly ecosystem: string;
  readonly installedVersion: string;
  readonly metadata: DependencyMetadata | undefined;
  readonly vulnerabilities: Map<string, Vulnerability>;
}

interface MutablePhase4EcosystemGroup {
  readonly key: string;
  readonly workspacePath: string;
  readonly projectPath: string;
  readonly ecosystem: string;
  readonly packageManagers: Set<string>;
  readonly manifestPaths: Set<string>;
  readonly dependencies: Dependency[];
  readonly vulnerabilities: Map<string, Vulnerability>;
  discovered: number;
  resolved: number;
  checked: number;
  vulnerable: number;
  unresolved: number;
  unsupported: number;
}

interface MutablePhase4ProjectGroup {
  readonly key: string;
  readonly workspacePath: string;
  readonly projectPath: string;
  readonly ecosystems: Map<string, MutablePhase4EcosystemGroup>;
}

type RemediationLookup = ReadonlyMap<
  string,
  readonly RemediationRecommendation[]
>;

type RemediationCapabilityLookup = ReadonlyMap<
  string,
  RemediationCapabilityView
>;

const SEVERITY_ORDER: readonly Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "UNKNOWN",
];
const DEFAULT_MAXIMUM_DEPENDENCIES_PER_SEVERITY = 500;
const DEFAULT_MAXIMUM_VULNERABILITIES_PER_DEPENDENCY = 100;
const MAXIMUM_IDENTIFIERS = 20;
const MAXIMUM_DISPLAY_TEXT = 200;

function boundedLimit(value: number | undefined, fallback: number): number {
  if (value === undefined || !Number.isSafeInteger(value) || value < 1) {
    return fallback;
  }
  return Math.min(value, fallback);
}

function boundedSum(values: readonly number[]): number {
  let result = 0;
  for (const value of values) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      continue;
    }
    if (value > Number.MAX_SAFE_INTEGER - result) {
      return Number.MAX_SAFE_INTEGER;
    }
    result += value;
  }
  return result;
}

function compareText(left: string, right: string): number {
  const normalizedLeft = left.toLowerCase();
  const normalizedRight = right.toLowerCase();
  if (normalizedLeft < normalizedRight) {
    return -1;
  }
  if (normalizedLeft > normalizedRight) {
    return 1;
  }
  if (left < right) {
    return -1;
  }
  return left > right ? 1 : 0;
}

export function sanitizeTreeText(
  value: string,
  maximumLength = MAXIMUM_DISPLAY_TEXT,
): string {
  const singleLine = value
    .replace(/[\u202a-\u202e\u2066-\u2069]/gu, "")
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
  const nonempty = singleLine.length === 0 ? "(unnamed)" : singleLine;
  if (nonempty.length <= maximumLength) {
    return nonempty;
  }
  return `${nonempty.slice(0, Math.max(0, maximumLength - 1))}…`;
}

function coordinateKey(
  ecosystem: string,
  packageName: string,
  installedVersion: string,
): string {
  return JSON.stringify([ecosystem, packageName, installedVersion]);
}

function dependencyGroupKey(
  workspacePath: string,
  vulnerability: Vulnerability,
): string {
  return JSON.stringify([
    workspacePath,
    vulnerability.ecosystem,
    vulnerability.packageName,
    vulnerability.installedVersion,
  ]);
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

function buildRemediationLookup(
  analysis: RemediationAnalysisResult | undefined,
): RemediationLookup | undefined {
  if (analysis === undefined) {
    return undefined;
  }
  const lookup = new Map<string, RemediationRecommendation[]>();
  for (const recommendation of analysis.recommendations) {
    const dependencyPath = recommendation.dependency.dependencyPath ?? [];
    if (
      recommendation.currentVersion !==
        recommendation.dependency.installedVersion ||
      recommendation.dependencyPath.length !== dependencyPath.length ||
      !recommendation.dependencyPath.every(
        (segment, index) => segment === dependencyPath[index],
      )
    ) {
      continue;
    }
    const key = dependencyOccurrenceKey(recommendation.dependency);
    const existing = lookup.get(key);
    if (existing === undefined) {
      lookup.set(key, [recommendation]);
    } else {
      existing.push(recommendation);
    }
  }
  return lookup;
}

function buildRemediationCapabilityLookup(
  snapshot: RemediationApplySnapshot | undefined,
): RemediationCapabilityLookup | undefined {
  if (snapshot === undefined) {
    return undefined;
  }
  const lookup = new Map<string, RemediationCapabilityView>();
  for (const entry of snapshot.capabilities) {
    const current = lookup.get(entry.recommendationKey);
    if (current === undefined) {
      lookup.set(entry.recommendationKey, entry);
    } else if (current.capability !== entry.capability) {
      lookup.set(entry.recommendationKey, {
        recommendationKey: entry.recommendationKey,
        capability: "unsupported",
        reason: "Conflicting remediation capability records require manual review.",
      });
    }
  }
  return lookup;
}

function dependencyTypeFor(
  metadata: DependencyMetadata | undefined,
): Dependency["dependencyType"] | "unknown" {
  if (metadata === undefined) {
    return "unknown";
  }
  return metadata.dependencies.some(
    (dependency) => dependency.dependencyType === "direct",
  )
    ? "direct"
    : "transitive";
}

function environmentFor(metadata: DependencyMetadata | undefined): string {
  if (metadata === undefined) {
    return "Unknown origin";
  }
  const environments = new Set(
    metadata.dependencies.map((dependency) => dependency.environment),
  );
  const ordered = ["production", "optional", "development"].filter(
    (environment) => environments.has(environment as Dependency["environment"]),
  );
  return ordered.map((environment) => sanitizeTreeText(environment, 40)).join(", ");
}

function identifierPriority(identifier: string): number {
  if (/^GHSA-/iu.test(identifier)) {
    return 0;
  }
  if (/^CVE-/iu.test(identifier)) {
    return 1;
  }
  return 2;
}

function identifiersFor(vulnerability: Vulnerability): string[] {
  const identifiers = new Set([vulnerability.id, ...vulnerability.aliases]);
  return [...identifiers].sort((left, right) => {
    const priority = identifierPriority(left) - identifierPriority(right);
    return priority === 0 ? compareText(left, right) : priority;
  });
}

function primaryIdentifierFor(vulnerability: Vulnerability): string {
  let selected = vulnerability.id;
  for (const identifier of vulnerability.aliases) {
    const priority =
      identifierPriority(identifier) - identifierPriority(selected);
    if (
      priority < 0 ||
      (priority === 0 && compareText(identifier, selected) < 0)
    ) {
      selected = identifier;
    }
  }
  return selected;
}

function informationNode(
  id: string,
  label: string,
  icon: InformationIcon,
  description?: string,
): InformationTreeNode {
  return description === undefined
    ? { kind: "information", id, label, icon }
    : { kind: "information", id, label, description, icon };
}

function buildVulnerabilityNode(
  vulnerability: Vulnerability,
  group: MutableDependencyGroup,
  groupKey: string,
  index: number,
): VulnerabilityTreeNode {
  const identifiers = identifiersFor(vulnerability);
  const primaryIdentifier = identifiers[0] ?? vulnerability.id;
  const visibleIdentifiers = identifiers.slice(0, MAXIMUM_IDENTIFIERS);
  const children: InformationTreeNode[] = [];

  if (visibleIdentifiers.length > 1) {
    children.push(
      informationNode(
        `${groupKey}:vulnerability:${index.toString()}:identifiers`,
        `Identifiers: ${sanitizeTreeText(visibleIdentifiers.join(", "))}`,
        "info",
      ),
    );
  }
  if (identifiers.length > visibleIdentifiers.length) {
    children.push(
      informationNode(
        `${groupKey}:vulnerability:${index.toString()}:identifier-limit`,
        `${(identifiers.length - visibleIdentifiers.length).toString()} additional identifiers omitted`,
        "info",
      ),
    );
  }
  if (vulnerability.fixedVersion !== undefined) {
    children.push(
      informationNode(
        `${groupKey}:vulnerability:${index.toString()}:fixed`,
        `Fixed: ${sanitizeTreeText(vulnerability.fixedVersion)}`,
        "check",
      ),
    );
  }
  children.push(
    informationNode(
      `${groupKey}:vulnerability:${index.toString()}:source`,
      `Source: ${sanitizeTreeText(vulnerability.source)}`,
      "info",
    ),
  );

  const summary = sanitizeTreeText(vulnerability.summary, 120);
  return {
    kind: "vulnerability",
    id: `${groupKey}:vulnerability:${vulnerabilityKey(vulnerability)}`,
    label: sanitizeTreeText(primaryIdentifier),
    description:
      vulnerability.fixedVersion === undefined
        ? vulnerability.severity
        : `Fixed in ${sanitizeTreeText(vulnerability.fixedVersion, 80)}`,
    tooltip: `${sanitizeTreeText(primaryIdentifier)} — ${summary}`,
    severity: vulnerability.severity,
    identity: vulnerabilityIdentity(vulnerability, group),
    children,
  };
}

function uniqueDependencyPath(
  metadata: DependencyMetadata | undefined,
): readonly string[] | undefined {
  const paths = new Map<string, readonly string[]>();
  for (const dependency of metadata?.dependencies ?? []) {
    if (dependency.dependencyPath !== undefined) {
      paths.set(JSON.stringify(dependency.dependencyPath), dependency.dependencyPath);
    }
  }
  return paths.size === 1 ? paths.values().next().value : undefined;
}

function uniqueProjectPath(
  group: MutableDependencyGroup,
): string | undefined {
  if (group.projectPath !== undefined) {
    return group.projectPath;
  }
  const paths = new Set(
    (group.metadata?.dependencies ?? []).flatMap((dependency) =>
      dependency.projectPath === undefined ? [] : [dependency.projectPath],
    ),
  );
  return paths.size === 1 ? [...paths][0] : undefined;
}

function uniqueManifestPath(
  metadata: DependencyMetadata | undefined,
): string | undefined {
  const paths = new Set(
    (metadata?.dependencies ?? []).flatMap((dependency) => {
      const manifestPath = dependencyManifestPath(dependency);
      return manifestPath === undefined ? [] : [manifestPath];
    }),
  );
  return paths.size === 1 ? [...paths][0] : undefined;
}

function vulnerabilityIdentity(
  vulnerability: Vulnerability,
  group: MutableDependencyGroup,
): VulnerabilityIdentity {
  const projectPath = group.includeOccurrenceIdentity === true
    ? uniqueProjectPath(group)
    : undefined;
  const manifestPath = group.includeOccurrenceIdentity === true
    ? uniqueManifestPath(group.metadata)
    : undefined;
  const dependencyPath = group.includeOccurrenceIdentity === true
    ? uniqueDependencyPath(group.metadata)
    : undefined;
  return {
    workspacePath: group.workspacePath,
    ...(projectPath === undefined ? {} : { projectPath }),
    ...(manifestPath === undefined ? {} : { manifestPath }),
    ...(dependencyPath === undefined ? {} : { dependencyPath }),
    source: vulnerability.source,
    vulnerabilityId: vulnerability.id,
    ecosystem: vulnerability.ecosystem,
    packageName: vulnerability.packageName,
    installedVersion: vulnerability.installedVersion,
  };
}

function remediationRecommendationsFor(
  group: MutableDependencyGroup,
  lookup: RemediationLookup | undefined,
): readonly RemediationRecommendation[] {
  if (lookup === undefined) {
    return [];
  }
  const vulnerabilityIds = new Set(
    [...group.vulnerabilities.values()].map((vulnerability) => vulnerability.id),
  );
  const dependencyOccurrences = group.metadata?.dependencies ?? [];
  if (dependencyOccurrences.length === 0) {
    return [];
  }
  const selected = new Map<string, RemediationRecommendation>();
  const occurrenceKeys = new Set(
    dependencyOccurrences.map(dependencyOccurrenceKey),
  );
  for (const occurrenceKey of occurrenceKeys) {
    for (const recommendation of lookup.get(occurrenceKey) ?? []) {
      if (
        recommendation.vulnerabilityIds.some((identifier) =>
          vulnerabilityIds.has(identifier),
        )
      ) {
        selected.set(recommendation.recommendationKey, recommendation);
      }
    }
  }
  return [...selected.values()];
}

function remediationTreeNode(
  group: MutableDependencyGroup,
  lookup: RemediationLookup | undefined,
  capabilityLookup: RemediationCapabilityLookup | undefined,
  applySnapshot: RemediationApplySnapshot | undefined,
): InformationTreeNode | undefined {
  const recommendations = remediationRecommendationsFor(group, lookup);
  if (recommendations.length === 0) {
    return undefined;
  }
  if (recommendations.length !== 1) {
    return informationNode(
      `${group.key}:remediation`,
      "Manual review required",
      "warning",
      "Multiple dependency occurrences or remediation candidates match this grouped tree item.",
    );
  }
  const targets = new Set(
    recommendations.flatMap((recommendation) =>
      recommendation.recommendedVersion === undefined
        ? []
        : [recommendation.recommendedVersion],
    ),
  );
  const allRemediable = recommendations.every(
    (recommendation) =>
      recommendation.recommendedVersion !== undefined &&
      (recommendation.strategy === "upgrade-direct" ||
        recommendation.strategy === "upgrade-parent" ||
        recommendation.strategy === "upgrade-transitive"),
  );
  if (allRemediable && targets.size === 1) {
    const target = sanitizeTreeText([...targets][0] ?? "", 80);
    const recommendation = recommendations[0];
    if (recommendation === undefined) {
      return undefined;
    }
    const capability = capabilityLookup?.get(
      recommendation.recommendationKey,
    );
    const matchingOperation =
      applySnapshot?.activeOperation?.recommendationKey ===
      recommendation.recommendationKey
        ? applySnapshot.activeOperation
        : undefined;
    if (matchingOperation !== undefined) {
      const operationLabels: Readonly<
        Record<typeof matchingOperation.stage, string>
      > = {
        previewing: "Preparing remediation preview",
        "preview-ready": "Remediation preview ready",
        applying: "Applying approved remediation",
        validating: "Validating remediation",
        rescanning: "Rescanning after remediation",
        "rolling-back": "Rolling back remediation",
      };
      return informationNode(
        `${group.key}:remediation`,
        operationLabels[matchingOperation.stage],
        matchingOperation.stage === "rolling-back" ? "warning" : "info",
        sanitizeTreeText(
          matchingOperation.message ??
            "A user-initiated remediation operation is in progress.",
          180,
        ),
      );
    }
    const matchingPreview =
      applySnapshot?.preview?.recommendationKey ===
      recommendation.recommendationKey
        ? applySnapshot.preview
        : undefined;
    if (matchingPreview !== undefined) {
      return informationNode(
        `${group.key}:remediation`,
        matchingPreview.valid
          ? matchingPreview.capability === "safe"
            ? `Fix preview ready → ${target}`
            : `Remediation preview available → ${target}`
          : "Remediation preview expired",
        matchingPreview.valid ? "info" : "warning",
        matchingPreview.valid
          ? "Review the actual diff. Applying a safe remediation still requires explicit approval."
          : "Generate a new preview before attempting remediation.",
      );
    }
    if (capability !== undefined) {
      if (capability.capability === "safe") {
        return informationNode(
          `${group.key}:remediation`,
          `✓ Remediation available → ${target}`,
          "check",
          "Review a deterministic preview before explicitly approving any file modification.",
        );
      }
      if (capability.capability === "preview-only") {
        return informationNode(
          `${group.key}:remediation`,
          `Review remediation → ${target}`,
          "warning",
          sanitizeTreeText(capability.reason, 180),
        );
      }
      return informationNode(
        `${group.key}:remediation`,
        "Manual review required",
        "warning",
        sanitizeTreeText(capability.reason, 180),
      );
    }
    const parentOnly = recommendation.strategy === "upgrade-parent";
    return informationNode(
      `${group.key}:remediation`,
      parentOnly
        ? `Review parent → resolves to ${target}`
        : `Recommended upgrade → ${target}`,
      "check",
      "Remediation candidate from current provider and dependency-graph evidence; no files are changed.",
    );
  }
  if (
    recommendations.every(
      (recommendation) => recommendation.strategy === "no-fixed-version",
    )
  ) {
    return informationNode(
      `${group.key}:remediation`,
      "No known fixed version",
      "warning",
      "The configured provider did not supply a fixed version; this is not a claim that the latest release is safe.",
    );
  }
  return informationNode(
    `${group.key}:remediation`,
    "Manual review required",
    "warning",
    sanitizeTreeText(
      recommendations[0]?.reason ??
        "No single remediation candidate could be established.",
      180,
    ),
  );
}

function buildDependencyNode(
  group: MutableDependencyGroup,
  maximumVulnerabilities: number,
  remediationLookup?: RemediationLookup,
  remediationCapabilityLookup?: RemediationCapabilityLookup,
  remediationApply?: RemediationApplySnapshot,
): DependencyTreeNode {
  const dependencyType = dependencyTypeFor(group.metadata);
  const vulnerabilities = [...group.vulnerabilities.values()]
    .map((vulnerability) => ({
      vulnerability,
      primaryIdentifier: primaryIdentifierFor(vulnerability),
    }))
    .sort((left, right) => {
      const identifierComparison = compareText(
        left.primaryIdentifier,
        right.primaryIdentifier,
      );
      return identifierComparison === 0
        ? compareText(left.vulnerability.id, right.vulnerability.id)
        : identifierComparison;
    });
  const visible = vulnerabilities.slice(0, maximumVulnerabilities);
  const children: Array<VulnerabilityTreeNode | InformationTreeNode> = visible.map(
    ({ vulnerability }, index) =>
      buildVulnerabilityNode(
        vulnerability,
        group,
        group.key,
        index,
      ),
  );
  if (visible.length < vulnerabilities.length) {
    children.push(
      informationNode(
        `${group.key}:vulnerability-limit`,
        `${(vulnerabilities.length - visible.length).toString()} additional vulnerabilities omitted from the tree`,
        "warning",
      ),
    );
  }
  const remediationNode = remediationTreeNode(
    group,
    remediationLookup,
    remediationCapabilityLookup,
    remediationApply,
  );
  if (remediationNode !== undefined) {
    children.push(remediationNode);
  }

  const dependencyTypeLabel =
    dependencyType === "unknown"
      ? "Unknown dependency type"
      : `${dependencyType[0]?.toUpperCase() ?? ""}${dependencyType.slice(1)}`;
  const firstVulnerability = visible[0]?.vulnerability;
  if (firstVulnerability === undefined) {
    throw new Error("A vulnerable dependency group must contain a vulnerability");
  }
  return {
    kind: "dependency",
    id: `${group.key}:dependency`,
    label: `${sanitizeTreeText(group.packageName)}@${sanitizeTreeText(group.installedVersion, 80)}`,
    description: `${dependencyTypeLabel} · ${environmentFor(group.metadata)}`,
    dependencyType,
    detailsIdentity: vulnerabilityIdentity(firstVulnerability, group),
    children,
  };
}

function severityLabel(severity: Severity): string {
  return `${severity[0] ?? ""}${severity.slice(1).toLowerCase()}`;
}

function providerUnavailable(results: readonly ScanResult[]): boolean {
  const providers = results.flatMap((result) => result.providerResults);
  return (
    providers.length > 0 &&
    providers.every((provider) => provider.status === "unavailable")
  );
}

function addBounded(left: number, right: number): number {
  return boundedSum([left, right]);
}

function pathLabel(path: string): string {
  const normalized = path.replaceAll("\\", "/").replace(/\/+$/u, "");
  return sanitizeTreeText(normalized.split("/").at(-1) ?? normalized, 80);
}

function ecosystemDisplayLabel(group: MutablePhase4EcosystemGroup): string {
  switch (group.ecosystem) {
    case "PyPI":
      return "Python";
    case "crates.io":
      return "Cargo";
    case "Packagist":
      return "Composer";
    case "Maven":
      return group.packageManagers.has("gradle") &&
        !group.packageManagers.has("maven")
        ? "Gradle"
        : "Maven";
    default:
      return group.ecosystem;
  }
}

function syntheticProjectCoverage(result: ScanResult): readonly ProjectCoverage[] {
  if (result.ecosystemCoverage !== undefined) {
    return result.ecosystemCoverage.map((coverage) => ({
      ...coverage,
      workspacePath: result.workspacePath,
      projectPath: result.workspacePath,
      manifestPaths: [],
    }));
  }
  const ecosystems = new Map<string, Dependency[]>();
  for (const dependency of result.dependencies) {
    const entries = ecosystems.get(dependency.ecosystem) ?? [];
    entries.push(dependency);
    ecosystems.set(dependency.ecosystem, entries);
  }
  return [...ecosystems].map(([ecosystem, dependencies]) => ({
    ecosystem,
    packageManagers: result.packageManagers,
    workspacePath: result.workspacePath,
    projectPath: result.workspacePath,
    manifestPaths: [
      ...new Set(
        dependencies.flatMap((dependency) => {
          const manifestPath = dependencyManifestPath(dependency);
          return manifestPath === undefined ? [] : [manifestPath];
        }),
      ),
    ],
    discovered: dependencies.length,
    resolved: dependencies.filter(dependencyIsResolved).length,
    checked: 0,
    vulnerable: new Set(
      result.vulnerabilities
        .filter((vulnerability) => vulnerability.ecosystem === ecosystem)
        .map((vulnerability) =>
          coordinateKey(
            vulnerability.ecosystem,
            vulnerability.packageName,
            vulnerability.installedVersion,
          ),
        ),
    ).size,
    unresolved: dependencies.filter(
      (dependency) => dependency.resolutionStatus === "unresolved",
    ).length,
    unsupported: dependencies.filter(
      (dependency) => dependency.resolutionStatus === "unsupported",
    ).length,
  }));
}

function coverageForPhase4Result(result: ScanResult): readonly ProjectCoverage[] {
  return result.projectCoverage ?? syntheticProjectCoverage(result);
}

function dependencyMatchesProject(
  dependency: Dependency,
  coverage: ProjectCoverage,
  ecosystemProjectCount: number,
): boolean {
  if (dependency.ecosystem !== coverage.ecosystem) {
    return false;
  }
  if (
    dependency.packageManager !== undefined &&
    !coverage.packageManagers.includes(dependency.packageManager)
  ) {
    return false;
  }
  if (dependency.projectPath !== undefined) {
    return dependency.projectPath === coverage.projectPath;
  }
  const manifestPath = dependencyManifestPath(dependency);
  if (manifestPath !== undefined && coverage.manifestPaths.includes(manifestPath)) {
    return true;
  }
  return ecosystemProjectCount === 1;
}

function collectPhase4Projects(
  results: readonly ScanResult[],
): readonly MutablePhase4ProjectGroup[] {
  const projects = new Map<string, MutablePhase4ProjectGroup>();
  for (const result of results) {
    const coverages = coverageForPhase4Result(result);
    const groupsForResult: Array<{
      readonly coverage: ProjectCoverage;
      readonly group: MutablePhase4EcosystemGroup;
    }> = [];
    for (const coverage of coverages) {
      const projectKey = JSON.stringify([
        coverage.workspacePath,
        coverage.projectPath,
      ]);
      let project = projects.get(projectKey);
      if (project === undefined) {
        project = {
          key: projectKey,
          workspacePath: coverage.workspacePath,
          projectPath: coverage.projectPath,
          ecosystems: new Map(),
        };
        projects.set(projectKey, project);
      }
      let group = project.ecosystems.get(coverage.ecosystem);
      if (group === undefined) {
        group = {
          key: JSON.stringify([
            coverage.workspacePath,
            coverage.projectPath,
            coverage.ecosystem,
          ]),
          workspacePath: coverage.workspacePath,
          projectPath: coverage.projectPath,
          ecosystem: coverage.ecosystem,
          packageManagers: new Set(),
          manifestPaths: new Set(),
          dependencies: [],
          vulnerabilities: new Map(),
          discovered: 0,
          resolved: 0,
          checked: 0,
          vulnerable: 0,
          unresolved: 0,
          unsupported: 0,
        };
        project.ecosystems.set(coverage.ecosystem, group);
      }
      for (const packageManager of coverage.packageManagers) {
        group.packageManagers.add(packageManager);
      }
      for (const manifestPath of coverage.manifestPaths) {
        group.manifestPaths.add(manifestPath);
      }
      group.discovered = addBounded(group.discovered, coverage.discovered);
      group.resolved = addBounded(group.resolved, coverage.resolved);
      group.checked = addBounded(group.checked, coverage.checked);
      group.vulnerable = addBounded(group.vulnerable, coverage.vulnerable);
      group.unresolved = addBounded(group.unresolved, coverage.unresolved);
      group.unsupported = addBounded(group.unsupported, coverage.unsupported);
      groupsForResult.push({ coverage, group });
    }

    const projectCountByEcosystem = new Map<string, number>();
    for (const { coverage } of groupsForResult) {
      projectCountByEcosystem.set(
        coverage.ecosystem,
        (projectCountByEcosystem.get(coverage.ecosystem) ?? 0) + 1,
      );
    }
    for (const dependency of result.dependencies) {
      const count = projectCountByEcosystem.get(dependency.ecosystem) ?? 0;
      for (const candidate of groupsForResult) {
        if (dependencyMatchesProject(dependency, candidate.coverage, count)) {
          candidate.group.dependencies.push(dependency);
        }
      }
    }
    for (const vulnerability of result.vulnerabilities) {
      const matchingDependencies = result.dependencies.filter(
        (dependency) =>
          dependency.ecosystem === vulnerability.ecosystem &&
          dependency.name === vulnerability.packageName &&
          dependency.installedVersion === vulnerability.installedVersion,
      );
      const targetGroups = new Set<MutablePhase4EcosystemGroup>();
      const count = projectCountByEcosystem.get(vulnerability.ecosystem) ?? 0;
      for (const candidate of groupsForResult) {
        if (candidate.coverage.ecosystem !== vulnerability.ecosystem) {
          continue;
        }
        if (
          matchingDependencies.some((dependency) =>
            dependencyMatchesProject(dependency, candidate.coverage, count),
          ) ||
          (matchingDependencies.length === 0 && count === 1)
        ) {
          targetGroups.add(candidate.group);
        }
      }
      for (const group of targetGroups) {
        group.vulnerabilities.set(vulnerabilityKey(vulnerability), vulnerability);
      }
    }
  }
  return [...projects.values()].sort((left, right) => {
    const labelComparison = compareText(
      pathLabel(left.projectPath),
      pathLabel(right.projectPath),
    );
    return labelComparison === 0
      ? compareText(left.projectPath, right.projectPath)
      : labelComparison;
  });
}

function buildPhase4SeverityNodes(
  group: MutablePhase4EcosystemGroup,
  maximumDependencies: number,
  maximumVulnerabilities: number,
  remediationLookup?: RemediationLookup,
  remediationCapabilityLookup?: RemediationCapabilityLookup,
  remediationApply?: RemediationApplySnapshot,
): SeverityTreeNode[] {
  const metadataByCoordinate = new Map<string, DependencyMetadata>();
  for (const dependency of group.dependencies) {
    const key = coordinateKey(
      dependency.ecosystem,
      dependency.name,
      dependency.installedVersion,
    );
    const metadata = metadataByCoordinate.get(key);
    if (metadata === undefined) {
      metadataByCoordinate.set(key, { dependencies: [dependency] });
    } else {
      metadata.dependencies.push(dependency);
    }
  }
  const bySeverity = new Map<Severity, Map<string, MutableDependencyGroup>>(
    SEVERITY_ORDER.map((severity) => [severity, new Map()]),
  );
  for (const vulnerability of group.vulnerabilities.values()) {
    const severityGroups = bySeverity.get(vulnerability.severity);
    if (severityGroups === undefined) {
      continue;
    }
    const key = JSON.stringify([
      group.key,
      vulnerability.ecosystem,
      vulnerability.packageName,
      vulnerability.installedVersion,
    ]);
    let dependencyGroup = severityGroups.get(key);
    if (dependencyGroup === undefined) {
      dependencyGroup = {
        key,
        workspacePath: group.workspacePath,
        projectPath: group.projectPath,
        includeOccurrenceIdentity: true,
        packageName: vulnerability.packageName,
        ecosystem: vulnerability.ecosystem,
        installedVersion: vulnerability.installedVersion,
        metadata: metadataByCoordinate.get(
          coordinateKey(
            vulnerability.ecosystem,
            vulnerability.packageName,
            vulnerability.installedVersion,
          ),
        ),
        vulnerabilities: new Map(),
      };
      severityGroups.set(key, dependencyGroup);
    }
    dependencyGroup.vulnerabilities.set(
      vulnerabilityKey(vulnerability),
      vulnerability,
    );
  }

  const output: SeverityTreeNode[] = [];
  for (const severity of SEVERITY_ORDER) {
    const severityGroups = bySeverity.get(severity);
    if (severityGroups === undefined || severityGroups.size === 0) {
      continue;
    }
    const dependencyGroups = [...severityGroups.values()].sort((left, right) => {
      const name = compareText(left.packageName, right.packageName);
      return name === 0
        ? compareText(left.installedVersion, right.installedVersion)
        : name;
    });
    const visible = dependencyGroups.slice(0, maximumDependencies);
    const children: Array<DependencyTreeNode | InformationTreeNode> = visible.map(
      (dependencyGroup) =>
        buildDependencyNode(
          dependencyGroup,
          maximumVulnerabilities,
          remediationLookup,
          remediationCapabilityLookup,
          remediationApply,
        ),
    );
    if (visible.length < dependencyGroups.length) {
      children.push(
        informationNode(
          `${group.key}:severity:${severity}:dependency-limit`,
          `${(dependencyGroups.length - visible.length).toString()} additional vulnerable dependencies omitted from the tree`,
          "warning",
        ),
      );
    }
    output.push({
      kind: "severity",
      id: `${group.key}:severity:${severity}`,
      label: `${severityLabel(severity)} (${boundedSum(
        dependencyGroups.map(
          (dependencyGroup) => dependencyGroup.vulnerabilities.size,
        ),
      ).toString()})`,
      severity,
      count: boundedSum(
        dependencyGroups.map(
          (dependencyGroup) => dependencyGroup.vulnerabilities.size,
        ),
      ),
      children,
    });
  }
  return output;
}

function buildPhase4Roots(
  results: readonly ScanResult[],
  maximumDependencies: number,
  maximumVulnerabilities: number,
  remediationLookup?: RemediationLookup,
  remediationCapabilityLookup?: RemediationCapabilityLookup,
  remediationApply?: RemediationApplySnapshot,
): WorkspaceTreeNode[] {
  return collectPhase4Projects(results).map((project) => {
    const ecosystemNodes = [...project.ecosystems.values()]
      .sort((left, right) => compareText(left.ecosystem, right.ecosystem))
      .map((group): EcosystemTreeNode => {
        const severityNodes = buildPhase4SeverityNodes(
          group,
          maximumDependencies,
          maximumVulnerabilities,
          remediationLookup,
          remediationCapabilityLookup,
          remediationApply,
        );
        const children: Array<SeverityTreeNode | InformationTreeNode> = [
          ...severityNodes,
        ];
        const noKnownCount = Math.max(0, group.checked - group.vulnerable);
        if (group.checked === 0 && group.discovered > 0) {
          children.push(
            informationNode(
              `${group.key}:none-checked`,
              `No Dependencies Checked (0 of ${group.discovered.toString()})`,
              "warning",
              "Zero findings is not a clean result when no discovered dependency was checked.",
            ),
          );
        } else {
          const complete =
            group.unresolved === 0 &&
            group.unsupported === 0 &&
            group.checked >= group.resolved;
          children.push(
            informationNode(
              `${group.key}:no-known`,
              `No Known Vulnerabilities (${noKnownCount.toString()})`,
              complete ? "check" : "info",
              complete
                ? "Checked dependencies without a known finding from the configured provider."
                : "Checked dependencies without a known finding; ecosystem coverage remains incomplete.",
            ),
          );
        }
        if (group.unresolved > 0) {
          children.push(
            informationNode(
              `${group.key}:unresolved`,
              `Unresolved Dependencies (${group.unresolved.toString()})`,
              "warning",
              "No exact installed version was available, so these dependencies were not checked.",
            ),
          );
        }
        if (group.unsupported > 0) {
          children.push(
            informationNode(
              `${group.key}:unsupported`,
              `Unsupported Dependencies (${group.unsupported.toString()})`,
              "warning",
              "These dependencies could not be mapped safely to the configured provider.",
            ),
          );
        }
        return {
          kind: "ecosystem",
          id: `${group.key}:ecosystem`,
          label: sanitizeTreeText(ecosystemDisplayLabel(group), 80),
          description: `${group.vulnerabilities.size.toString()} findings · ${group.checked.toString()}/${group.discovered.toString()} checked`,
          ecosystem: group.ecosystem,
          children,
        };
      });
    return {
      kind: "workspace",
      id: `${project.key}:workspace`,
      label: `Workspace: ${pathLabel(project.projectPath)}`,
      description:
        project.projectPath === project.workspacePath
          ? `${ecosystemNodes.length.toString()} ecosystem${ecosystemNodes.length === 1 ? "" : "s"}`
          : sanitizeTreeText(project.projectPath, 120),
      workspacePath: project.workspacePath,
      projectPath: project.projectPath,
      children: ecosystemNodes,
    };
  });
}

function buildRetainedFindingsRoot(
  results: readonly ScanResult[],
  retainedFindings: readonly RetainedVulnerabilityFinding[],
  truncated: boolean,
  maximumDependencies: number,
  maximumVulnerabilities: number,
): RetainedFindingsTreeNode | undefined {
  const currentKeys = new Set(
    results.flatMap((result) =>
      result.vulnerabilities.map(vulnerabilityFindingKey),
    ),
  );
  const retainedByKey = new Map<string, RetainedVulnerabilityFinding>();
  for (const finding of retainedFindings) {
    const key = vulnerabilityFindingKey(finding.vulnerability);
    if (!currentKeys.has(key) && !retainedByKey.has(key)) {
      retainedByKey.set(key, finding);
    }
  }
  if (retainedByKey.size === 0 && !truncated) {
    return undefined;
  }

  const bySeverity = new Map<Severity, Map<string, MutableDependencyGroup>>(
    SEVERITY_ORDER.map((severity) => [severity, new Map()]),
  );
  for (const finding of retainedByKey.values()) {
    const vulnerability = finding.vulnerability;
    const severityGroups = bySeverity.get(vulnerability.severity);
    if (severityGroups === undefined) {
      continue;
    }
    const coordinate = coordinateKey(
      vulnerability.ecosystem,
      vulnerability.packageName,
      vulnerability.installedVersion,
    );
    const key = JSON.stringify(["retained", vulnerability.severity, coordinate]);
    let group = severityGroups.get(key);
    if (group === undefined) {
      const matchingDependencies = finding.dependencies.filter(
        (dependency) =>
          coordinateKey(
            dependency.ecosystem,
            dependency.name,
            dependency.installedVersion,
          ) === coordinate,
      );
      group = {
        key,
        workspacePath:
          matchingDependencies[0]?.workspacePath ??
          finding.workspacePaths[0] ??
          "",
        packageName: vulnerability.packageName,
        ecosystem: vulnerability.ecosystem,
        installedVersion: vulnerability.installedVersion,
        metadata:
          matchingDependencies.length === 0
            ? undefined
            : { dependencies: [...matchingDependencies] },
        vulnerabilities: new Map(),
      };
      severityGroups.set(key, group);
    }
    group.vulnerabilities.set(vulnerabilityKey(vulnerability), vulnerability);
  }

  const children: Array<SeverityTreeNode | InformationTreeNode> = [];
  for (const severity of SEVERITY_ORDER) {
    const severityGroups = bySeverity.get(severity);
    if (severityGroups === undefined || severityGroups.size === 0) {
      continue;
    }
    const groups = [...severityGroups.values()].sort((left, right) => {
      const name = compareText(left.packageName, right.packageName);
      return name === 0
        ? compareText(left.installedVersion, right.installedVersion)
        : name;
    });
    const visible = groups.slice(0, maximumDependencies);
    const severityChildren: Array<DependencyTreeNode | InformationTreeNode> =
      visible.map((group) =>
        buildDependencyNode(group, maximumVulnerabilities),
      );
    if (visible.length < groups.length) {
      severityChildren.push(
        informationNode(
          `retained:severity:${severity}:dependency-limit`,
          `${(groups.length - visible.length).toString()} additional retained dependencies omitted from the tree`,
          "warning",
        ),
      );
    }
    const count = boundedSum(
      groups.map((group) => group.vulnerabilities.size),
    );
    children.push({
      kind: "severity",
      id: `retained:severity:${severity}`,
      label: `${severityLabel(severity)} (${count.toString()})`,
      severity,
      count,
      children: severityChildren,
    });
  }
  if (truncated) {
    children.push(
      informationNode(
        "retained:limit",
        "Additional last-complete findings were omitted from this bounded view.",
        "warning",
      ),
    );
  }
  return {
    kind: "retained-findings",
    id: "retained:last-complete",
    label: `Last Complete Scan Findings (${retainedByKey.size.toString()})`,
    description: "Not reconfirmed by the current incomplete scan",
    count: retainedByKey.size,
    children,
  };
}

function appendManualReviewSummary(
  roots: VulnerabilityTreeNodeModel[],
  analysis: RemediationAnalysisResult | undefined,
  vulnerabilityCount: number,
): void {
  if (analysis === undefined || vulnerabilityCount === 0) {
    return;
  }
  const count = Math.min(
    vulnerabilityCount,
    boundedSum([analysis.summary.manualReview]),
  );
  if (count === 0) {
    return;
  }
  roots.push(
    informationNode(
      "remediation:manual-review",
      `Manual Review (${count.toString()})`,
      "warning",
      "Current displayed findings for which no automatic remediation candidate was established; Phase 5A does not change files.",
    ),
  );
}

export function buildVulnerabilityTreeModel(
  results: readonly ScanResult[],
  options: VulnerabilityTreeOptions = {},
): VulnerabilityTreeModel {
  const hasWorkspace = options.hasWorkspace ?? true;
  const maximumDependencies = boundedLimit(
    options.maximumDependenciesPerSeverity,
    DEFAULT_MAXIMUM_DEPENDENCIES_PER_SEVERITY,
  );
  const maximumVulnerabilities = boundedLimit(
    options.maximumVulnerabilitiesPerDependency,
    DEFAULT_MAXIMUM_VULNERABILITIES_PER_DEPENDENCY,
  );
  const remediationLookup = buildRemediationLookup(
    options.remediationAnalysis,
  );
  const remediationCapabilityLookup = buildRemediationCapabilityLookup(
    options.remediationApply,
  );
  const retainedRoot = buildRetainedFindingsRoot(
    results,
    options.retainedFindings ?? [],
    options.retainedFindingsTruncated === true,
    maximumDependencies,
    maximumVulnerabilities,
  );
  const retainedFindingCount = retainedRoot?.count ?? 0;
  const dependenciesScanned = boundedSum(
    results.map((result) => result.dependenciesScanned),
  );
  const vulnerabilityCount = boundedSum(
    results.map((result) => result.vulnerabilities.length),
  );
  const suppressedVulnerabilityCount =
    countSuppressedVulnerabilities(results);
  const vulnerableDependencies = boundedSum(
    results.map((result) =>
      Math.min(result.dependenciesScanned, result.vulnerableDependencies),
    ),
  );
  const phase4CoveragePresent = results.some(
    (result) => result.projectCoverage !== undefined,
  );
  const phase4Discovered = boundedSum(
    results.flatMap((result) =>
      coverageForPhase4Result(result).map((coverage) => coverage.discovered),
    ),
  );
  const noKnownVulnerabilitiesCount = phase4CoveragePresent
    ? boundedSum(
        results.flatMap((result) =>
          coverageForPhase4Result(result).map((coverage) =>
            Math.max(0, coverage.checked - coverage.vulnerable),
          ),
        ),
      )
    : Math.max(0, dependenciesScanned - vulnerableDependencies);
  const latestAttemptCancelled =
    options.latestAttemptCoverage === "cancelled";
  const coverageComplete = scanCoverageIsComplete(
    results,
    options.latestAttemptCoverage,
  );
  const emptyModel = (
    root: InformationTreeNode,
    includeRetained = true,
  ): VulnerabilityTreeModel => ({
    roots:
      includeRetained && retainedRoot !== undefined
        ? [root, retainedRoot]
        : [root],
    coverageComplete,
    dependenciesScanned,
    vulnerabilityCount,
    retainedFindingCount,
    suppressedVulnerabilityCount,
    noKnownVulnerabilitiesCount,
  });

  if (!hasWorkspace) {
    return emptyModel(
      informationNode(
        "state:no-workspace",
        "No workspace is open.",
        "info",
      ),
      false,
    );
  }
  if (latestAttemptCancelled && results.length === 0) {
    return emptyModel(
      informationNode(
        "state:scan-cancelled",
        "Dependency scan cancelled.",
        "warning",
        "No new scan results are available.",
      ),
    );
  }
  if (results.length === 0) {
    return emptyModel(
      informationNode(
        "state:not-scanned",
        "No dependency scan results yet.",
        "info",
        "Run Scan Workspace to inspect resolved dependencies.",
      ),
    );
  }
  if (latestAttemptCancelled && dependenciesScanned === 0) {
    return emptyModel(
      informationNode(
        "state:scan-cancelled",
        "Dependency scan cancelled.",
        "warning",
        "No new scan results are available.",
      ),
    );
  }
  if (
    dependenciesScanned === 0 &&
    (!phase4CoveragePresent || phase4Discovered === 0)
  ) {
    return emptyModel(
      informationNode(
        "state:no-dependencies",
        "No supported dependency files were found.",
        "info",
      ),
    );
  }

  const roots: VulnerabilityTreeNodeModel[] = [];
  if (!coverageComplete) {
    roots.push(
      informationNode(
        "state:coverage-incomplete",
        latestAttemptCancelled
          ? "Dependency scan cancelled."
          : options.latestAttemptCoverage === "unavailable" ||
          providerUnavailable(results)
            ? "Vulnerability database unavailable."
            : "Dependency scan coverage is incomplete.",
        "warning",
        latestAttemptCancelled
          ? "Showing results retained from the previous usable scan."
          : "Reported findings may not represent every discovered dependency.",
      ),
    );
  }

  if (phase4CoveragePresent) {
    roots.push(
      ...buildPhase4Roots(
        results,
        maximumDependencies,
        maximumVulnerabilities,
        remediationLookup,
        remediationCapabilityLookup,
        options.remediationApply,
      ),
    );
    if (suppressedVulnerabilityCount > 0) {
      roots.push(
        informationNode(
          "state:severity-filtered-findings",
          `Known Findings Hidden by Severity Filter (${suppressedVulnerabilityCount.toString()})`,
          "warning",
          "Change the minimum severity setting to control which known findings are displayed.",
        ),
      );
    }
    appendManualReviewSummary(
      roots,
      options.remediationAnalysis,
      vulnerabilityCount,
    );
    if (retainedRoot !== undefined) {
      roots.push(retainedRoot);
    }
    return {
      roots,
      coverageComplete,
      dependenciesScanned,
      vulnerabilityCount,
      retainedFindingCount,
      suppressedVulnerabilityCount,
      noKnownVulnerabilitiesCount,
    };
  }

  const groupsBySeverity = new Map<Severity, Map<string, MutableDependencyGroup>>(
    SEVERITY_ORDER.map((severity) => [severity, new Map()]),
  );
  for (const result of results) {
    const metadataByCoordinate = new Map<string, DependencyMetadata>();
    for (const dependency of result.dependencies) {
      const key = coordinateKey(
        dependency.ecosystem,
        dependency.name,
        dependency.installedVersion,
      );
      const metadata = metadataByCoordinate.get(key);
      if (metadata === undefined) {
        metadataByCoordinate.set(key, { dependencies: [dependency] });
      } else {
        metadata.dependencies.push(dependency);
      }
    }

    for (const vulnerability of result.vulnerabilities) {
      const severityGroups = groupsBySeverity.get(vulnerability.severity);
      if (severityGroups === undefined) {
        continue;
      }
      const groupKey = dependencyGroupKey(result.workspacePath, vulnerability);
      let group = severityGroups.get(groupKey);
      if (group === undefined) {
        group = {
          key: groupKey,
          workspacePath: result.workspacePath,
          packageName: vulnerability.packageName,
          ecosystem: vulnerability.ecosystem,
          installedVersion: vulnerability.installedVersion,
          metadata: metadataByCoordinate.get(
            coordinateKey(
              vulnerability.ecosystem,
              vulnerability.packageName,
              vulnerability.installedVersion,
            ),
          ),
          vulnerabilities: new Map(),
        };
        severityGroups.set(groupKey, group);
      }
      group.vulnerabilities.set(vulnerabilityKey(vulnerability), vulnerability);
    }
  }

  for (const severity of SEVERITY_ORDER) {
    const severityGroups = groupsBySeverity.get(severity);
    if (severityGroups === undefined || severityGroups.size === 0) {
      continue;
    }
    const groups = [...severityGroups.values()].sort((left, right) => {
      const nameComparison = compareText(left.packageName, right.packageName);
      if (nameComparison !== 0) {
        return nameComparison;
      }
      const versionComparison = compareText(
        left.installedVersion,
        right.installedVersion,
      );
      return versionComparison === 0
        ? compareText(left.workspacePath, right.workspacePath)
        : versionComparison;
    });
    const count = boundedSum(
      groups.map((group) => group.vulnerabilities.size),
    );
    const visibleGroups = groups.slice(0, maximumDependencies);
    const children: Array<DependencyTreeNode | InformationTreeNode> =
      visibleGroups.map((group) =>
        buildDependencyNode(
          group,
          maximumVulnerabilities,
          remediationLookup,
          remediationCapabilityLookup,
          options.remediationApply,
        ),
      );
    if (visibleGroups.length < groups.length) {
      children.push(
        informationNode(
          `severity:${severity}:dependency-limit`,
          `${(groups.length - visibleGroups.length).toString()} additional vulnerable dependencies omitted from the tree`,
          "warning",
        ),
      );
    }
    roots.push({
      kind: "severity",
      id: `severity:${severity}`,
      label: `${severityLabel(severity)} (${count.toString()})`,
      severity,
      count,
      children,
    });
  }

  if (suppressedVulnerabilityCount > 0) {
    roots.push(
      informationNode(
        "state:severity-filtered-findings",
        `Known Findings Hidden by Severity Filter (${suppressedVulnerabilityCount.toString()})`,
        "warning",
        "Change the minimum severity setting to control which known findings are displayed.",
      ),
    );
  }

  appendManualReviewSummary(
    roots,
    options.remediationAnalysis,
    vulnerabilityCount,
  );

  roots.push(
    coverageComplete
      ? informationNode(
          "state:no-known-vulnerabilities",
          `No Known Vulnerabilities (${noKnownVulnerabilitiesCount.toString()})`,
          "check",
          "Dependencies with no known vulnerabilities reported by the configured provider.",
        )
      : informationNode(
          "state:unconfirmed-dependencies",
          `Coverage Unconfirmed (${noKnownVulnerabilitiesCount.toString()})`,
          "warning",
          "These dependencies have no reported findings, but scan coverage is incomplete.",
        ),
  );

  if (retainedRoot !== undefined) {
    roots.push(retainedRoot);
  }

  return {
    roots,
    coverageComplete,
    dependenciesScanned,
    vulnerabilityCount,
    retainedFindingCount,
    suppressedVulnerabilityCount,
    noKnownVulnerabilitiesCount,
  };
}
