import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type {
  ProjectCoverage,
  ProviderResult,
  ScanResult,
} from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import type {
  RemediationAnalysisResult,
  RemediationRecommendation,
} from "../remediation/RemediationModels";
import { buildDependencyStatusModel } from "../status/statusModel";
import {
  buildVulnerabilityTreeModel,
  type EcosystemTreeNode,
  type InformationTreeNode,
  type SeverityTreeNode,
  type WorkspaceTreeNode,
} from "../tree/treeModel";

function provider(eligible: number): ProviderResult {
  return {
    provider: "OSV",
    status: "available",
    dependenciesEligible: eligible,
    dependenciesSubmitted: eligible,
    successful: eligible,
    failed: 0,
    cacheHits: 0,
    staleCacheFallbacks: 0,
    vulnerabilitiesFound: 1,
  };
}

function dependency(options: {
  name: string;
  ecosystem: string;
  version?: string;
  projectPath: string;
  manifestPath: string;
  packageManager: string;
  resolutionStatus?: Dependency["resolutionStatus"];
}): Dependency {
  return {
    name: options.name,
    ecosystem: options.ecosystem,
    installedVersion: options.version ?? "",
    resolutionStatus: options.resolutionStatus ?? "resolved",
    dependencyType: "direct",
    environment: "production",
    manifestPath: options.manifestPath,
    packageManager: options.packageManager,
    projectPath: options.projectPath,
    workspacePath: "/repo",
  };
}

function coverage(options: {
  ecosystem: string;
  packageManager: string;
  projectPath: string;
  manifestPath: string;
  discovered: number;
  resolved: number;
  checked: number;
  vulnerable?: number;
  unresolved?: number;
  unsupported?: number;
}): ProjectCoverage {
  return {
    ecosystem: options.ecosystem,
    packageManagers: [options.packageManager],
    workspacePath: "/repo",
    projectPath: options.projectPath,
    manifestPaths: [options.manifestPath],
    discovered: options.discovered,
    resolved: options.resolved,
    checked: options.checked,
    vulnerable: options.vulnerable ?? 0,
    unresolved: options.unresolved ?? 0,
    unsupported: options.unsupported ?? 0,
  };
}

function finding(): Vulnerability {
  return {
    id: "GHSA-fixture",
    aliases: ["CVE-2026-FIXTURE"],
    packageName: "axios",
    ecosystem: "npm",
    installedVersion: "1.6.0",
    severity: "HIGH",
    summary: "Fixture vulnerability",
    references: [],
    source: "OSV",
  };
}

function phase4Result(): ScanResult {
  const dependencies = [
    dependency({
      name: "axios",
      ecosystem: "npm",
      version: "1.6.0",
      projectPath: "/repo/frontend",
      manifestPath: "/repo/frontend/package.json",
      packageManager: "npm",
    }),
    dependency({
      name: "react",
      ecosystem: "npm",
      version: "18.3.1",
      projectPath: "/repo/frontend",
      manifestPath: "/repo/frontend/package.json",
      packageManager: "npm",
    }),
    dependency({
      name: "requests",
      ecosystem: "PyPI",
      version: "2.31.0",
      projectPath: "/repo/backend",
      manifestPath: "/repo/backend/requirements.txt",
      packageManager: "pip",
    }),
    dependency({
      name: "urllib3",
      ecosystem: "PyPI",
      version: "2.0.7",
      projectPath: "/repo/backend",
      manifestPath: "/repo/backend/requirements.txt",
      packageManager: "pip",
    }),
    dependency({
      name: "flask",
      ecosystem: "PyPI",
      projectPath: "/repo/backend",
      manifestPath: "/repo/backend/requirements.txt",
      packageManager: "pip",
      resolutionStatus: "unresolved",
    }),
  ];
  const projectCoverage = [
    coverage({
      ecosystem: "npm",
      packageManager: "npm",
      projectPath: "/repo/frontend",
      manifestPath: "/repo/frontend/package.json",
      discovered: 2,
      resolved: 2,
      checked: 2,
      vulnerable: 1,
    }),
    coverage({
      ecosystem: "PyPI",
      packageManager: "pip",
      projectPath: "/repo/backend",
      manifestPath: "/repo/backend/requirements.txt",
      discovered: 3,
      resolved: 2,
      checked: 2,
      unresolved: 1,
    }),
  ];
  return {
    workspacePath: "/repo",
    scannedAt: "2026-08-12T00:00:00.000Z",
    durationMs: 20,
    packageManagers: ["npm", "pip"],
    dependenciesScanned: 4,
    vulnerableDependencies: 1,
    vulnerabilities: [finding()],
    dependencies,
    errors: [],
    providerResults: [provider(4)],
    projectCoverage,
    ecosystemCoverage: [
      {
        ecosystem: "npm",
        packageManagers: ["npm"],
        discovered: 2,
        resolved: 2,
        checked: 2,
        vulnerable: 1,
        unresolved: 0,
        unsupported: 0,
      },
      {
        ecosystem: "PyPI",
        packageManagers: ["pip"],
        discovered: 3,
        resolved: 2,
        checked: 2,
        vulnerable: 0,
        unresolved: 1,
        unsupported: 0,
      },
    ],
    cancelled: false,
  };
}

function phase5Recommendation(
  dependencyValue: Dependency,
  overrides: Partial<RemediationRecommendation> = {},
): RemediationRecommendation {
  return {
    recommendationKey: "npm:axios:frontend",
    vulnerabilityId: "GHSA-fixture",
    vulnerabilityIds: ["GHSA-fixture"],
    dependency: dependencyValue,
    currentVersion: "1.6.0",
    recommendedVersion: "1.6.8",
    fixedVersions: ["1.6.8"],
    strategy: "upgrade-direct",
    confidence: "high",
    dependencyPath: dependencyValue.dependencyPath ?? [],
    directDependency: true,
    breakingChangeRisk: "low",
    reason: "Provider reports a fixed version.",
    evidence: [{ source: "osv", description: "Fixed in 1.6.8." }],
    ...overrides,
  };
}

function phase5Analysis(
  recommendation: RemediationRecommendation,
  overrides: Partial<RemediationAnalysisResult["summary"]> = {},
): RemediationAnalysisResult {
  return {
    recommendations: [recommendation],
    remediable: [recommendation],
    noFix: [],
    manualReview: [],
    unresolved: [],
    summary: {
      totalVulnerabilities: 1,
      remediable: 1,
      noKnownFix: 0,
      manualReview: 0,
      unresolved: 0,
      remediationCoveragePercent: 100,
      analysisComplete: true,
      ...overrides,
    },
  };
}

function withoutEcosystemCoverage(result: ScanResult): ScanResult {
  const copy = { ...result };
  delete copy.ecosystemCoverage;
  return copy;
}

function workspaceRoots(
  roots: ReturnType<typeof buildVulnerabilityTreeModel>["roots"],
): WorkspaceTreeNode[] {
  return roots.filter(
    (node): node is WorkspaceTreeNode => node.kind === "workspace",
  );
}

void test("Phase 4 tree groups projects, ecosystems, severities, dependencies, and advisories", () => {
  const model = buildVulnerabilityTreeModel([phase4Result()]);
  const workspaces = workspaceRoots(model.roots);

  assert.equal(model.coverageComplete, false);
  assert.equal(model.noKnownVulnerabilitiesCount, 3);
  assert.deepEqual(
    workspaces.map((node) => node.label),
    ["Workspace: backend", "Workspace: frontend"],
  );

  const frontend = workspaces.find((node) => node.projectPath.endsWith("frontend"));
  const npm = frontend?.children.find(
    (node): node is EcosystemTreeNode => node.ecosystem === "npm",
  );
  const high = npm?.children.find(
    (node): node is SeverityTreeNode =>
      node.kind === "severity" && node.severity === "HIGH",
  );
  assert.equal(high?.label, "High (1)");
  assert.equal(high?.children[0]?.kind, "dependency");
  assert.equal(
    high?.children[0]?.kind === "dependency"
      ? high.children[0].children[0]?.kind
      : undefined,
    "vulnerability",
  );
  assert.equal(
    npm?.children.some(
      (node) =>
        node.kind === "information" &&
        node.label === "No Known Vulnerabilities (1)",
    ),
    true,
  );

  const backend = workspaces.find((node) => node.projectPath.endsWith("backend"));
  const pypi = backend?.children.find((node) => node.ecosystem === "PyPI");
  assert.equal(pypi?.label, "Python");
  assert.equal(
    pypi?.children.some(
      (node) =>
        node.kind === "information" &&
        node.label === "Unresolved Dependencies (1)",
    ),
    true,
  );
});

void test("Phase 4 tree never presents zero checked dependencies as clean", () => {
  const base = phase4Result();
  const uncheckedCoverage = coverage({
    ecosystem: "Maven",
    packageManager: "maven",
    projectPath: "/repo/api",
    manifestPath: "/repo/api/pom.xml",
    discovered: 4,
    resolved: 0,
    checked: 0,
    unresolved: 4,
  });
  const model = buildVulnerabilityTreeModel([
    {
      ...withoutEcosystemCoverage(base),
      dependenciesScanned: 0,
      vulnerableDependencies: 0,
      vulnerabilities: [],
      dependencies: [],
      providerResults: [],
      projectCoverage: [uncheckedCoverage],
    },
  ]);
  const ecosystem = workspaceRoots(model.roots)[0]?.children[0];

  assert.equal(model.coverageComplete, false);
  assert.equal(
    ecosystem?.children.some(
      (node): node is InformationTreeNode =>
        node.kind === "information" &&
        node.label === "No Dependencies Checked (0 of 4)",
    ),
    true,
  );
  assert.equal(
    ecosystem?.children.some((node) =>
      node.label.includes("No Known Vulnerabilities"),
    ),
    false,
  );
});

void test("Phase 4 status aggregates findings and unresolved coverage", () => {
  const model = buildDependencyStatusModel([phase4Result()], false);

  assert.equal(model.state, "incomplete");
  assert.equal(model.unresolvedCount, 1);
  assert.equal(model.text, "$(shield) Dependencies: 1 finding · 1 unresolved");
  assert.doesNotMatch(model.text, /secure|no known/iu);
});

void test("Phase 5 tree adds one concise current remediation child", () => {
  const result = phase4Result();
  const vulnerableDependency = {
    ...result.dependencies[0]!,
    dependencyPath: ["frontend", "axios@1.6.0"],
  };
  const updated = {
    ...result,
    dependencies: [vulnerableDependency, ...result.dependencies.slice(1)],
  };
  const recommendation = phase5Recommendation(vulnerableDependency);
  const model = buildVulnerabilityTreeModel([updated], {
    remediationAnalysis: phase5Analysis(recommendation),
  });
  const frontend = workspaceRoots(model.roots).find((node) =>
    node.projectPath.endsWith("frontend"),
  );
  const npm = frontend?.children.find((node) => node.ecosystem === "npm");
  const high = npm?.children.find(
    (node): node is SeverityTreeNode =>
      node.kind === "severity" && node.severity === "HIGH",
  );
  const dependencyNode = high?.children.find(
    (node) => node.kind === "dependency",
  );
  assert.equal(dependencyNode?.kind, "dependency");
  assert.equal(
    dependencyNode?.kind === "dependency"
      ? dependencyNode.children.at(-1)?.label
      : undefined,
    "Recommended upgrade → 1.6.8",
  );
  if (dependencyNode?.kind === "dependency") {
    assert.equal(dependencyNode.detailsIdentity.projectPath, "/repo/frontend");
    assert.equal(
      dependencyNode.detailsIdentity.manifestPath,
      "/repo/frontend/package.json",
    );
    assert.deepEqual(dependencyNode.detailsIdentity.dependencyPath, [
      "frontend",
      "axios@1.6.0",
    ]);
    const findingNode = dependencyNode.children.find(
      (node) => node.kind === "vulnerability",
    );
    assert.equal(
      findingNode?.kind === "vulnerability"
        ? findingNode.identity.projectPath
        : undefined,
      "/repo/frontend",
    );
  }
});

void test("Phase 5 tree refuses a recommendation from another dependency path", () => {
  const result = phase4Result();
  const vulnerableDependency = {
    ...result.dependencies[0]!,
    dependencyPath: ["frontend", "axios@1.6.0"],
  };
  const foreignRecommendation = phase5Recommendation(vulnerableDependency, {
    recommendationKey: "npm:axios:other",
    dependencyPath: ["other", "axios@1.6.0"],
  });
  const model = buildVulnerabilityTreeModel(
    [{ ...result, dependencies: [vulnerableDependency, ...result.dependencies.slice(1)] }],
    { remediationAnalysis: phase5Analysis(foreignRecommendation) },
  );
  const labels = JSON.stringify(model.roots);
  assert.doesNotMatch(labels, /Recommended upgrade|No known fixed version/u);
});

void test("Phase 5 tree occurrence lookup stays linear for one large coordinate group", () => {
  const base = phase4Result();
  const count = 2_000;
  let dependencyPathReads = 0;
  const dependencies = Array.from({ length: count }, (_unused, index) => {
    const value = dependency({
      name: "axios",
      ecosystem: "npm",
      version: "1.6.0",
      projectPath: "/repo/frontend",
      manifestPath: "/repo/frontend/package.json",
      packageManager: "npm",
    }) as Dependency;
    Object.defineProperty(value, "dependencyPath", {
      enumerable: true,
      get: () => {
        dependencyPathReads += 1;
        return ["frontend", `parent-${index.toString()}`, "axios@1.6.0"];
      },
    });
    return value;
  });
  const recommendations = dependencies.map((dependencyValue, index) =>
    phase5Recommendation(dependencyValue, {
      recommendationKey: `large-${index.toString()}`,
      dependencyPath: [
        "frontend",
        `parent-${index.toString()}`,
        "axios@1.6.0",
      ],
    }),
  );
  const result: ScanResult = {
    ...base,
    dependencies,
    dependenciesScanned: count,
    packageManagers: ["npm"],
    projectCoverage: [
      coverage({
        ecosystem: "npm",
        packageManager: "npm",
        projectPath: "/repo/frontend",
        manifestPath: "/repo/frontend/package.json",
        discovered: count,
        resolved: count,
        checked: count,
        vulnerable: count,
      }),
    ],
    ecosystemCoverage: [
      {
        ecosystem: "npm",
        packageManagers: ["npm"],
        discovered: count,
        resolved: count,
        checked: count,
        vulnerable: count,
        unresolved: 0,
        unsupported: 0,
      },
    ],
    providerResults: [provider(count)],
  };
  const model = buildVulnerabilityTreeModel([result], {
    remediationAnalysis: {
      recommendations,
      remediable: recommendations,
      noFix: [],
      manualReview: [],
      unresolved: [],
      summary: {
        totalVulnerabilities: 1,
        remediable: 1,
        noKnownFix: 0,
        manualReview: 0,
        unresolved: 0,
        remediationCoveragePercent: 100,
        analysisComplete: true,
      },
    },
  });
  assert.equal(model.vulnerabilityCount, 1);
  assert.match(JSON.stringify(model.roots), /Manual Review Required/iu);
  assert.ok(
    dependencyPathReads <= count * 10,
    `expected linear dependency-path reads, received ${dependencyPathReads.toString()}`,
  );
});

void test("Phase 5 status appends current remediation counts without claiming security", () => {
  const result = phase4Result();
  const recommendation = phase5Recommendation(result.dependencies[0]!);
  const model = buildDependencyStatusModel([result], false, {
    remediationAnalysis: phase5Analysis(recommendation),
  });
  assert.match(model.text, /1 finding · 1 remediable/u);
  assert.match(model.tooltip, /calculated remediation candidate/u);
  assert.doesNotMatch(model.text, /secure|fixed/iu);
});

void test("Phase 4 complete findings use finding terminology without changing legacy status", () => {
  const base = phase4Result();
  const complete = buildDependencyStatusModel(
    [
      {
        ...base,
        dependencies: base.dependencies.slice(0, 2),
        dependenciesScanned: 2,
        packageManagers: ["npm"],
        projectCoverage: base.projectCoverage?.slice(0, 1) ?? [],
        ecosystemCoverage: base.ecosystemCoverage?.slice(0, 1) ?? [],
        providerResults: [provider(2)],
      },
    ],
    false,
  );

  assert.equal(complete.coverageComplete, true);
  assert.equal(complete.text, "$(shield) Dependencies: 1 finding");
});

void test("unresolved-only Phase 4 scans are incomplete rather than empty", () => {
  const base = phase4Result();
  const unresolvedOnly = buildDependencyStatusModel(
    [
      {
        ...withoutEcosystemCoverage(base),
        dependenciesScanned: 0,
        vulnerableDependencies: 0,
        vulnerabilities: [],
        dependencies: [],
        providerResults: [],
        projectCoverage: [
          coverage({
            ecosystem: "Maven",
            packageManager: "gradle",
            projectPath: "/repo/api",
            manifestPath: "/repo/api/build.gradle.kts",
            discovered: 2,
            resolved: 0,
            checked: 0,
            unresolved: 2,
          }),
        ],
      },
    ],
    false,
  );

  assert.equal(unresolvedOnly.state, "incomplete");
  assert.equal(unresolvedOnly.text, "$(shield) Dependencies: Scan incomplete · 2 unresolved");
});
