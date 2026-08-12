import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type {
  ProviderResult,
  ScanError,
  ScanResult,
} from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import { buildDependencyDiagnosticPlans } from "../diagnostics/diagnosticModels";
import {
  analyzeDependencyPath,
  dependencyOccurrenceKey,
} from "../remediation/DependencyPathAnalyzer";
import { RemediationAnalyzer } from "../remediation/RemediationAnalyzer";
import type {
  RemediationAnalysisResult,
  RemediationRecommendation,
} from "../remediation/RemediationModels";
import { remediationDisplayValue } from "../remediation/RemediationReason";
import {
  compareEcosystemVersions,
  intersectFixedVersions,
  selectRecommendedVersion,
} from "../remediation/VersionRecommendation";
import { analyzeVersionRisk } from "../remediation/VersionRiskAnalyzer";
import type { SupportedOsvEcosystem } from "../vulnerability/EcosystemMapper";

const analyzer = new RemediationAnalyzer();

interface EcosystemFixture {
  readonly ecosystem: string;
  readonly osv: SupportedOsvEcosystem;
  readonly manager: string;
  readonly name: string;
  readonly current: string;
  readonly fixed: string;
}

const ecosystems: readonly EcosystemFixture[] = [
  {
    ecosystem: "npm",
    osv: "npm",
    manager: "npm",
    name: "lodash",
    current: "4.17.20",
    fixed: "4.17.21",
  },
  {
    ecosystem: "PyPI",
    osv: "PyPI",
    manager: "pip",
    name: "requests",
    current: "2.31.0",
    fixed: "2.32.0",
  },
  {
    ecosystem: "Maven",
    osv: "Maven",
    manager: "maven",
    name: "org.example:demo",
    current: "1.9.0",
    fixed: "1.10.0",
  },
  {
    ecosystem: "crates.io",
    osv: "crates.io",
    manager: "cargo",
    name: "time",
    current: "0.3.35",
    fixed: "0.3.36",
  },
  {
    ecosystem: "Go",
    osv: "Go",
    manager: "go",
    name: "example.com/module",
    current: "v1.20.2",
    fixed: "v1.20.3",
  },
  {
    ecosystem: "NuGet",
    osv: "NuGet",
    manager: "nuget",
    name: "Newtonsoft.Json",
    current: "13.0.2",
    fixed: "13.0.3",
  },
  {
    ecosystem: "Packagist",
    osv: "Packagist",
    manager: "composer",
    name: "vendor/package",
    current: "6.3.0",
    fixed: "6.4.0",
  },
] as const;

function dependency(
  fixture: EcosystemFixture = ecosystems[0] as EcosystemFixture,
  overrides: Partial<Dependency> = {},
): Dependency {
  const workspacePath = "/repo";
  const projectPath = `${workspacePath}/${fixture.manager}`;
  const path = [`${fixture.manager}-app`, `${fixture.name}@${fixture.current}`];
  return {
    name: fixture.name,
    ecosystem: fixture.ecosystem,
    installedVersion: fixture.current,
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
    dependencyPath: path,
    manifestPath: `${projectPath}/manifest`,
    lockfilePath: `${projectPath}/lock`,
    packageManager: fixture.manager,
    projectPath,
    workspacePath,
    ...overrides,
  };
}

function vulnerability(
  fixture: EcosystemFixture = ecosystems[0] as EcosystemFixture,
  id = "GHSA-fixture",
  fixedVersions: readonly string[] = [fixture.fixed],
  overrides: Partial<Vulnerability> = {},
): Vulnerability {
  return {
    id,
    aliases: [],
    packageName: fixture.name,
    ecosystem: fixture.osv,
    installedVersion: fixture.current,
    severity: "HIGH",
    summary: "Fixture advisory",
    fixedVersions: [...fixedVersions],
    remediationCandidates: [...fixedVersions],
    ...(fixedVersions.length === 1
      ? { fixedVersion: fixedVersions[0] as string }
      : {}),
    references: [],
    source: "OSV",
    ...overrides,
  };
}

function provider(
  dependencies: number,
  vulnerabilities: number,
  overrides: Partial<ProviderResult> = {},
): ProviderResult {
  return {
    provider: "OSV",
    status: "available",
    dependenciesEligible: dependencies,
    dependenciesSubmitted: dependencies,
    successful: dependencies,
    failed: 0,
    cacheHits: 0,
    staleCacheFallbacks: 0,
    vulnerabilitiesFound: vulnerabilities,
    ...overrides,
  };
}

function scan(
  dependencies: readonly Dependency[],
  vulnerabilities: readonly Vulnerability[],
  overrides: Partial<ScanResult> = {},
): ScanResult {
  return {
    workspacePath: "/repo",
    scannedAt: "2026-08-12T00:00:00.000Z",
    durationMs: 1,
    packageManagers: [...new Set(dependencies.flatMap((item) => item.packageManager ?? []))],
    dependenciesScanned: dependencies.length,
    vulnerableDependencies: new Set(
      vulnerabilities.map(
        (item) => `${item.ecosystem}:${item.packageName}:${item.installedVersion}`,
      ),
    ).size,
    vulnerabilities,
    dependencies,
    errors: [],
    providerResults: [provider(dependencies.length, vulnerabilities.length)],
    cancelled: false,
    ...overrides,
  };
}

function only(
  result: RemediationAnalysisResult,
): RemediationRecommendation {
  assert.equal(result.recommendations.length, 1);
  const recommendation = result.recommendations[0];
  assert.ok(recommendation !== undefined);
  return recommendation;
}

void test("direct dependency selects one exact provider fixed version with high confidence", () => {
  const fixture = ecosystems[0] as EcosystemFixture;
  const result = analyzer.analyze([
    scan([dependency(fixture)], [vulnerability(fixture)]),
  ]);
  const recommendation = only(result);

  assert.equal(recommendation.strategy, "upgrade-direct");
  assert.equal(recommendation.recommendedVersion, "4.17.21");
  assert.equal(recommendation.confidence, "high");
  assert.equal(recommendation.directDependency, true);
  assert.equal(recommendation.breakingChangeRisk, "low");
  assert.equal(result.summary.remediable, 1);
  assert.equal(result.summary.remediationCoveragePercent, 100);
  assert.equal(result.summary.analysisComplete, true);
});

void test("multiple fixed versions prefer the lowest forward candidate in the same major", () => {
  const fixture = ecosystems[0] as EcosystemFixture;
  const result = analyzer.analyze([
    scan(
      [dependency(fixture, { installedVersion: "4.1.2", dependencyPath: ["app", "lodash@4.1.2"] })],
      [
        vulnerability(fixture, "GHSA-many", ["6.0.1", "5.0.2", "4.1.5"], {
          installedVersion: "4.1.2",
        }),
      ],
    ),
  ]);
  assert.equal(only(result).recommendedVersion, "4.1.5");
});

void test("does not infer safety when current is already newer than every fixed event", () => {
  const result = analyzer.analyze([
    scan(
      [dependency(undefined, { installedVersion: "4.17.22" })],
      [vulnerability(undefined, "GHSA-old", ["4.17.21"], { installedVersion: "4.17.22" })],
    ),
  ]);
  const recommendation = only(result);
  assert.equal(recommendation.strategy, "manual-review");
  assert.equal(recommendation.recommendedVersion, undefined);
  assert.match(recommendation.reason, /forward upgrade candidate/u);
});

void test("aggregates vulnerabilities only through an exact shared proven candidate", () => {
  const dependencyValue = dependency();
  const first = vulnerability(undefined, "GHSA-a", ["4.17.21"], {
    remediationCandidates: ["4.17.21", "4.17.22"],
  });
  const second = vulnerability(undefined, "GHSA-b", ["4.17.22"], {
    remediationCandidates: ["4.17.22"],
  });
  const recommendation = only(
    analyzer.analyze([scan([dependencyValue], [first, second])]),
  );
  assert.equal(recommendation.recommendedVersion, "4.17.22");
  assert.deepEqual(recommendation.vulnerabilityIds, ["GHSA-a", "GHSA-b"]);
  assert.deepEqual(recommendation.fixedVersions, ["4.17.21", "4.17.22"]);
  assert.match(recommendation.reason, /every contributing/u);
});

void test("different advisory events without an exact proven intersection require manual review", () => {
  const recommendation = only(
    analyzer.analyze([
      scan(
        [dependency()],
        [
          vulnerability(undefined, "GHSA-a", ["4.17.21"]),
          vulnerability(undefined, "GHSA-b", ["4.17.22"]),
        ],
      ),
    ]),
  );
  assert.equal(recommendation.strategy, "manual-review");
  assert.equal(recommendation.confidence, "low");
  assert.equal(recommendation.recommendedVersion, undefined);
  assert.match(recommendation.reason, /No exact provider-listed/u);
});

void test("a reintroduced or conflicted candidate is never treated as monotonic safety", () => {
  const recommendation = only(
    analyzer.analyze([
      scan(
        [dependency()],
        [
          vulnerability(undefined, "GHSA-reintroduced", ["4.17.21", "4.17.22"], {
            remediationCandidates: ["4.17.21"],
          }),
          vulnerability(undefined, "GHSA-other", ["4.17.22"], {
            remediationCandidates: ["4.17.22"],
          }),
        ],
      ),
    ]),
  );
  assert.equal(recommendation.strategy, "manual-review");
  assert.equal(recommendation.recommendedVersion, undefined);
});

void test("the analyzer rejects a remediation candidate absent from all authoritative fixed events", () => {
  const recommendation = only(
    analyzer.analyze([
      scan(
        [dependency()],
        [
          vulnerability(undefined, "GHSA-invented", ["4.17.21"], {
            remediationCandidates: ["9.9.9"],
          }),
        ],
      ),
    ]),
  );

  assert.deepEqual(recommendation.fixedVersions, ["4.17.21"]);
  assert.equal(recommendation.strategy, "manual-review");
  assert.equal(recommendation.recommendedVersion, undefined);
});

void test("alias-connected provider fixed-version conflict is manual and low confidence", () => {
  const recommendation = only(
    analyzer.analyze([
      scan(
        [dependency()],
        [vulnerability(undefined, "GHSA-conflict", ["4.17.21"], { fixedVersionConflict: true })],
      ),
    ]),
  );
  assert.equal(recommendation.strategy, "manual-review");
  assert.equal(recommendation.confidence, "low");
  assert.match(recommendation.reason, /disagree/u);
});

void test("no fixed version remains a no-fix result and makes no latest-safe claim", () => {
  const recommendation = only(
    analyzer.analyze([scan([dependency()], [vulnerability(undefined, "GHSA-none", [])])]),
  );
  assert.equal(recommendation.strategy, "no-fixed-version");
  assert.equal(recommendation.recommendedVersion, undefined);
  assert.equal(recommendation.confidence, "low");
  assert.match(recommendation.reason, /^No fixed version/u);
});

void test("a mixed known-fix and no-fix advisory set is manual, not partially remediable", () => {
  const recommendation = only(
    analyzer.analyze([
      scan(
        [dependency()],
        [vulnerability(undefined, "GHSA-fix"), vulnerability(undefined, "GHSA-none", [])],
      ),
    ]),
  );
  assert.equal(recommendation.strategy, "manual-review");
  assert.equal(recommendation.recommendedVersion, undefined);
});

void test("provider fixed events without a proven candidate require manual review", () => {
  const result = analyzer.analyze([
    scan(
      [dependency()],
      [
        vulnerability(undefined, "GHSA-ambiguous-branch", ["4.17.21", "5.0.1"], {
          remediationCandidates: [],
        }),
      ],
    ),
  ]);
  const recommendation = only(result);
  assert.equal(recommendation.strategy, "manual-review");
  assert.equal(recommendation.recommendedVersion, undefined);
  assert.equal(result.summary.noKnownFix, 0);
  assert.equal(result.summary.manualReview, 1);
});

void test("unresolved dependency never receives a version recommendation", () => {
  const unresolved = dependency(undefined, {
    installedVersion: "",
    resolutionStatus: "unresolved",
    dependencyPath: ["app", "lodash@unresolved"],
  });
  const recommendation = only(
    analyzer.analyze([
      scan([unresolved], [vulnerability(undefined, "GHSA-unresolved", ["4.17.21"], { installedVersion: "" })]),
    ]),
  );
  assert.equal(recommendation.strategy, "unresolved");
  assert.equal(recommendation.confidence, "low");
  assert.equal(recommendation.recommendedVersion, undefined);
});

void test("transitive dependency uses only an exact same-origin direct path prefix", () => {
  const parent = dependency(undefined, {
    name: "package-a",
    installedVersion: "1.0.0",
    dependencyPath: ["app", "package-a@1.0.0"],
  });
  const transitive = dependency(undefined, {
    dependencyType: "transitive",
    dependencyPath: ["app", "package-a@1.0.0", "lodash@4.17.20"],
  });
  const recommendation = only(
    analyzer.analyze([scan([parent, transitive], [vulnerability()])]),
  );
  assert.equal(recommendation.strategy, "upgrade-parent");
  assert.equal(recommendation.directDependency, false);
  assert.equal(recommendation.recommendedVersion, "4.17.21");
  assert.equal(recommendation.confidence, "medium");
  assert.deepEqual(recommendation.dependencyPath, transitive.dependencyPath);
  assert.match(recommendation.reason, /package-a/u);
  assert.doesNotMatch(recommendation.reason, /package-a.*\b\d+\.\d+\.\d+.*release/u);
});

void test("transitive dependency without a proven parent requires manual review", () => {
  const transitive = dependency(undefined, {
    dependencyType: "transitive",
    dependencyPath: ["app", "package-a@1.0.0", "lodash@4.17.20"],
  });
  const recommendation = only(
    analyzer.analyze([scan([transitive], [vulnerability()])]),
  );
  assert.equal(recommendation.strategy, "manual-review");
  assert.equal(recommendation.recommendedVersion, undefined);
  assert.equal(recommendation.confidence, "low");
});

void test("path analysis rejects a parent from a different manifest, lockfile, or ambiguous prefix", () => {
  const target = dependency(undefined, {
    dependencyType: "transitive",
    dependencyPath: ["app", "parent@1.0.0", "lodash@4.17.20"],
  });
  const wrongManifest = dependency(undefined, {
    name: "parent",
    installedVersion: "1.0.0",
    manifestPath: "/repo/other/package.json",
    dependencyPath: ["app", "parent@1.0.0"],
  });
  const wrongLock = dependency(undefined, {
    name: "parent",
    installedVersion: "1.0.0",
    lockfilePath: "/repo/npm/other.lock",
    dependencyPath: ["app", "parent@1.0.0"],
  });
  assert.equal(analyzeDependencyPath(target, [wrongManifest, target]).parentProven, false);
  assert.equal(analyzeDependencyPath(target, [wrongLock, target]).parentProven, false);
});

void test("path analysis never proves a parent from matching display segments without stable origin evidence", () => {
  const parent: Dependency = {
    name: "package-a",
    ecosystem: "npm",
    installedVersion: "1.0.0",
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
    dependencyPath: ["app", "package-a@1.0.0"],
  };
  const target: Dependency = {
    name: "lodash",
    ecosystem: "npm",
    installedVersion: "4.17.20",
    resolutionStatus: "resolved",
    dependencyType: "transitive",
    environment: "production",
    dependencyPath: ["app", "package-a@1.0.0", "lodash@4.17.20"],
  };

  assert.equal(analyzeDependencyPath(target, [parent, target]).parentProven, false);
  const recommendation = only(
    analyzer.analyze([scan([parent, target], [vulnerability()])]),
  );
  assert.equal(recommendation.strategy, "manual-review");
  assert.equal(recommendation.recommendedVersion, undefined);
});

void test("provider failure and incomplete coverage downgrade confidence and completeness", () => {
  const failedProvider = provider(1, 1, {
    status: "partial",
    successful: 0,
    failed: 1,
  });
  const errors: readonly ScanError[] = [
    { code: "PROVIDER_ERROR", message: "fixture provider failure", provider: "OSV" },
  ];
  const result = analyzer.analyze([
    scan([dependency()], [vulnerability()], {
      providerResults: [failedProvider],
      errors,
    }),
  ]);
  assert.equal(only(result).confidence, "medium");
  assert.equal(result.summary.analysisComplete, false);
});

void test("pre-aborted analysis is bounded, empty, and accounts for findings conservatively", () => {
  const controller = new AbortController();
  controller.abort();
  const result = analyzer.analyze(
    [scan([dependency()], [vulnerability(), vulnerability(undefined, "GHSA-two")])],
    { signal: controller.signal },
  );
  assert.equal(result.recommendations.length, 0);
  assert.equal(result.summary.totalVulnerabilities, 2);
  assert.equal(result.summary.manualReview, 2);
  assert.equal(result.summary.analysisComplete, false);
});

void test("dependency and vulnerability bounds are enforced with omitted findings manual", () => {
  const dependencies = [
    dependency(undefined, { name: "a", installedVersion: "1.0.0", dependencyPath: ["app", "a@1.0.0"] }),
    dependency(undefined, { name: "b", installedVersion: "1.0.0", dependencyPath: ["app", "b@1.0.0"] }),
  ];
  const vulnerabilities = [
    vulnerability(undefined, "GHSA-a", ["1.0.1"], {
      packageName: "a",
      installedVersion: "1.0.0",
      remediationCandidates: ["1.0.1"],
    }),
    vulnerability(undefined, "GHSA-b", ["1.0.1"], {
      packageName: "b",
      installedVersion: "1.0.0",
      remediationCandidates: ["1.0.1"],
    }),
  ];
  const result = analyzer.analyze([scan(dependencies, vulnerabilities)], {
    maximumDependencyOccurrences: 1,
    maximumVulnerabilityRecords: 2,
  });
  assert.ok(result.recommendations.length <= 1);
  assert.equal(result.summary.totalVulnerabilities, 2);
  assert.equal(result.summary.manualReview + result.summary.remediable, 2);
  assert.equal(result.summary.analysisComplete, false);

  const vulnerabilityBound = analyzer.analyze([scan(dependencies, vulnerabilities)], {
    maximumDependencyOccurrences: 2,
    maximumVulnerabilityRecords: 1,
  });
  assert.equal(vulnerabilityBound.summary.manualReview + vulnerabilityBound.summary.remediable, 2);
  assert.equal(vulnerabilityBound.summary.analysisComplete, false);
  assert.throws(
    () => analyzer.analyze([], { maximumDependencyOccurrences: 0 }),
    RangeError,
  );
});

void test("vulnerability truncation suppresses a target when an omitted constraint shares the occurrence", () => {
  const result = analyzer.analyze(
    [
      scan(
        [dependency()],
        [
          vulnerability(undefined, "GHSA-a", ["4.17.21"]),
          vulnerability(undefined, "GHSA-b", ["4.17.22"]),
        ],
      ),
    ],
    { maximumVulnerabilityRecords: 1 },
  );

  const recommendation = only(result);
  assert.equal(recommendation.strategy, "manual-review");
  assert.equal(recommendation.recommendedVersion, undefined);
  assert.match(recommendation.reason, /bounds omitted/u);
  assert.equal(result.summary.remediable, 0);
  assert.equal(result.summary.manualReview, 2);
  assert.equal(result.summary.analysisComplete, false);
});

void test("the finding-occurrence association bound is fail-closed", () => {
  const first = dependency(undefined, {
    manifestName: "alias-a",
    requestedVersion: "npm:lodash@^4.17.0",
  });
  const second = dependency(undefined, {
    manifestName: "alias-b",
    requestedVersion: "npm:lodash@~4.17.0",
  });
  const result = analyzer.analyze(
    [scan([first, second], [vulnerability()])],
    { maximumFindingOccurrenceAssociations: 1 },
  );

  assert.equal(result.recommendations.length, 1);
  assert.equal(result.recommendations[0]?.strategy, "manual-review");
  assert.equal(result.recommendations[0]?.recommendedVersion, undefined);
  assert.equal(result.summary.remediable, 0);
  assert.equal(result.summary.manualReview, 1);
  assert.equal(result.summary.analysisComplete, false);
  assert.throws(
    () =>
      analyzer.analyze([], { maximumFindingOccurrenceAssociations: 0 }),
    RangeError,
  );
});

void test("unmatched vulnerabilities obey the occurrence bound", () => {
  const vulnerabilities = Array.from({ length: 5 }, (_, index) =>
    vulnerability(undefined, `GHSA-unmatched-${index.toString()}`, ["1.0.1"], {
      packageName: `unmatched-${index.toString()}`,
      installedVersion: "1.0.0",
      remediationCandidates: ["1.0.1"],
    }),
  );
  const result = analyzer.analyze([scan([], vulnerabilities)], {
    maximumDependencyOccurrences: 2,
  });
  assert.equal(result.recommendations.length, 2);
  assert.equal(result.summary.manualReview, 5);
  assert.equal(result.summary.analysisComplete, false);
});

void test("same-looking dependencies from separate scan results never collapse", () => {
  const withOrigin = dependency(undefined, {
    dependencyPath: ["app", "lodash@4.17.20"],
  });
  const noOrigin: Dependency = {
    name: withOrigin.name,
    ecosystem: withOrigin.ecosystem,
    installedVersion: withOrigin.installedVersion,
    resolutionStatus: "resolved",
    dependencyType: withOrigin.dependencyType,
    environment: withOrigin.environment,
    dependencyPath: ["app", "lodash@4.17.20"],
  };
  const first = scan([noOrigin], [vulnerability()], {
    workspacePath: "/repo-a",
    scannedAt: "2026-08-12T00:00:00.000Z",
  });
  const second = scan([noOrigin], [vulnerability(undefined, "GHSA-two")], {
    workspacePath: "/repo-b",
    scannedAt: "2026-08-12T00:00:01.000Z",
  });
  const result = analyzer.analyze([first, second]);
  assert.equal(result.recommendations.length, 2);
  assert.equal(result.summary.totalVulnerabilities, 2);
  assert.equal(result.summary.remediable, 2);
});

void test("npm alias declarations remain exact occurrences through diagnostics", () => {
  const first = dependency(undefined, {
    manifestName: "alias-a",
    requestedVersion: "npm:lodash@^4.17.0",
  });
  const second = dependency(undefined, {
    manifestName: "alias-b",
    requestedVersion: "npm:lodash@~4.17.0",
  });
  assert.notEqual(
    dependencyOccurrenceKey(first),
    dependencyOccurrenceKey(second),
  );

  const scanValue = scan([first, second], [vulnerability()]);
  const analysis = analyzer.analyze([scanValue]);
  assert.deepEqual(
    analysis.recommendations
      .map((recommendation) => recommendation.dependency.manifestName)
      .sort(),
    ["alias-a", "alias-b"],
  );
  const plans = buildDependencyDiagnosticPlans([scanValue], 2_000, analysis);
  assert.equal(plans.length, 2);
  assert.equal(
    plans.filter((plan) => plan.message.includes("Recommended upgrade: 4.17.21"))
      .length,
    2,
  );
});

void test("a vulnerability matching multiple exact occurrences is not count-inflated", () => {
  const first = dependency(undefined, {
    projectPath: "/repo/a",
    manifestPath: "/repo/a/package.json",
    lockfilePath: "/repo/a/package-lock.json",
  });
  const second = dependency(undefined, {
    projectPath: "/repo/b",
    manifestPath: "/repo/b/package.json",
    lockfilePath: "/repo/b/package-lock.json",
  });
  const result = analyzer.analyze([scan([first, second], [vulnerability()])]);
  assert.equal(result.recommendations.length, 2);
  assert.equal(result.summary.totalVulnerabilities, 1);
  assert.equal(result.summary.remediable, 1);
  assert.equal(result.summary.remediationCoveragePercent, 100);
});

void test("analysis is deterministic and does not mutate the ScanResult", () => {
  const dependencyValue = dependency();
  const vulnerabilityValue = vulnerability(undefined, "GHSA-deterministic", ["5.0.0", "4.17.21"]);
  const input = scan([dependencyValue], [vulnerabilityValue]);
  const before = JSON.stringify(input);
  assert.deepEqual(analyzer.analyze([input]), analyzer.analyze([input]));
  assert.equal(JSON.stringify(input), before);
});

void test("all seven supported remediation ecosystems select only exact candidates", () => {
  for (const fixture of ecosystems) {
    const recommendation = only(
      analyzer.analyze([
        scan([dependency(fixture)], [vulnerability(fixture)], {
          workspacePath: `/repo/${fixture.manager}`,
        }),
      ]),
    );
    assert.equal(recommendation.strategy, "upgrade-direct", fixture.osv);
    assert.equal(recommendation.recommendedVersion, fixture.fixed, fixture.osv);
  }
});

void test("ecosystem comparators cover prereleases and conservative unsupported schemes", () => {
  assert.ok((compareEcosystemVersions("npm", "1.0.0-rc.1", "1.0.0") ?? 0) < 0);
  assert.ok((compareEcosystemVersions("PyPI", "1.0rc1", "1.0") ?? 0) < 0);
  assert.ok((compareEcosystemVersions("PyPI", "1.0", "1.0.post1") ?? 0) < 0);
  assert.equal(compareEcosystemVersions("PyPI", "1.0.post1.dev1", "1.0.post1"), undefined);
  assert.ok((compareEcosystemVersions("NuGet", "1.0.0-beta.2", "1.0.0") ?? 0) < 0);
  assert.equal(compareEcosystemVersions("Maven", "1.0.Final", "1.1.0"), undefined);
  assert.equal(selectRecommendedVersion("npm", "invalid", ["1.0.0"]).kind, "unsupported");
  assert.equal(selectRecommendedVersion("Maven", "1.0.Final", ["1.1.0"]).kind, "unsupported");
});

void test("version risk distinguishes patch, minor, major, multi-major, and unknown", () => {
  assert.equal(analyzeVersionRisk("npm", "4.1.2", "4.1.5"), "low");
  assert.equal(analyzeVersionRisk("npm", "4.1.2", "4.2.0"), "medium");
  assert.equal(analyzeVersionRisk("npm", "4.1.2", "5.0.0"), "medium");
  assert.equal(analyzeVersionRisk("npm", "4.1.2", "6.0.0"), "high");
  assert.equal(analyzeVersionRisk("PyPI", "4.1.2", "5.0.0"), "unknown");
  assert.equal(analyzeVersionRisk("Maven", "1.0.0", "2.0.0"), "unknown");
});

void test("fixed-version intersection is exact and deterministic", () => {
  assert.deepEqual(
    intersectFixedVersions([
      ["2.0.0", "1.5.0", "2.0.0"],
      ["2.0.0", "3.0.0"],
      ["2.0.0"],
    ]),
    ["2.0.0"],
  );
  assert.deepEqual(intersectFixedVersions([["1.0.0"], ["2.0.0"]]), []);
  assert.deepEqual(intersectFixedVersions([]), []);
});

void test("control and bidi payloads are neutralized in generated reason and evidence", () => {
  const maliciousName = "safe\u202e<script>alert(1)</script>";
  const maliciousSummary = "summary\u0007<script>alert(2)</script>";
  const recommendation = only(
    analyzer.analyze([
      scan(
        [dependency(undefined, { name: maliciousName })],
        [
          vulnerability(undefined, "GHSA-evil\u202e", ["4.17.21"], {
            packageName: maliciousName,
            summary: maliciousSummary,
          }),
        ],
      ),
    ]),
  );
  assert.equal(recommendation.strategy, "manual-review");
  assert.doesNotMatch(recommendation.reason, /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u);
  for (const evidence of recommendation.evidence) {
    assert.doesNotMatch(evidence.description, /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u);
  }
  assert.equal(remediationDisplayValue(maliciousSummary).includes("\u0007"), false);
  assert.ok(recommendation.dependency.name.includes("<script>"));
});
