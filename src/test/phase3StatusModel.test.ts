import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { ProviderResult, ScanError, ScanResult } from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import type { RetainedVulnerabilityFinding } from "../services/ScanResultStore";
import { buildDependencyStatusModel } from "../status/statusModel";

function provider(
  status: ProviderResult["status"],
  dependencyCount: number,
  vulnerabilitiesFound = 0,
): ProviderResult {
  return {
    provider: "OSV",
    status,
    dependenciesEligible: dependencyCount,
    dependenciesSubmitted: dependencyCount,
    successful: status === "available" ? dependencyCount : 0,
    failed: status === "available" ? 0 : dependencyCount,
    cacheHits: 0,
    staleCacheFallbacks: 0,
    vulnerabilitiesFound,
  };
}

function finding(id = "OSV-TEST"): Vulnerability {
  return {
    id,
    aliases: [],
    packageName: "example",
    ecosystem: "npm",
    installedVersion: "1.0.0",
    severity: "HIGH",
    summary: "Example",
    references: [],
    source: "OSV",
  };
}

function retainedFinding(id: string): RetainedVulnerabilityFinding {
  return {
    vulnerability: finding(id),
    dependencies: [],
    workspacePaths: ["/workspace"],
    lastConfirmedAt: "2026-08-11T19:00:00.000Z",
  };
}

function result(options: {
  dependencyCount?: number;
  vulnerabilities?: readonly Vulnerability[];
  status?: ProviderResult["status"];
  errors?: readonly ScanError[];
  providerVulnerabilitiesFound?: number;
} = {}): ScanResult {
  const dependencyCount = options.dependencyCount ?? 1;
  const vulnerabilities = options.vulnerabilities ?? [];
  return {
    workspacePath: "/workspace",
    scannedAt: "2026-08-11T20:00:00.000Z",
    durationMs: 10,
    packageManagers: dependencyCount === 0 ? [] : ["npm"],
    dependenciesScanned: dependencyCount,
    vulnerableDependencies: vulnerabilities.length === 0 ? 0 : 1,
    vulnerabilities,
    dependencies: [],
    errors: options.errors ?? [],
    providerResults: [
      provider(
        options.status ?? "available",
        dependencyCount,
        options.providerVulnerabilitiesFound,
      ),
    ],
    cancelled: false,
  };
}

void test("status model reports scanning before previous findings", () => {
  const model = buildDependencyStatusModel(
    [result({ vulnerabilities: [finding()] })],
    true,
  );

  assert.equal(model.state, "scanning");
  assert.equal(model.text, "$(shield) Scanning...");
});

void test("status model reports complete zero findings without a broad security claim", () => {
  const model = buildDependencyStatusModel([result()], false);

  assert.equal(model.state, "clean");
  assert.equal(model.coverageComplete, true);
  assert.equal(model.text, "$(shield) Dependencies: No known vulnerabilities");
  assert.match(model.tooltip, /not a claim of overall application security/u);
});

void test("status model reports known vulnerabilities with singular and plural text", () => {
  const singular = buildDependencyStatusModel(
    [result({ vulnerabilities: [finding()] })],
    false,
  );
  const plural = buildDependencyStatusModel(
    [result({ vulnerabilities: [finding("ONE"), finding("TWO")] })],
    false,
  );

  assert.equal(singular.state, "findings");
  assert.equal(singular.text, "$(shield) Dependencies: 1 vulnerability");
  assert.equal(plural.text, "$(shield) Dependencies: 2 vulnerabilities");
});

void test("severity-filtered findings prevent a false clean status", () => {
  const singular = buildDependencyStatusModel(
    [result({ providerVulnerabilitiesFound: 1 })],
    false,
  );
  const plural = buildDependencyStatusModel(
    [result({ providerVulnerabilitiesFound: 3 })],
    false,
  );

  assert.equal(singular.state, "findings");
  assert.equal(singular.text, "$(shield) Dependencies: 1 filtered finding");
  assert.equal(singular.suppressedVulnerabilityCount, 1);
  assert.equal(plural.text, "$(shield) Dependencies: 3 filtered findings");
  assert.doesNotMatch(plural.text, /no known|secure/iu);
});

void test("status distinguishes displayed from severity-filtered findings", () => {
  const model = buildDependencyStatusModel(
    [
      result({
        vulnerabilities: [finding()],
        providerVulnerabilitiesFound: 3,
      }),
    ],
    false,
  );

  assert.equal(model.vulnerabilityCount, 1);
  assert.equal(model.suppressedVulnerabilityCount, 2);
  assert.equal(
    model.text,
    "$(shield) Dependencies: 1 finding, 2 filtered findings",
  );
});

void test("status model never labels unavailable zero-finding coverage clean", () => {
  const model = buildDependencyStatusModel(
    [result({ status: "unavailable" })],
    false,
  );

  assert.equal(model.state, "incomplete");
  assert.equal(model.coverageComplete, false);
  assert.equal(model.text, "$(shield) Dependencies: Scan incomplete");
  assert.doesNotMatch(model.text, /secure|no known/iu);
});

void test("latest unavailable attempt overrides retained complete results", () => {
  const model = buildDependencyStatusModel([result()], false, {
    latestAttemptCoverage: "unavailable",
  });

  assert.equal(model.state, "incomplete");
  assert.equal(model.text, "$(shield) Dependencies: Scan incomplete");
  assert.match(model.tooltip, /latest vulnerability database check was unavailable/u);
});

void test("cancelled attempt is visible when no displayed results exist", () => {
  const model = buildDependencyStatusModel([], false, {
    latestAttemptCoverage: "cancelled",
  });

  assert.equal(model.state, "incomplete");
  assert.equal(model.text, "$(shield) Dependencies: Scan cancelled");
  assert.doesNotMatch(model.text, /not scanned|no known/iu);
});

void test("cancelled attempt overrides but retains prior result counts", () => {
  const model = buildDependencyStatusModel(
    [result({ vulnerabilities: [finding()] })],
    false,
    { latestAttemptCoverage: "cancelled" },
  );

  assert.equal(model.state, "incomplete");
  assert.equal(model.text, "$(shield) Dependencies: Scan cancelled");
  assert.equal(model.vulnerabilityCount, 1);
  assert.match(model.tooltip, /previously displayed results remain available/u);
});

void test("status model calls partial-coverage vulnerabilities findings", () => {
  const model = buildDependencyStatusModel(
    [result({ vulnerabilities: [finding()], status: "partial" })],
    false,
  );

  assert.equal(model.state, "incomplete");
  assert.equal(model.text, "$(shield) Dependencies: 1 finding");
  assert.doesNotMatch(model.text, /vulnerability/u);
});

void test("status surfaces last-complete evidence without adding it to current counts", () => {
  const model = buildDependencyStatusModel(
    [
      result({
        dependencyCount: 2,
        vulnerabilities: [finding("OSV-CURRENT")],
        status: "partial",
      }),
    ],
    false,
    {
      latestAttemptCoverage: "partial",
      retainedFindings: [
        retainedFinding("OSV-OLD"),
        retainedFinding("OSV-CURRENT"),
      ],
    },
  );

  assert.equal(model.state, "incomplete");
  assert.equal(model.vulnerabilityCount, 1);
  assert.equal(model.retainedFindingCount, 1);
  assert.equal(model.dependenciesScanned, 2);
  assert.match(model.text, /1 last-complete finding not reconfirmed/u);
  assert.match(model.tooltip, /not included in current coverage or dependency counts/u);
});

void test("coverage-impacting parse errors prevent a clean status", () => {
  const model = buildDependencyStatusModel(
    [
      result({
        errors: [
          {
            code: "DEPENDENCY_UNRESOLVED",
            message: "A dependency was unresolved.",
          },
        ],
      }),
    ],
    false,
  );

  assert.equal(model.state, "incomplete");
});

void test("status model distinguishes no scan from no supported dependencies", () => {
  const noScan = buildDependencyStatusModel([], false);
  const noDependencies = buildDependencyStatusModel(
    [result({ dependencyCount: 0 })],
    false,
  );

  assert.equal(noScan.state, "not-scanned");
  assert.equal(noDependencies.state, "empty");
});
