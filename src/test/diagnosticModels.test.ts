import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  buildDependencyDiagnosticPlans,
  buildRetainedDependencyDiagnosticPlans,
  diagnosticLevelForSeverity,
} from "../diagnostics/diagnosticModels";
import type { Dependency } from "../models/Dependency";
import type { ScanResult } from "../models/ScanResult";
import type { Severity, Vulnerability } from "../models/Vulnerability";
import type { RetainedVulnerabilityFinding } from "../services/ScanResultStore";

function vulnerability(
  severity: Severity,
  overrides: Partial<Vulnerability> = {},
): Vulnerability {
  return {
    id: "GHSA-test-test-test",
    aliases: ["CVE-2026-12345"],
    packageName: "lodash",
    ecosystem: "npm",
    installedVersion: "4.17.20",
    severity,
    summary: "Test advisory",
    fixedVersion: "4.17.21",
    references: ["https://osv.dev/vulnerability/GHSA-test-test-test"],
    source: "OSV",
    ...overrides,
  };
}

function dependency(overrides: Partial<Dependency> = {}): Dependency {
  return {
    name: "lodash",
    ecosystem: "npm",
    installedVersion: "4.17.20",
    dependencyType: "direct",
    environment: "production",
    dependencyPath: ["application", "lodash@4.17.20"],
    packageJsonPath: "/workspace/package.json",
    ...overrides,
  };
}

function scanResult(
  dependencies: readonly Dependency[],
  vulnerabilities: readonly Vulnerability[],
): ScanResult {
  return {
    workspacePath: "/workspace",
    scannedAt: "2026-08-11T00:00:00.000Z",
    durationMs: 1,
    packageManagers: ["npm"],
    dependenciesScanned: dependencies.length,
    vulnerableDependencies: vulnerabilities.length === 0 ? 0 : 1,
    vulnerabilities,
    dependencies,
    errors: [],
    providerResults: [
      {
        provider: "OSV",
        status: "available",
        dependenciesEligible: dependencies.length,
        dependenciesSubmitted: dependencies.length,
        successful: dependencies.length,
        failed: 0,
        cacheHits: 0,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: vulnerabilities.length,
      },
    ],
    cancelled: false,
  };
}

void test("maps critical, high, medium, low, and unknown diagnostics", () => {
  assert.deepEqual(
    (["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const).map(
      diagnosticLevelForSeverity,
    ),
    ["error", "error", "warning", "information", "information"],
  );
});

void test("builds a concise direct dependency diagnostic", () => {
  const plans = buildDependencyDiagnosticPlans([
    scanResult([dependency()], [vulnerability("HIGH")]),
  ]);

  assert.equal(plans.length, 1);
  assert.equal(plans[0]?.targetDependency.name, "lodash");
  assert.match(
    plans[0]?.message ?? "",
    /lodash@4\.17\.20 \(npm dependency\) — HIGH/u,
  );
  assert.match(plans[0]?.message ?? "", /CVE-2026-12345/u);
  assert.match(plans[0]?.message ?? "", /Fixed version: 4\.17\.21/u);
});

void test("places a transitive finding on its nearest direct introducer", () => {
  const direct = dependency({
    name: "package-a",
    manifestName: "package-a",
    installedVersion: "1.0.0",
    dependencyPath: ["application", "package-a@1.0.0"],
  });
  const transitive = dependency({
    dependencyType: "transitive",
    parent: "package-b@2.0.0",
    dependencyPath: [
      "application",
      "package-a@1.0.0",
      "package-b@2.0.0",
      "lodash@4.17.20",
    ],
  });
  const plans = buildDependencyDiagnosticPlans([
    scanResult([direct, transitive], [vulnerability("CRITICAL")]),
  ]);

  assert.equal(plans.length, 1);
  assert.equal(plans[0]?.targetDependency.name, "package-a");
  assert.match(
    plans[0]?.message ?? "",
    /package-a introduces vulnerable lodash@4\.17\.20/u,
  );
  assert.match(plans[0]?.dependencyPath ?? "", /package-b@2\.0\.0/u);
});

void test("labels retained transitive evidence on its historical direct introducer", () => {
  const direct = dependency({
    name: "package-a",
    manifestName: "package-a",
    installedVersion: "1.0.0",
    dependencyPath: ["application", "package-a@1.0.0"],
  });
  const transitive = dependency({
    dependencyType: "transitive",
    dependencyPath: [
      "application",
      "package-a@1.0.0",
      "lodash@4.17.20",
    ],
  });
  const retained: RetainedVulnerabilityFinding = {
    vulnerability: vulnerability("HIGH"),
    dependencies: [transitive, direct],
    workspacePaths: ["/workspace"],
    lastConfirmedAt: "2026-08-11T00:00:00.000Z",
  };

  const plans = buildRetainedDependencyDiagnosticPlans([retained]);

  assert.equal(plans.length, 1);
  assert.equal(plans[0]?.targetDependency.name, "package-a");
  assert.match(plans[0]?.message ?? "", /Historical evidence/u);
  assert.match(plans[0]?.message ?? "", /not reconfirmed/u);
  assert.match(plans[0]?.message ?? "", /2026-08-11T00:00:00\.000Z/u);
});

void test("does not invent a source location for an unanchored transitive finding", () => {
  const transitive = dependency({
    dependencyType: "transitive",
    dependencyPath: ["application", "missing-root@1.0.0", "lodash@4.17.20"],
  });
  const plans = buildDependencyDiagnosticPlans([
    scanResult([transitive], [vulnerability("MEDIUM")]),
  ]);

  assert.deepEqual(plans, []);
});

void test("anchors an explicit Go indirect requirement on its own go.mod declaration", () => {
  const indirect = dependency({
    name: "golang.org/x/text",
    manifestName: "golang.org/x/text",
    ecosystem: "Go",
    installedVersion: "v0.18.0",
    dependencyType: "transitive",
    dependencyPath: ["example.com/application", "golang.org/x/text@v0.18.0"],
    manifestPath: "/workspace/go.mod",
    packageManager: "go",
    metadata: {
      manifestSection: "require",
      indirect: true,
      relationshipDetail: "parent-unavailable-from-go.mod",
    },
  });
  const finding = vulnerability("HIGH", {
    packageName: "golang.org/x/text",
    ecosystem: "Go",
    installedVersion: "v0.18.0",
  });
  const plans = buildDependencyDiagnosticPlans([
    scanResult([indirect], [finding]),
  ]);

  assert.equal(plans.length, 1);
  assert.equal(plans[0]?.targetDependency, indirect);
  assert.match(plans[0]?.message ?? "", /golang\.org\/x\/text@v0\.18\.0/u);
  assert.doesNotMatch(plans[0]?.message ?? "", /introduces vulnerable/u);
});

void test("bounds and neutralizes control characters in diagnostic values", () => {
  const badName = `bad\nname${"x".repeat(700)}`;
  const plans = buildDependencyDiagnosticPlans([
    scanResult(
      [dependency({ name: badName })],
      [
        vulnerability("LOW", {
          packageName: badName,
          id: "GHSA-safe-id",
          aliases: [],
        }),
      ],
    ),
  ]);

  assert.equal(plans.length, 1);
  assert.equal(plans[0]?.message.includes("bad\nname"), false);
  assert.ok((plans[0]?.message.length ?? 0) < 700);
});
