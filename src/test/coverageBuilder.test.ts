import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type { ProjectCoverage } from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import type { DependencyAuditResult } from "../services/DependencyAuditService";
import { buildCoverage } from "../services/CoverageBuilder";

const PROJECT_COVERAGE: ProjectCoverage = {
  workspacePath: "/workspace",
  projectPath: "/workspace/app",
  manifestPaths: ["/workspace/app/package.json"],
  ecosystem: "npm",
  packageManagers: ["npm"],
  discovered: 2,
  resolved: 2,
  checked: 0,
  vulnerable: 0,
  unresolved: 0,
  unsupported: 0,
};

function dependency(manifestPath: string): Dependency {
  return {
    name: "fixture-package",
    ecosystem: "npm",
    installedVersion: "1.2.3",
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
    manifestPath,
    packageManager: "npm",
    projectPath: "/workspace/app",
    workspacePath: "/workspace",
  };
}

function audit(
  checked: boolean,
  vulnerabilities: readonly Vulnerability[] = [],
): DependencyAuditResult {
  return {
    vulnerabilities,
    errors: [],
    providerResult: {
      provider: "OSV",
      status: checked ? "available" : "partial",
      dependenciesEligible: checked ? 1 : 0,
      dependenciesSubmitted: checked ? 1 : 0,
      successful: checked ? 1 : 0,
      failed: checked ? 0 : 1,
      cacheHits: 0,
      staleCacheFallbacks: 0,
      vulnerabilitiesFound: vulnerabilities.length,
    },
    subjectResults: checked
      ? [
          {
            ecosystem: "npm",
            packageName: "fixture-package",
            version: "1.2.3",
            checked: true,
            vulnerabilityCount: vulnerabilities.length,
          },
        ]
      : [],
    cancelled: false,
  };
}

void test("preserves pre-cap resolved coverage when dependency objects are omitted", () => {
  const result = buildCoverage([PROJECT_COVERAGE], [], audit(false));

  assert.equal(result.projects[0]?.discovered, 2);
  assert.equal(result.projects[0]?.resolved, 2);
  assert.equal(result.projects[0]?.checked, 0);
  assert.equal(result.ecosystems[0]?.discovered, 2);
  assert.equal(result.ecosystems[0]?.resolved, 2);
});

void test("counts each retained project occurrence covered by one provider subject", () => {
  const finding: Vulnerability = {
    id: "OSV-FIXTURE",
    aliases: [],
    packageName: "fixture-package",
    ecosystem: "npm",
    installedVersion: "1.2.3",
    severity: "HIGH",
    summary: "Fixture finding",
    references: [],
    source: "OSV",
  };
  const result = buildCoverage(
    [PROJECT_COVERAGE],
    [
      dependency("/workspace/app/package.json"),
      dependency("/workspace/app/packages/child/package.json"),
    ],
    audit(true, [finding]),
  );

  assert.equal(result.projects[0]?.resolved, 2);
  assert.equal(result.projects[0]?.checked, 2);
  assert.equal(result.projects[0]?.vulnerable, 2);
});
