import assert from "node:assert/strict";
import { test } from "node:test";

import { analyzeLicenseInventory } from "../core/license/LicenseIntelligence";
import { analyzeMonorepoVersions } from "../core/monorepo/MonorepoVersionIntelligence";

const SCALE_RECORDS = 10_000;

void test("Phase 8 license intelligence retains a deterministic 10k-record prefix", () => {
  const inputs = Array.from({ length: SCALE_RECORDS }, (_unused, index) => ({
    dependencyId: `dependency-${index.toString()}`,
    name: `package-${(index % 1_000).toString()}`,
    ecosystem: "npm",
    version: `1.${(index % 10).toString()}.0`,
    dependencyType: "direct" as const,
    declaredLicense: "MIT",
  }));
  const result = analyzeLicenseInventory(
    inputs,
    { allowedLicenses: ["MIT"], unknownLicense: "review" },
    { maximumRecords: SCALE_RECORDS },
  );

  assert.equal(result.entries.length, SCALE_RECORDS);
  assert.equal(result.coverage.processedRecords, SCALE_RECORDS);
  assert.equal(result.coverage.knownLicenseRecords, SCALE_RECORDS);
  assert.equal(result.coverage.analysisComplete, true);
  assert.equal(result.coverage.truncated, false);
  assert.equal(result.entries[0]?.dependencyId, "dependency-0");
});

void test("Phase 8 monorepo intelligence accounts for every record at 10k scale", () => {
  const records = Array.from({ length: SCALE_RECORDS }, (_unused, index) => ({
    workspacePath: `workspace-${(index % 4).toString()}`,
    projectPath: `project-${(index % 100).toString()}`,
    manifestPath: `project-${(index % 100).toString()}/package.json`,
    ecosystem: "npm",
    name: `package-${(index % 1_000).toString()}`,
    installedVersion: `1.${(Math.floor(index / 1_000) % 2).toString()}.0`,
    resolutionStatus: "resolved" as const,
  }));
  const result = analyzeMonorepoVersions(records, {
    limits: {
      maximumRecords: SCALE_RECORDS,
      maximumProjects: 1_000,
      maximumFindings: 10_000,
      maximumVersionsPerDependency: 16,
    },
  });

  assert.equal(result.coverage.recordsExamined, SCALE_RECORDS);
  assert.equal(result.coverage.recordsAnalyzed, SCALE_RECORDS);
  assert.equal(result.coverage.recordsOmitted, 0);
  assert.equal(result.coverage.analysisComplete, true);
  assert.equal(result.coverage.truncated, false);
  assert.ok(result.coverage.findingsEmitted > 0);
});
