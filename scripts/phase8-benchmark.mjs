import { createRequire } from "node:module";
import { performance } from "node:perf_hooks";

const require = createRequire(import.meta.url);
const { analyzeLicenseInventory } = require("../dist/core/license/LicenseIntelligence.js");
const { analyzeMonorepoVersions } = require("../dist/core/monorepo/MonorepoVersionIntelligence.js");

const requested = process.argv[2] === undefined ? 100_000 : Number(process.argv[2]);
if (!Number.isSafeInteger(requested) || requested < 1 || requested > 100_000) {
  throw new RangeError("Benchmark record count must be an integer from 1 to 100000");
}

function measured(name, operation) {
  const heapBefore = process.memoryUsage().heapUsed;
  const started = performance.now();
  const result = operation();
  const durationMs = performance.now() - started;
  const heapAfter = process.memoryUsage().heapUsed;
  return {
    name,
    records: requested,
    durationMs: Math.round(durationMs * 100) / 100,
    heapDeltaMiB: Math.round(((heapAfter - heapBefore) / (1024 * 1024)) * 100) / 100,
    result,
  };
}

const licenseInputs = Array.from({ length: requested }, (_unused, index) => ({
  dependencyId: `dependency-${index}`,
  name: `package-${index % 1_000}`,
  ecosystem: "npm",
  version: `1.${index % 10}.0`,
  dependencyType: index % 3 === 0 ? "transitive" : "direct",
  declaredLicense: "MIT",
  evidenceSource: "synthetic-benchmark",
}));
const license = measured("license-inventory", () =>
  analyzeLicenseInventory(
    licenseInputs,
    { allowedLicenses: ["MIT"], unknownLicense: "review" },
    { maximumRecords: requested },
  ),
);
if (
  license.result.coverage.processedRecords !== requested ||
  !license.result.coverage.analysisComplete
) {
  throw new Error("License benchmark did not retain complete bounded coverage");
}

const monorepoInputs = Array.from({ length: requested }, (_unused, index) => ({
  workspacePath: `workspace-${index % 4}`,
  projectPath: `project-${index % 100}`,
  manifestPath: `project-${index % 100}/package.json`,
  ecosystem: "npm",
  name: `package-${index % 1_000}`,
  installedVersion: `1.${Math.floor(index / 1_000) % 2}.0`,
  resolutionStatus: "resolved",
}));
const monorepo = measured("monorepo-version-intelligence", () =>
  analyzeMonorepoVersions(monorepoInputs, {
    limits: {
      maximumRecords: requested,
      maximumProjects: 10_000,
      maximumFindings: 50_000,
      maximumVersionsPerDependency: 256,
    },
  }),
);
if (
  monorepo.result.coverage.recordsAnalyzed !== requested ||
  !monorepo.result.coverage.analysisComplete
) {
  throw new Error("Monorepo benchmark did not retain complete bounded coverage");
}

process.stdout.write(
  `${JSON.stringify(
    {
      schemaVersion: 1,
      node: process.version,
      platform: process.platform,
      architecture: process.arch,
      measurements: [
        {
          name: license.name,
          records: license.records,
          durationMs: license.durationMs,
          heapDeltaMiB: license.heapDeltaMiB,
        },
        {
          name: monorepo.name,
          records: monorepo.records,
          durationMs: monorepo.durationMs,
          heapDeltaMiB: monorepo.heapDeltaMiB,
          findings: monorepo.result.coverage.findingsEmitted,
        },
      ],
    },
    null,
    2,
  )}\n`,
);
