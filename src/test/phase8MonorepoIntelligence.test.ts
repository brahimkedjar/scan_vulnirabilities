import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  analyzeMonorepoVersions,
  MONOREPO_VERSION_ANALYSIS_HARD_LIMITS,
  type MonorepoProjectDependencyRecord,
} from "../core/monorepo/MonorepoVersionIntelligence";

function dependency(
  projectPath: string,
  installedVersion: string,
  overrides: Partial<MonorepoProjectDependencyRecord> = {},
): MonorepoProjectDependencyRecord {
  return {
    workspacePath: "C:/private/workspace",
    projectPath,
    ecosystem: "npm",
    name: "shared-package",
    installedVersion,
    resolutionStatus: "resolved",
    ...overrides,
  };
}

void test("reports deterministic cross-project version drift with immutable, opaque evidence", () => {
  const records = [
    dependency("C:/private/workspace/packages/zeta", "2.0.0"),
    dependency("C:/private/workspace/packages/alpha", "1.0.0"),
  ];
  const first = analyzeMonorepoVersions(records);
  const reordered = analyzeMonorepoVersions([...records].reverse());

  assert.deepEqual(first, reordered);
  assert.equal(first.coverage.analysisComplete, true);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0]?.kind, "VERSION_DRIFT");
  assert.deepEqual(
    first.findings[0]?.versions.map((version) => version.version),
    ["1.0.0", "2.0.0"],
  );
  assert.deepEqual(first.findings[0]?.projectRefs, [
    "project-0001",
    "project-0002",
  ]);
  assert.ok(Object.isFrozen(first));
  assert.ok(Object.isFrozen(first.coverage));
  assert.ok(Object.isFrozen(first.findings));
  assert.ok(Object.isFrozen(first.findings[0]));
  assert.ok(Object.isFrozen(first.findings[0]?.versions));
  assert.ok(first.findings[0]?.versions.every(Object.isFrozen));
});

void test("distinguishes multi-version duplication inside one project from harmless repeated evidence", () => {
  const duplicate = analyzeMonorepoVersions([
    dependency("/repo/package-a", "1.0.0"),
    dependency("/repo/package-a", "1.0.0"),
    dependency("/repo/package-a", "2.0.0"),
  ]);
  assert.equal(duplicate.findings.length, 1);
  assert.equal(duplicate.findings[0]?.kind, "DUPLICATE_VERSION");
  assert.equal(duplicate.findings[0]?.affectedProjectCount, 1);
  assert.equal(duplicate.findings[0]?.occurrenceCount, 3);
  assert.deepEqual(
    duplicate.findings[0]?.versions.map((version) => [
      version.version,
      version.occurrenceCount,
    ]),
    [
      ["1.0.0", 2],
      ["2.0.0", 1],
    ],
  );

  const harmless = analyzeMonorepoVersions([
    dependency("/repo/package-a", "1.0.0"),
    dependency("/repo/package-b", "1.0.0"),
  ]);
  assert.deepEqual(harmless.findings, []);
  assert.equal(harmless.coverage.analysisComplete, true);
});

void test("reports both local duplication and cross-project drift when both are evidenced", () => {
  const analysis = analyzeMonorepoVersions([
    dependency("/repo/package-a", "1.0.0"),
    dependency("/repo/package-a", "2.0.0"),
    dependency("/repo/package-b", "1.0.0"),
  ]);

  assert.deepEqual(
    analysis.findings.map((finding) => finding.kind).sort(),
    ["DUPLICATE_VERSION", "VERSION_DRIFT"],
  );
  assert.equal(analysis.coverage.findingsEmitted, 2);
});

void test("fails coverage closed for unresolved, invalid, control-text, and hostile records", () => {
  const hostile = Object.defineProperties(
    {},
    {
      resolutionStatus: { enumerable: true, value: "resolved" },
      ecosystem: {
        enumerable: true,
        get: (): never => {
          throw new Error("hostile getter");
        },
      },
    },
  ) as MonorepoProjectDependencyRecord;
  const analysis = analyzeMonorepoVersions([
    dependency("/repo/a", "", { resolutionStatus: "unresolved" }),
    dependency("/repo/b", "1.0.0", { name: "bad\u202Ename" }),
    hostile,
    null as unknown as MonorepoProjectDependencyRecord,
  ]);

  assert.deepEqual(analysis.findings, []);
  assert.equal(analysis.coverage.recordsExamined, 4);
  assert.equal(analysis.coverage.recordsIneligible, 1);
  assert.equal(analysis.coverage.recordsInvalid, 3);
  assert.equal(analysis.coverage.analysisComplete, false);
});

void test("treats paths as opaque grouping data and never returns private or traversal text", () => {
  let manifestRead = false;
  const first = dependency(
    "C:\\Users\\Alice\\secret\\..\\packages\\a",
    "1.0.0",
    { workspacePath: "C:\\Users\\Alice\\secret" },
  );
  const second = {
    ...dependency("/home/alice/top-secret/../../packages/b", "2.0.0", {
      workspacePath: "/home/alice/top-secret",
      name: "__proto__",
    }),
    get manifestPath(): string {
      manifestRead = true;
      throw new Error("must not inspect manifests");
    },
  };
  const frozenInput = Object.freeze([Object.freeze(first), second]);
  const analysis = analyzeMonorepoVersions(frozenInput);
  const serialized = JSON.stringify(analysis);

  assert.equal(manifestRead, false);
  assert.equal(frozenInput[0], first);
  assert.doesNotMatch(serialized, /Alice|alice|top-secret|\\secret|\.\./u);
  assert.equal(analysis.coverage.recordsAnalyzed, 2);
  assert.equal(analysis.coverage.analysisComplete, true);
});

void test("bounds records, projects, findings, and per-identity version evidence transparently", () => {
  const recordLimited = analyzeMonorepoVersions(
    [
      dependency("/repo/a", "1.0.0"),
      dependency("/repo/b", "2.0.0"),
      dependency("/repo/c", "3.0.0"),
    ],
    { limits: { maximumRecords: 2 } },
  );
  assert.equal(recordLimited.coverage.recordsAnalyzed, 2);
  assert.equal(recordLimited.coverage.recordsOmitted, 1);
  assert.equal(recordLimited.coverage.truncated, true);
  assert.equal(recordLimited.coverage.analysisComplete, false);

  const projectLimited = analyzeMonorepoVersions(
    [
      dependency("/repo/a", "1.0.0"),
      dependency("/repo/b", "2.0.0"),
    ],
    { limits: { maximumProjects: 1 } },
  );
  assert.equal(projectLimited.coverage.projectsAnalyzed, 1);
  assert.equal(projectLimited.coverage.projectsOmitted, 1);
  assert.equal(projectLimited.coverage.analysisComplete, false);

  const findingLimited = analyzeMonorepoVersions(
    [
      dependency("/repo/a", "1.0.0", { name: "alpha" }),
      dependency("/repo/b", "2.0.0", { name: "alpha" }),
      dependency("/repo/a", "1.0.0", { name: "beta" }),
      dependency("/repo/b", "2.0.0", { name: "beta" }),
    ],
    { limits: { maximumFindings: 1 } },
  );
  assert.equal(findingLimited.coverage.findingsEmitted, 1);
  assert.equal(findingLimited.coverage.findingsOmitted, 1);
  assert.equal(findingLimited.coverage.analysisComplete, false);

  const versionLimited = analyzeMonorepoVersions(
    [
      dependency("/repo/a", "1.0.0"),
      dependency("/repo/b", "2.0.0"),
    ],
    { limits: { maximumVersionsPerDependency: 1 } },
  );
  assert.deepEqual(versionLimited.findings, []);
  assert.equal(
    versionLimited.coverage.identitiesOmittedByVersionLimit,
    1,
  );
  assert.equal(versionLimited.coverage.analysisComplete, false);
});

void test("rejects adversarial limit values and refuses over-hard-limit input without reading it", () => {
  const fixture = [dependency("/repo/a", "1.0.0")];
  assert.throws(
    () =>
      analyzeMonorepoVersions(fixture, {
        limits: { maximumRecords: 0 },
      }),
    RangeError,
  );
  assert.throws(
    () =>
      analyzeMonorepoVersions(fixture, {
        limits: {
          maximumProjects:
            MONOREPO_VERSION_ANALYSIS_HARD_LIMITS.maximumProjects + 1,
        },
      }),
    RangeError,
  );

  let read = false;
  const hostile = Object.defineProperty({}, "ecosystem", {
    get: (): never => {
      read = true;
      throw new Error("must not read over-limit input");
    },
  }) as MonorepoProjectDependencyRecord;
  const oversized = new Array<MonorepoProjectDependencyRecord>(
    MONOREPO_VERSION_ANALYSIS_HARD_LIMITS.maximumRecords + 1,
  ).fill(hostile);
  const refused = analyzeMonorepoVersions(oversized);
  assert.equal(read, false);
  assert.equal(refused.coverage.hardLimitExceeded, true);
  assert.equal(refused.coverage.recordsAnalyzed, 0);
  assert.equal(refused.coverage.analysisComplete, false);
});

void test("honors cancellation without returning a complete analysis", () => {
  const controller = new AbortController();
  controller.abort();
  const analysis = analyzeMonorepoVersions(
    [dependency("/repo/a", "1.0.0")],
    { signal: controller.signal },
  );

  assert.deepEqual(analysis.findings, []);
  assert.equal(analysis.coverage.cancelled, true);
  assert.equal(analysis.coverage.recordsExamined, 0);
  assert.equal(analysis.coverage.analysisComplete, false);
});
