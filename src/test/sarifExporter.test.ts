import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type { Vulnerability } from "../models/Vulnerability";
import {
  buildSarifLog,
  exportSarifJson,
  SarifExportError,
  type SarifScanResult,
} from "../reporting";

const WORKSPACE = "C:\\repo";

function dependency(
  relativeManifest: string,
  overrides: Partial<Dependency> = {},
): Dependency {
  return {
    name: "lodash",
    ecosystem: "npm",
    installedVersion: "4.17.20",
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
    dependencyPath: ["lodash"],
    manifestPath: `${WORKSPACE}\\${relativeManifest.replaceAll("/", "\\")}`,
    packageManager: "npm",
    projectPath: WORKSPACE,
    workspacePath: WORKSPACE,
    metadata: { sourceLine: 12 },
    ...overrides,
  };
}

function vulnerability(
  overrides: Partial<Vulnerability> = {},
): Vulnerability {
  return {
    id: "OSV-2026-LODASH",
    aliases: ["GHSA-aaaa-bbbb-cccc", "CVE-2026-12345"],
    packageName: "lodash",
    ecosystem: "npm",
    installedVersion: "4.17.20",
    severity: "UNKNOWN",
    summary: "Fixture prototype pollution advisory",
    affectedRange: "<4.17.21",
    fixedVersion: "4.17.21",
    references: ["https://osv.dev/vulnerability/OSV-2026-LODASH"],
    source: "OSV",
    ...overrides,
  };
}

function scanResult(
  dependencies: readonly Dependency[],
  overrides: Partial<SarifScanResult> = {},
): SarifScanResult {
  return {
    workspacePath: WORKSPACE,
    scannedAt: "2026-08-12T10:11:12Z",
    durationMs: 10,
    packageManagers: ["npm"],
    dependenciesScanned: dependencies.length,
    vulnerableDependencies: 1,
    vulnerabilities: [],
    allVulnerabilities: [vulnerability()],
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
        vulnerabilitiesFound: 1,
      },
    ],
    ecosystemCoverage: [
      {
        ecosystem: "npm",
        packageManagers: ["npm"],
        discovered: dependencies.length,
        resolved: dependencies.length,
        checked: dependencies.length,
        vulnerable: 1,
        unresolved: 0,
        unsupported: 0,
      },
    ],
    cancelled: false,
    ...overrides,
  };
}

void test("exports stable SARIF rules and one result per exact occurrence", () => {
  const dependencies = [
    dependency("packages/a/package.json"),
    dependency("packages/package b/package.json", {
      metadata: { sourceLine: 27 },
    }),
  ];
  const input = scanResult(dependencies);
  const log = buildSarifLog([input], { workspaceRoots: [WORKSPACE] });
  const run = log.runs[0];

  assert.equal(log.version, "2.1.0");
  assert.equal(run.tool.driver.rules.length, 1);
  assert.equal(run.tool.driver.rules[0]?.id, "CVE-2026-12345");
  assert.equal(run.results.length, 2);
  assert.ok(run.results.every((result) => result.level === "warning"));
  assert.deepEqual(
    run.results.map(
      (result) => result.locations[0].physicalLocation.artifactLocation.uri,
    ),
    ["packages/a/package.json", "packages/package%20b/package.json"],
  );
  assert.deepEqual(
    run.results.map(
      (result) => result.locations[0].physicalLocation.region?.startLine,
    ),
    [12, 27],
  );
  assert.notEqual(
    run.results[0]?.partialFingerprints.primaryLocationLineHash,
    run.results[1]?.partialFingerprints.primaryLocationLineHash,
  );

  const serialized = exportSarifJson([input], {
    workspaceRoots: [WORKSPACE],
  });
  assert.equal(
    serialized,
    exportSarifJson([scanResult([...dependencies].reverse())], {
      workspaceRoots: [WORKSPACE],
    }),
  );
  assert.doesNotMatch(serialized, /C:\\\\repo/iu);
});

void test("keeps distinct transitive paths at the same manifest occurrence", () => {
  const manifest = "app/package.json";
  const dependencies = [
    dependency(manifest, {
      name: "root-a",
      installedVersion: "1.0.0",
      dependencyPath: ["root-a"],
    }),
    dependency(manifest, {
      name: "root-b",
      installedVersion: "1.0.0",
      dependencyPath: ["root-b"],
    }),
    dependency(manifest, {
      dependencyType: "transitive",
      dependencyPath: ["root-a", "lodash"],
      metadata: {},
    }),
    dependency(manifest, {
      dependencyType: "transitive",
      dependencyPath: ["root-b", "lodash"],
      metadata: {},
    }),
  ];
  const results = buildSarifLog([scanResult(dependencies)], {
    workspaceRoots: [WORKSPACE],
  }).runs[0].results;

  assert.equal(results.length, 2);
  assert.ok(
    results.every(
      (result) =>
        result.locations[0].physicalLocation.artifactLocation.uri ===
        "app/package.json",
    ),
  );
  assert.notEqual(
    results[0]?.partialFingerprints.primaryLocationLineHash,
    results[1]?.partialFingerprints.primaryLocationLineHash,
  );
});

void test("omits unsafe locations without leaking an absolute path", () => {
  const input = scanResult([
    dependency("outside/package.json", {
      manifestPath: "D:\\private\\secret\\package.json",
    }),
  ]);
  const log = buildSarifLog([input], { workspaceRoots: [WORKSPACE] });
  const serialized = JSON.stringify(log);

  assert.equal(log.runs[0].results.length, 0);
  assert.equal(log.runs[0].invocations?.[0].executionSuccessful, false);
  assert.match(
    log.runs[0].invocations?.[0].toolExecutionNotifications[0]?.message.text ??
      "",
    /omitted/iu,
  );
  assert.doesNotMatch(serialized, /D:\\\\private/iu);
  assert.doesNotMatch(serialized, /secret\\\\package\.json/iu);
});

void test("fails closed on cancellation and the occurrence result limit", () => {
  const input = scanResult([
    dependency("packages/a/package.json"),
    dependency("packages/b/package.json"),
  ]);
  const controller = new AbortController();
  controller.abort();

  assert.throws(
    () =>
      buildSarifLog([input], {
        workspaceRoots: [WORKSPACE],
        signal: controller.signal,
      }),
    (error: unknown) =>
      error instanceof SarifExportError && error.code === "CANCELLED",
  );
  assert.throws(
    () =>
      buildSarifLog([input], {
        workspaceRoots: [WORKSPACE],
        limits: { maximumResults: 1 },
      }),
    (error: unknown) =>
      error instanceof SarifExportError && error.code === "LIMIT_EXCEEDED",
  );
});

void test("reports incomplete scan coverage instead of implying clean results", () => {
  const input = scanResult([dependency("package.json")], {
    allVulnerabilities: [],
    providerResults: [
      {
        provider: "OSV",
        status: "partial",
        dependenciesEligible: 1,
        dependenciesSubmitted: 1,
        successful: 0,
        failed: 1,
        cacheHits: 0,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: 0,
      },
    ],
  });
  const run = buildSarifLog([input], {
    workspaceRoots: [WORKSPACE],
  }).runs[0];

  assert.equal(run.results.length, 0);
  assert.match(
    run.invocations?.[0].toolExecutionNotifications[0]?.message.text ?? "",
    /incomplete/iu,
  );
});

void test("reports incomplete coverage when a present complete-finding field is truncated", () => {
  const base = scanResult([dependency("package.json")]);
  const { allVulnerabilities: _legacyComplete, ...withoutLegacyComplete } = base;
  assert.equal(_legacyComplete?.length, 1);
  const input: SarifScanResult = {
    ...withoutLegacyComplete,
    unfilteredVulnerabilities: [],
  };

  const run = buildSarifLog([input], {
    workspaceRoots: [WORKSPACE],
  }).runs[0];

  assert.equal(run.results.length, 0);
  assert.equal(run.invocations?.[0].executionSuccessful, false);
  assert.match(
    run.invocations?.[0].toolExecutionNotifications[0]?.message.text ?? "",
    /incomplete/iu,
  );
});

void test("keeps identical relative SARIF locations distinct across workspace roots", () => {
  const input = scanResult([
    dependency("unused/package.json", {
      manifestPath: "C:\\work\\a\\package.json",
    }),
    dependency("unused/package.json", {
      manifestPath: "C:\\work\\b\\package.json",
    }),
  ]);

  const run = buildSarifLog([input], {
    workspaceRoots: ["C:\\work\\b", "C:\\work\\a"],
  }).runs[0];

  assert.deepEqual(
    run.results
      .map((result) => result.locations[0].physicalLocation.artifactLocation.uri)
      .sort(),
    ["workspace-root-1/package.json", "workspace-root-2/package.json"],
  );
  assert.notEqual(
    run.results[0]?.partialFingerprints.primaryLocationLineHash,
    run.results[1]?.partialFingerprints.primaryLocationLineHash,
  );
  assert.doesNotMatch(JSON.stringify(run), /C:\\\\work/iu);
});

void test("rejects conflicting complete-finding compatibility fields", () => {
  const input = scanResult([dependency("package.json")], {
    unfilteredVulnerabilities: [],
  });

  assert.throws(
    () => buildSarifLog([input], { workspaceRoots: [WORKSPACE] }),
    (error: unknown) =>
      error instanceof SarifExportError && error.code === "INVALID_INPUT",
  );
});

void test("rejects contradictory evidence for one provider advisory", () => {
  const input = scanResult([dependency("package.json")], {
    allVulnerabilities: [
      vulnerability(),
      vulnerability({ severity: "HIGH" }),
    ],
  });

  assert.throws(
    () => buildSarifLog([input], { workspaceRoots: [WORKSPACE] }),
    /Conflicting vulnerability evidence/u,
  );
});
