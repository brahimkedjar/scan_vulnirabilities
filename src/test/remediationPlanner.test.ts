import { strict as assert } from "node:assert";
import { test } from "node:test";

import type * as vscode from "vscode";

import type { Dependency } from "../models/Dependency";
import { RemediationPlanner } from "../remediation/apply/RemediationPlanner";
import type { RemediationRecommendation } from "../remediation/RemediationModels";

const ROOT = "C:\\fixture\\npm";
const MANIFEST = `${ROOT}\\package.json`;
const LOCKFILE = `${ROOT}\\package-lock.json`;
const INTEGRITY = `sha512-${Buffer.alloc(64, 7).toString("base64")}`;

interface FixtureOptions {
  readonly specification?: string;
  readonly duplicateCandidate?: boolean;
  readonly candidateGraph?: boolean;
  readonly candidateResolved?: string;
  readonly candidateIntegrity?: string;
  readonly lockfileVersion?: number;
  readonly workspace?: boolean;
  readonly manifestText?: string;
  readonly lockfileText?: string;
  readonly candidateReachable?: boolean;
}

function fixture(options: FixtureOptions = {}): {
  readonly manifest: string;
  readonly lockfile: string;
} {
  const specification = options.specification ?? "^1.0.0";
  const manifest =
    options.manifestText ??
    `${JSON.stringify(
      {
        name: "fixture",
        version: "1.0.0",
        ...(options.workspace ? { workspaces: ["packages/*"] } : {}),
        dependencies: {
          vulnerable: specification,
          ...(options.candidateReachable === false ? {} : { holder: "1.0.0" }),
        },
      },
      null,
      2,
    )}\n`;
  const candidate = {
    version: "1.0.1",
    resolved:
      options.candidateResolved ??
      "https://registry.npmjs.org/vulnerable/-/vulnerable-1.0.1.tgz",
    integrity: options.candidateIntegrity ?? INTEGRITY,
    ...(options.candidateGraph
      ? { dependencies: { child: "1.0.0" } }
      : {}),
  };
  const packages: Record<string, unknown> = {
    "": {
      name: "fixture",
      version: "1.0.0",
      dependencies: {
        vulnerable: specification,
        ...(options.candidateReachable === false ? {} : { holder: "1.0.0" }),
      },
    },
    "node_modules/vulnerable": {
      version: "1.0.0",
      resolved:
        "https://registry.npmjs.org/vulnerable/-/vulnerable-1.0.0.tgz",
      integrity: `sha512-${Buffer.alloc(64, 1).toString("base64")}`,
    },
    ...(options.candidateReachable === false
      ? {}
      : {
          "node_modules/holder": {
            version: "1.0.0",
            resolved: "https://registry.npmjs.org/holder/-/holder-1.0.0.tgz",
            integrity: `sha512-${Buffer.alloc(64, 2).toString("base64")}`,
            dependencies: { vulnerable: "1.0.1" },
          },
        }),
    "node_modules/holder/node_modules/vulnerable": candidate,
  };
  if (options.duplicateCandidate) {
    packages["node_modules/other/node_modules/vulnerable"] = candidate;
  }
  if (options.workspace) {
    packages["packages/app"] = {
      name: "app",
      version: "1.0.0",
    };
  }
  const lockfile =
    options.lockfileText ??
    `${JSON.stringify(
      {
        name: "fixture",
        version: "1.0.0",
        lockfileVersion: options.lockfileVersion ?? 3,
        requires: true,
        packages,
      },
      null,
      2,
    )}\n`;
  return { manifest, lockfile };
}

function recommendation(
  overrides: Partial<RemediationRecommendation> = {},
): RemediationRecommendation {
  const dependency: Dependency = {
    name: "vulnerable",
    ecosystem: "npm",
    requestedVersion: "^1.0.0",
    manifestName: "vulnerable",
    installedVersion: "1.0.0",
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
    dependencyPath: ["fixture", "vulnerable@1.0.0"],
    manifestPath: MANIFEST,
    lockfilePath: LOCKFILE,
    packageManager: "npm",
    projectPath: ROOT,
    workspacePath: ROOT,
  };
  return {
    recommendationKey: "opaque-recommendation-key",
    vulnerabilityId: "GHSA-fixture",
    vulnerabilityIds: ["GHSA-fixture"],
    dependency,
    currentVersion: "1.0.0",
    recommendedVersion: "1.0.1",
    fixedVersions: ["1.0.1"],
    strategy: "upgrade-direct",
    confidence: "high",
    dependencyPath: dependency.dependencyPath ?? [],
    directDependency: true,
    breakingChangeRisk: "low",
    reason: "Provider-listed candidate.",
    evidence: [],
    ...overrides,
  };
}

function planner(
  data: ReturnType<typeof fixture>,
): RemediationPlanner {
  return new RemediationPlanner({
    fileUri: (absolutePath) =>
      ({
        scheme: "file",
        fsPath: absolutePath,
        path: absolutePath.replaceAll("\\", "/"),
        toString: () => `file:///${absolutePath.replaceAll("\\", "/")}`,
      }) as vscode.Uri,
    readFile: async (uri) =>
      new TextEncoder().encode(
        uri.fsPath === MANIFEST ? data.manifest : data.lockfile,
      ),
    canGuaranteeAtomicReplace: () => true,
  });
}

void test("planner creates a deterministic minimal SAFE npm plan from one existing leaf artifact", async () => {
  const data = fixture();
  const result = await planner(data).plan(recommendation(), {
    scanGeneration: "generation-1",
  });
  assert.equal(result.capability, "safe");
  assert.equal(result.reasonCode, "safe-npm-existing-resolution");
  assert.equal(result.files.length, 2);
  assert.equal(result.scanGeneration, "generation-1");
  assert.match(result.registryProvenanceFingerprint ?? "", /^[a-f0-9]{64}$/u);
  const manifestChange = result.files[0];
  const lockChange = result.files[1];
  assert.ok(manifestChange?.afterContent !== undefined);
  assert.ok(lockChange?.afterContent !== undefined);
  assert.equal(
    JSON.parse(manifestChange.afterContent).dependencies.vulnerable,
    "^1.0.1",
  );
  const nextLock = JSON.parse(lockChange.afterContent) as {
    packages: Record<
      string,
      Record<string, unknown> & {
        readonly dependencies?: Record<string, string>;
      }
    >;
  };
  assert.equal(nextLock.packages[""]?.dependencies?.vulnerable, "^1.0.1");
  assert.equal(
    nextLock.packages["node_modules/vulnerable"]?.version,
    "1.0.1",
  );
  assert.equal(
    nextLock.packages["node_modules/vulnerable"]?.integrity,
    INTEGRITY,
  );
  assert.match(manifestChange.unifiedDiff ?? "", /\^1\.0\.0/u);
  assert.match(manifestChange.unifiedDiff ?? "", /\^1\.0\.1/u);
  assert.equal(JSON.parse(data.manifest).dependencies.vulnerable, "^1.0.0");
  assert.equal(JSON.parse(data.lockfile).packages["node_modules/vulnerable"].version, "1.0.0");
});

for (const specification of ["1.0.0", "^1.0.0", "~1.0.0"]) {
  void test(`planner preserves ${specification} range semantics`, async () => {
    const data = fixture({ specification });
    const rec = recommendation({
      dependency: {
        ...recommendation().dependency,
        requestedVersion: specification,
      },
    });
    const result = await planner(data).plan(rec);
    assert.equal(result.capability, "safe");
    assert.equal(
      JSON.parse(result.files[0]?.afterContent ?? "{}").dependencies.vulnerable,
      specification.replace("1.0.0", "1.0.1"),
    );
  });
}

for (const [label, options] of [
  ["duplicate candidate", { duplicateCandidate: true }],
  ["candidate dependency graph", { candidateGraph: true }],
  ["untrusted registry URL", { candidateResolved: "https://evil.invalid/vulnerable-1.0.1.tgz" }],
  ["malformed integrity", { candidateIntegrity: "sha512-not-sri" }],
  ["mismatched registry tarball", { candidateResolved: "https://registry.npmjs.org/evil/-/evil-1.0.1.tgz" }],
  ["non-default registry port", { candidateResolved: "https://registry.npmjs.org:444/vulnerable/-/vulnerable-1.0.1.tgz" }],
  ["unreachable stale candidate", { candidateReachable: false }],
  ["lockfile v2", { lockfileVersion: 2 }],
  ["workspace lock", { workspace: true }],
] as const) {
  void test(`planner refuses SAFE for ${label}`, async () => {
    const result = await planner(fixture(options)).plan(recommendation());
    assert.equal(result.capability, "preview-only");
    assert.equal(result.files.length, 0);
    assert.equal(result.reasonCode, "requires-package-manager-resolution");
  });
}

for (const specification of [
  ">=1.0.0",
  "1.x",
  "latest",
  "1.0.0 || 1.0.1",
  "npm:other@^1.0.0",
]) {
  void test(`planner refuses semantic rewrite for ${specification}`, async () => {
    const data = fixture({ specification });
    const rec = recommendation({
      dependency: {
        ...recommendation().dependency,
        requestedVersion: specification,
      },
    });
    const result = await planner(data).plan(rec);
    assert.equal(result.capability, "preview-only");
    assert.equal(result.files.length, 0);
    assert.equal(result.reasonCode, "range-semantics-change");
  });
}

void test("planner fails closed on duplicate JSON keys", async () => {
  const manifestText =
    '{"name":"fixture","dependencies":{"vulnerable":"^1.0.0","vulnerable":"^1.0.0"}}';
  const result = await planner(fixture({ manifestText })).plan(recommendation());
  assert.equal(result.capability, "preview-only");
  assert.equal(result.files.length, 0);
});

void test("planner never writes a transitive child target onto its parent", async () => {
  const directParent: Dependency = {
    ...recommendation().dependency,
    name: "parent",
    manifestName: "parent",
    requestedVersion: "^2.0.0",
    installedVersion: "2.0.0",
    dependencyType: "transitive",
  };
  const result = await planner(fixture()).plan(
    recommendation({
      dependency: directParent,
      strategy: "upgrade-parent",
      directDependency: false,
    }),
  );
  assert.equal(result.capability, "preview-only");
  assert.equal(result.reasonCode, "transitive-manual-review");
  assert.equal(result.files.length, 0);
});

void test("planner classifies non-npm and no-target recommendations honestly", async () => {
  const nonNpm = recommendation({
    dependency: {
      ...recommendation().dependency,
      ecosystem: "PyPI",
      packageManager: "pip",
    },
  });
  assert.equal((await planner(fixture()).plan(nonNpm)).capability, "preview-only");
  const original = recommendation();
  const noTarget: RemediationRecommendation = {
    recommendationKey: original.recommendationKey,
    vulnerabilityId: original.vulnerabilityId,
    vulnerabilityIds: original.vulnerabilityIds,
    dependency: original.dependency,
    currentVersion: original.currentVersion,
    fixedVersions: original.fixedVersions,
    strategy: original.strategy,
    confidence: original.confidence,
    dependencyPath: original.dependencyPath,
    directDependency: original.directDependency,
    breakingChangeRisk: original.breakingChangeRisk,
    reason: original.reason,
    evidence: original.evidence,
  };
  assert.equal((await planner(fixture()).plan(noTarget)).capability, "unsupported");
});

void test("planner cancellation is observable and preview generation remains read-only", async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    planner(fixture()).plan(recommendation(), { signal: controller.signal }),
    (error: unknown) =>
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "CANCELLED",
  );
});

void test("planner keeps a deterministic diff preview-only when the host cannot prove atomic replacement", async () => {
  const data = fixture();
  const unavailable = new RemediationPlanner({
    fileUri: (absolutePath) =>
      ({
        scheme: "file",
        fsPath: absolutePath,
        path: absolutePath.replaceAll("\\", "/"),
        toString: () => `file:///${absolutePath.replaceAll("\\", "/")}`,
      }) as vscode.Uri,
    readFile: async (uri) =>
      new TextEncoder().encode(
        uri.fsPath === MANIFEST ? data.manifest : data.lockfile,
      ),
    canGuaranteeAtomicReplace: () => false,
  });
  const result = await unavailable.plan(recommendation());
  assert.equal(result.capability, "preview-only");
  assert.equal(result.reasonCode, "atomic-replace-unavailable");
  assert.equal(result.files.length, 2);
  assert.match(result.files[0]?.unifiedDiff ?? "", /\^1\.0\.1/u);
});

void test("planner fails closed when unrelated root lock declarations are stale", async () => {
  const data = fixture();
  const parsed = JSON.parse(data.lockfile) as {
    packages: Record<string, { dependencies?: Record<string, string> }>;
  };
  const root = parsed.packages[""];
  assert.ok(root?.dependencies !== undefined);
  root.dependencies.holder = "0.9.0";
  const result = await planner({
    manifest: data.manifest,
    lockfile: `${JSON.stringify(parsed, null, 2)}\n`,
  }).plan(recommendation());
  assert.equal(result.capability, "preview-only");
  assert.equal(result.reasonCode, "requires-package-manager-resolution");
  assert.equal(result.files.length, 0);
});

void test("planner rejects a stale leaf candidate even when a different target-version node is active", async () => {
  const data = fixture();
  const parsed = JSON.parse(data.lockfile) as {
    packages: Record<string, Record<string, unknown>>;
  };
  const active = parsed.packages["node_modules/holder/node_modules/vulnerable"];
  assert.ok(active !== undefined);
  active.dependencies = { child: "1.0.0" };
  parsed.packages["node_modules/holder/node_modules/child"] = {
    version: "1.0.0",
    resolved: "https://registry.npmjs.org/child/-/child-1.0.0.tgz",
    integrity: `sha512-${Buffer.alloc(64, 3).toString("base64")}`,
  };
  parsed.packages["node_modules/stale/node_modules/vulnerable"] = {
    version: "1.0.1",
    resolved:
      "https://registry.npmjs.org/vulnerable/-/vulnerable-1.0.1.tgz",
    integrity: INTEGRITY,
  };
  const result = await planner({
    manifest: data.manifest,
    lockfile: `${JSON.stringify(parsed, null, 2)}\n`,
  }).plan(recommendation());
  assert.equal(result.capability, "preview-only");
  assert.equal(result.reasonCode, "requires-package-manager-resolution");
  assert.equal(result.files.length, 0);
});

void test("planner preserves UTF-8 BOM, CRLF, indentation, and unrelated manifest bytes", async () => {
  const base = fixture();
  const manifestText = `\uFEFF${base.manifest
    .replaceAll("\n", "\r\n")
    .replaceAll("  ", "\t")}`;
  const lockfileText = `\uFEFF${base.lockfile.replaceAll("\n", "\r\n")}`;
  const result = await planner(fixture({ manifestText, lockfileText })).plan(
    recommendation(),
  );
  assert.equal(result.capability, "safe");
  const manifestAfter = result.files[0]?.afterContent ?? "";
  const lockfileAfter = result.files[1]?.afterContent ?? "";
  assert.ok(manifestAfter.startsWith("\uFEFF"));
  assert.ok(lockfileAfter.startsWith("\uFEFF"));
  assert.doesNotMatch(manifestAfter, /(?<!\r)\n/u);
  assert.doesNotMatch(lockfileAfter, /(?<!\r)\n/u);
  assert.equal(
    manifestAfter.replace("^1.0.1", "^1.0.0"),
    manifestText,
  );
});
