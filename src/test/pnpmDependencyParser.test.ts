import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { parsePnpmDependencies } from "../package-managers/pnpm/PnpmDependencyParser";
import type {
  JavaScriptParseResult,
  ManifestInput,
} from "../package-managers/yarn/JavaScriptParserTypes";

const fixture = join(
  process.cwd(),
  "src",
  "test",
  "fixtures",
  "pnpm",
  "v9-workspace",
  "pnpm-lock.yaml",
);
const options = {
  includeDevDependencies: true,
  includeTransitiveDependencies: true,
} as const;

function manifest(
  relativeDirectory: string,
  dependencies: Readonly<Record<string, string>>,
  content?: string,
): ManifestInput {
  const prefix = relativeDirectory === "." ? "/workspace" : `/workspace/${relativeDirectory}`;
  return {
    path: `${prefix}/package.json`,
    relativeDirectory,
    content: content ?? JSON.stringify({ dependencies }),
  };
}

const fixtureManifests: readonly ManifestInput[] = [
  manifest(
    ".",
    {},
    readFileSync(join(fixture, "..", "package.json"), "utf8"),
  ),
  manifest(
    "packages/app",
    {},
    readFileSync(join(fixture, "..", "packages", "app", "package.json"), "utf8"),
  ),
];

function parseFixture(): JavaScriptParseResult {
  return parsePnpmDependencies({
    lockfile: readFileSync(fixture, "utf8"),
    lockfilePath: "/workspace/pnpm-lock.yaml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: fixtureManifests,
    options,
  });
}

void test("parses pnpm v9 snapshots, aliases, importers, and environments", () => {
  const result = parseFixture();

  assert.equal(result.discovered, 7);
  assert.equal(result.resolved, 6);
  assert.equal(result.unsupported, 1);
  const beta = result.dependencies.find((dependency) => dependency.name === "beta");
  assert.equal(beta?.dependencyType, "transitive");
  assert.equal(beta?.parent, "alpha@1.2.3");
  const alias = result.dependencies.find(
    (dependency) => dependency.manifestName === "alias-util",
  );
  assert.equal(alias?.name, "real-util");
  assert.equal(alias?.installedVersion, "3.1.0");
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "local-workspace")
      ?.resolutionStatus,
    "unsupported",
  );
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "workspace-runtime")
      ?.manifestPath,
    "/workspace/packages/app/package.json",
  );
});

void test("supports pnpm v6 at-sign package paths", () => {
  const result = parsePnpmDependencies({
    lockfile: `lockfileVersion: '6.0'\ndependencies:\n  alpha:\n    specifier: ^1.0.0\n    version: 1.2.3\npackages:\n  /alpha@1.2.3:\n    resolution: {integrity: sha512-alpha}\n    dependencies:\n      beta: 2.0.0\n  /beta@2.0.0:\n    resolution: {integrity: sha512-beta}\n`,
    lockfilePath: "/workspace/pnpm-lock.yaml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [manifest(".", { alpha: "^1.0.0" })],
    options,
  });

  assert.deepEqual(
    result.dependencies.map((dependency) => `${dependency.name}@${dependency.installedVersion}`),
    ["alpha@1.2.3", "beta@2.0.0"],
  );
});

void test("supports pnpm v5 slash package paths", () => {
  const result = parsePnpmDependencies({
    lockfile: `lockfileVersion: 5.4\nspecifiers:\n  alpha: ^1.0.0\ndependencies:\n  alpha: 1.2.3\npackages:\n  /alpha/1.2.3:\n    resolution: {integrity: sha512-alpha}\n`,
    lockfilePath: "/workspace/pnpm-lock.yaml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [manifest(".", { alpha: "^1.0.0" })],
    options,
  });

  assert.equal(result.resolved, 1);
  assert.equal(result.dependencies[0]?.installedVersion, "1.2.3");
});

void test("extracts the main lock from pnpm combined YAML documents", () => {
  const result = parsePnpmDependencies({
    lockfile: `---\nlockfileVersion: '1.0'\nimporters: {}\n---\nlockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      alpha:\n        specifier: 1.0.0\n        version: 1.0.0\npackages:\n  alpha@1.0.0:\n    resolution: {integrity: sha512-alpha}\nsnapshots:\n  alpha@1.0.0: {}\n`,
    lockfilePath: "/workspace/pnpm-lock.yaml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [manifest(".", { alpha: "1.0.0" })],
    options,
  });
  assert.equal(result.resolved, 1);
});

void test("honors pnpm scan options and rejects duplicate YAML keys", () => {
  const withoutDevOrTransit = parsePnpmDependencies({
    lockfile: readFileSync(fixture, "utf8"),
    lockfilePath: "/workspace/pnpm-lock.yaml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: fixtureManifests,
    options: {
      includeDevDependencies: false,
      includeTransitiveDependencies: false,
    },
  });
  assert.equal(
    withoutDevOrTransit.dependencies.some((dependency) => dependency.name === "dev-tool"),
    false,
  );
  assert.equal(
    withoutDevOrTransit.dependencies.some((dependency) => dependency.name === "beta"),
    false,
  );

  const duplicate = parsePnpmDependencies({
    lockfile: "lockfileVersion: '9.0'\nlockfileVersion: '9.0'\n",
    lockfilePath: "/workspace/pnpm-lock.yaml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [],
    options,
  });
  assert.equal(duplicate.issues[0]?.code, "INVALID_LOCKFILE");
});

void test("reports unsupported pnpm versions and cancellation", () => {
  const unsupported = parsePnpmDependencies({
    lockfile: "lockfileVersion: '999.0'\nimporters: {}\n",
    lockfilePath: "/workspace/pnpm-lock.yaml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [],
    options,
  });
  assert.equal(unsupported.issues[0]?.code, "UNSUPPORTED_LOCKFILE");

  const controller = new AbortController();
  controller.abort();
  const cancelled = parsePnpmDependencies({
    lockfile: readFileSync(fixture, "utf8"),
    lockfilePath: "/workspace/pnpm-lock.yaml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: fixtureManifests,
    options,
    signal: controller.signal,
  });
  assert.equal(cancelled.cancelled, true);
  assert.equal(cancelled.dependencies.length, 0);
});

void test("does not seed pnpm dependencies without a discovered importer manifest", () => {
  const result = parsePnpmDependencies({
    lockfile: `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      alpha:\n        specifier: 1.0.0\n        version: 1.0.0\npackages:\n  alpha@1.0.0:\n    resolution: {integrity: sha512-alpha}\nsnapshots:\n  alpha@1.0.0: {}\n`,
    lockfilePath: "/workspace/pnpm-lock.yaml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [],
    options,
  });

  assert.equal(result.dependencies.length, 0);
  assert.equal(result.resolved, 0);
  assert.equal(
    result.issues.some((issue) => issue.code === "INVALID_MANIFEST"),
    true,
  );
});

void test("reports pnpm manifest dependencies missing or stale in the lock", () => {
  const result = parsePnpmDependencies({
    lockfile: `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      alpha:\n        specifier: 1.0.0\n        version: 1.0.0\npackages:\n  alpha@1.0.0:\n    resolution: {integrity: sha512-alpha}\nsnapshots:\n  alpha@1.0.0: {}\n`,
    lockfilePath: "/workspace/pnpm-lock.yaml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [
      manifest(".", { alpha: "^2.0.0", "brand-new": "1.0.0" }),
    ],
    options,
  });

  assert.equal(result.resolved, 0);
  assert.equal(result.unresolved, 2);
  assert.equal(
    result.dependencies.some((dependency) => dependency.name === "brand-new"),
    true,
  );
  assert.equal(
    result.issues.filter((issue) => issue.code === "DEPENDENCY_UNRESOLVED").length,
    2,
  );
});

void test("rejects stale pnpm direct snapshot selections with matching specifiers", () => {
  const result = parsePnpmDependencies({
    lockfile: `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alpha:
        specifier: ^2.0.0
        version: 1.0.0
      alias-util:
        specifier: npm:real-util@^2.0.0
        version: real-util@1.0.0
      tagged:
        specifier: latest
        version: 4.5.6
packages:
  alpha@1.0.0:
    resolution: {integrity: sha512-alpha}
  real-util@1.0.0:
    resolution: {integrity: sha512-real}
  tagged@4.5.6:
    resolution: {integrity: sha512-tagged}
snapshots:
  alpha@1.0.0: {}
  real-util@1.0.0: {}
  tagged@4.5.6: {}
`,
    lockfilePath: "/workspace/pnpm-lock.yaml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [
      manifest(".", {
        alpha: "^2.0.0",
        "alias-util": "npm:real-util@^2.0.0",
        tagged: "latest",
      }),
    ],
    options,
  });

  assert.equal(result.resolved, 1);
  assert.equal(result.unresolved, 2);
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "alpha")
      ?.resolutionStatus,
    "unresolved",
  );
  assert.equal(
    result.dependencies.find(
      (dependency) => dependency.manifestName === "alias-util",
    )?.resolutionStatus,
    "unresolved",
  );
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "tagged")
      ?.installedVersion,
    "4.5.6",
  );
  assert.equal(
    result.issues.filter((issue) => issue.code === "DEPENDENCY_UNRESOLVED")
      .length,
    2,
  );
});
