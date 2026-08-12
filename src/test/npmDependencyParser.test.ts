import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  parseNpmDependencies,
  type NpmDependencyParseResult,
} from "../package-managers/npm/NpmDependencyParser";

const fixtureDirectory = join(
  process.cwd(),
  "src",
  "test",
  "fixtures",
  "npm",
  "modern-graph",
);

function parseFixture(): NpmDependencyParseResult {
  return parseNpmDependencies({
    packageJson: readFileSync(join(fixtureDirectory, "package.json"), "utf8"),
    packageJsonPath: "/workspace/package.json",
    lockfile: readFileSync(
      join(fixtureDirectory, "package-lock.json"),
      "utf8",
    ),
    lockfilePath: "/workspace/package-lock.json",
  });
}

void test("parses exact resolved versions and direct npm environments", () => {
  const result = parseFixture();

  assert.equal(result.cancelled, false);
  assert.equal(result.truncated, false);
  assert.equal(result.unresolvedDependencies, 0);

  const packageA = result.dependencies.find(
    (dependency) => dependency.name === "package-a",
  );
  assert.deepEqual(packageA, {
    name: "package-a",
    ecosystem: "npm",
    requestedVersion: "^1.0.0",
    manifestName: "package-a",
    installedVersion: "1.4.0",
    dependencyType: "direct",
    environment: "production",
    declaredEnvironment: "production",
    dependencyPath: ["fixture-application", "package-a@1.4.0"],
    packageJsonPath: "/workspace/package.json",
    lockfilePath: "/workspace/package-lock.json",
  });

  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "dev-tool")
      ?.environment,
    "development",
  );
  assert.equal(
    result.dependencies.find(
      (dependency) => dependency.name === "optional-addon",
    )?.environment,
    "optional",
  );
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "peer-host")
      ?.dependencyType,
    "direct",
  );
});

void test("builds hoisted transitive paths and keeps nested versions separate", () => {
  const result = parseFixture();
  const lodash = result.dependencies.find(
    (dependency) => dependency.name === "lodash",
  );

  assert.deepEqual(lodash?.dependencyPath, [
    "fixture-application",
    "package-a@1.4.0",
    "package-b@2.3.0",
    "lodash@4.17.20",
  ]);
  assert.equal(lodash?.dependencyType, "transitive");
  assert.equal(lodash?.parent, "package-b@2.3.0");

  const duplicates = result.dependencies
    .filter((dependency) => dependency.name === "duplicate")
    .map((dependency) => dependency.installedVersion)
    .sort();
  assert.deepEqual(duplicates, ["1.0.2", "2.1.0"]);
});

void test("uses the real package identity for npm aliases", () => {
  const result = parseFixture();
  const alias = result.dependencies.find(
    (dependency) => dependency.name === "real-util",
  );

  assert.equal(alias?.requestedVersion, "npm:real-util@^3.0.0");
  assert.equal(alias?.manifestName, "alias-util");
  assert.equal(alias?.installedVersion, "3.2.1");
  assert.equal(alias?.dependencyType, "direct");
});

void test("includes resolved peers but not missing optional peers or stale entries", () => {
  const result = parseFixture();
  const names = new Set(result.dependencies.map((dependency) => dependency.name));

  assert.equal(names.has("peer-runtime"), true);
  assert.equal(names.has("missing-optional-peer"), false);
  assert.equal(names.has("unreachable"), false);
  assert.equal(
    result.issues.some((issue) => issue.code === "UNRESOLVED_DEPENDENCY"),
    false,
  );
});

void test("treats packages as authoritative over the legacy dependency map", () => {
  const result = parseNpmDependencies({
    packageJson: {
      name: "authority-test",
      dependencies: { alpha: "^1.0.0" },
    },
    packageJsonPath: "/workspace/package.json",
    lockfile: {
      lockfileVersion: 2,
      packages: {
        "": {},
        "node_modules/alpha": { version: "1.2.3" },
      },
      dependencies: {
        alpha: { version: "99.0.0" },
      },
    },
    lockfilePath: "/workspace/package-lock.json",
  });

  assert.equal(result.dependencies[0]?.installedVersion, "1.2.3");
});

void test("does not trust a resolved npm node that contradicts the current manifest", () => {
  const result = parseNpmDependencies({
    packageJson: {
      name: "stale-lock-test",
      dependencies: { alpha: "^2.0.0" },
    },
    packageJsonPath: "/workspace/package.json",
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { alpha: "^1.0.0" } },
        "node_modules/alpha": { version: "1.2.3" },
      },
    },
    lockfilePath: "/workspace/package-lock.json",
  });

  assert.equal(result.dependencies.length, 0);
  assert.equal(result.unresolvedDependencies, 1);
  assert.equal(
    result.issues.some(
      (issue) => issue.code === "STALE_LOCKFILE_DEPENDENCY",
    ),
    true,
  );
});

void test("seeds configured lock-proven workspace manifests as direct origins", () => {
  const result = parseNpmDependencies({
    packageJson: {
      name: "monorepo-root",
      private: true,
      workspaces: ["packages/*"],
    },
    packageJsonPath: "/workspace/package.json",
    workspaceManifests: [
      {
        location: "packages/web",
        packageJson: {
          name: "web-app",
          dependencies: { runtime: "^1.0.0" },
          devDependencies: { compiler: "^2.0.0" },
        },
        packageJsonPath: "/workspace/packages/web/package.json",
      },
    ],
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": { name: "monorepo-root", workspaces: ["packages/*"] },
        "packages/web": {
          name: "web-app",
          version: "1.0.0",
          dependencies: { runtime: "^1.0.0" },
          devDependencies: { compiler: "^2.0.0" },
        },
        "node_modules/web-app": {
          resolved: "packages/web",
          link: true,
        },
        "node_modules/runtime": { version: "1.4.0" },
        "node_modules/compiler": { version: "2.1.0", dev: true },
      },
    },
  });

  const runtime = result.dependencies.find(
    (dependency) => dependency.name === "runtime",
  );
  const compiler = result.dependencies.find(
    (dependency) => dependency.name === "compiler",
  );
  assert.equal(runtime?.dependencyType, "direct");
  assert.equal(runtime?.packageJsonPath, "/workspace/packages/web/package.json");
  assert.deepEqual(runtime?.dependencyPath, ["web-app", "runtime@1.4.0"]);
  assert.equal(compiler?.environment, "development");
  assert.equal(compiler?.declaredEnvironment, "development");
  assert.equal(
    result.issues.some((issue) => issue.code === "WORKSPACE_NOT_LOCKED"),
    false,
  );
});

void test("does not treat an arbitrary nested manifest as a workspace", () => {
  const result = parseNpmDependencies({
    packageJson: { name: "ordinary-root" },
    packageJsonPath: "/workspace/package.json",
    workspaceManifests: [
      {
        location: "examples/demo",
        packageJson: {
          name: "independent-demo",
          dependencies: { hidden: "1.0.0" },
        },
        packageJsonPath: "/workspace/examples/demo/package.json",
      },
    ],
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": {},
        "examples/demo": {
          name: "independent-demo",
          version: "1.0.0",
          dependencies: { hidden: "1.0.0" },
        },
        "node_modules/hidden": { version: "1.0.0" },
      },
    },
  });

  assert.equal(result.dependencies.length, 0);
  assert.equal(
    result.issues.some((issue) => issue.code === "WORKSPACE_NOT_LOCKED"),
    true,
  );
});

void test("skips non-registry package identities but traverses registry children", () => {
  const result = parseNpmDependencies({
    packageJson: {
      name: "source-provenance",
      dependencies: {
        gitpkg: "git+https://example.test/gitpkg.git",
        localpkg: "file:packages/localpkg",
        remotepkg: "https://example.test/remotepkg.tgz",
      },
    },
    packageJsonPath: "/workspace/package.json",
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/gitpkg": {
          name: "gitpkg",
          version: "1.0.0",
          resolved: "git+https://example.test/gitpkg.git",
          dependencies: { registrychild: "1.0.0" },
        },
        "node_modules/localpkg": {
          name: "localpkg",
          version: "1.0.0",
          resolved: "file:packages/localpkg",
        },
        "node_modules/remotepkg": {
          name: "remotepkg",
          version: "1.0.0",
          resolved: "https://example.test/remotepkg.tgz",
        },
        "node_modules/registrychild": {
          version: "1.0.0",
          resolved:
            "https://registry.npmjs.org/registrychild/-/registrychild-1.0.0.tgz",
        },
      },
    },
  });

  assert.deepEqual(
    result.dependencies.map((dependency) => dependency.name),
    ["registrychild"],
  );
  assert.equal(result.dependencies[0]?.dependencyType, "transitive");
  assert.equal(
    result.issues.filter(
      (issue) => issue.code === "UNSUPPORTED_PACKAGE_SOURCE",
    ).length,
    3,
  );
});

void test("follows validated workspace links and resolves their hoisted children", () => {
  const result = parseNpmDependencies({
    packageJson: {
      name: "workspace-root",
      workspaces: ["packages/workspace"],
      dependencies: { workspace: "file:packages/workspace" },
    },
    packageJsonPath: "/workspace/package.json",
    workspaceManifests: [
      {
        location: "packages/workspace",
        packageJson: {
          name: "workspace-package",
          dependencies: { child: "^2.0.0" },
        },
        packageJsonPath: "/workspace/packages/workspace/package.json",
      },
    ],
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": {},
        "packages/workspace": {
          name: "workspace-package",
          version: "1.2.0",
          dependencies: { child: "^2.0.0" },
        },
        "node_modules/workspace": {
          resolved: "packages/workspace",
          link: true,
        },
        "node_modules/child": { version: "2.1.0" },
      },
    },
  });

  const child = result.dependencies.find(
    (dependency) =>
      dependency.name === "child" &&
      dependency.packageJsonPath ===
        "/workspace/packages/workspace/package.json",
  );
  assert.equal(
    result.dependencies.some(
      (dependency) => dependency.name === "workspace-package",
    ),
    false,
  );
  assert.equal(child?.dependencyType, "direct");
  assert.deepEqual(child?.dependencyPath, [
    "workspace-package",
    "child@2.1.0",
  ]);
});

void test("bounds cyclic lockfile links", () => {
  const result = parseNpmDependencies({
    packageJson: { name: "link-cycle", dependencies: { cycle: "file:a" } },
    packageJsonPath: "/workspace/package.json",
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/cycle": { resolved: "packages/a", link: true },
        "packages/a": { resolved: "node_modules/cycle", link: true },
      },
    },
  });

  assert.equal(result.dependencies.length, 0);
  assert.equal(
    result.issues.some((issue) => issue.code === "LINK_CYCLE"),
    true,
  );
});

void test("uses lock flags when a production package is first reached through dev", () => {
  const result = parseNpmDependencies({
    packageJson: {
      name: "mixed-environment",
      dependencies: { "z-production": "1.0.0" },
      devDependencies: { "a-development": "1.0.0" },
    },
    packageJsonPath: "/workspace/package.json",
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/a-development": {
          version: "1.0.0",
          dev: true,
          dependencies: { shared: "1.0.0" },
        },
        "node_modules/z-production": {
          version: "1.0.0",
          dependencies: { shared: "1.0.0" },
        },
        "node_modules/shared": { version: "1.0.0" },
      },
    },
  });

  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "shared")
      ?.environment,
    "production",
  );
});

void test("keeps runtime exposure separate from a direct dev declaration", () => {
  const result = parseNpmDependencies({
    packageJson: {
      name: "dual-use",
      dependencies: { parent: "1.0.0" },
      devDependencies: { shared: "1.0.0" },
    },
    packageJsonPath: "/workspace/package.json",
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/parent": {
          version: "1.0.0",
          dependencies: { shared: "1.0.0" },
        },
        "node_modules/shared": { version: "1.0.0" },
      },
    },
  });
  const shared = result.dependencies.find(
    (dependency) => dependency.name === "shared",
  );

  assert.equal(shared?.dependencyType, "direct");
  assert.equal(shared?.environment, "production");
  assert.equal(shared?.declaredEnvironment, "development");
});

void test("rejects malformed JSON and unsafe lockfile paths without throwing", () => {
  const malformed = parseNpmDependencies({
    packageJson: "{",
    packageJsonPath: "/workspace/package.json",
    lockfile: "{}",
  });
  assert.equal(malformed.dependencies.length, 0);
  assert.equal(malformed.issues[0]?.code, "INVALID_PACKAGE_JSON");

  const unsafe = parseNpmDependencies({
    packageJson: {
      name: "unsafe-test",
      dependencies: { safe: "1.0.0" },
    },
    packageJsonPath: "/workspace/package.json",
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": {},
        "../node_modules/safe": { version: "1.0.0" },
      },
    },
  });
  assert.equal(unsafe.dependencies.length, 0);
  assert.equal(
    unsafe.issues.some((issue) => issue.code === "INVALID_LOCKFILE_LOCATION"),
    true,
  );
});

void test("reports a reachable lock entry that omits its resolved version", () => {
  const result = parseNpmDependencies({
    packageJson: {
      name: "missing-version-test",
      dependencies: { broken: "1.0.0", healthy: "1.0.0" },
    },
    packageJsonPath: "/workspace/package.json",
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/broken": {},
        "node_modules/healthy": { version: "1.0.0" },
      },
    },
  });

  assert.deepEqual(
    result.dependencies.map((dependency) => dependency.name),
    ["healthy"],
  );
  assert.equal(result.unresolvedDependencies, 1);
  assert.equal(
    result.issues.some(
      (issue) => issue.code === "INVALID_RESOLVED_PACKAGE",
    ),
    true,
  );
});

void test("bounds compiled workspace-pattern comparisons", () => {
  const result = parseNpmDependencies({
    packageJson: {
      name: "workspace-pattern-budget-test",
      workspaces: ["apps/*", "tools/*"],
    },
    packageJsonPath: "/workspace/package.json",
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": {},
        "packages/alpha": { name: "alpha", version: "1.0.0" },
        "packages/beta": { name: "beta", version: "1.0.0" },
      },
    },
    limits: { maxWorkspacePatternComparisons: 3 },
  });

  assert.equal(result.truncated, true);
  assert.equal(
    result.issues.some(
      (issue) => issue.code === "WORKSPACE_MATCH_LIMIT_EXCEEDED",
    ),
    true,
  );
});

void test("bounds workspace brace expansion before glob compilation", () => {
  const result = parseNpmDependencies({
    packageJson: {
      name: "workspace-expansion-budget-test",
      workspaces: [`${"{a,b}".repeat(16)}/*`],
    },
    packageJsonPath: "/workspace/package.json",
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": {},
        "packages/alpha": { name: "alpha", version: "1.0.0" },
      },
    },
  });

  assert.equal(result.truncated, true);
  assert.equal(
    result.issues.some(
      (issue) =>
        issue.code === "WORKSPACE_PATTERN_COMPLEXITY_LIMIT_EXCEEDED",
    ),
    true,
  );
});

void test("reports a non-registry peer even when its version is omitted", () => {
  const result = parseNpmDependencies({
    packageJson: {
      name: "non-registry-peer-test",
      dependencies: { healthy: "1.0.0" },
      peerDependencies: { fork: "*" },
    },
    packageJsonPath: "/workspace/package.json",
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/fork": {
          resolved: "git+https://example.invalid/repository.git",
        },
        "node_modules/healthy": { version: "1.0.0" },
      },
    },
  });

  assert.deepEqual(
    result.dependencies.map((dependency) => dependency.name),
    ["healthy"],
  );
  assert.equal(
    result.issues.some(
      (issue) => issue.code === "UNSUPPORTED_PACKAGE_SOURCE",
    ),
    true,
  );
});

void test("enforces package bounds and cancellation", () => {
  const bounded = parseNpmDependencies({
    packageJson: { name: "bounded", dependencies: { alpha: "1.0.0" } },
    packageJsonPath: "/workspace/package.json",
    lockfile: {
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/alpha": { version: "1.0.0" },
        "node_modules/beta": { version: "1.0.0" },
      },
    },
    limits: { maxPackages: 2 },
  });
  assert.equal(bounded.truncated, true);
  assert.equal(
    bounded.issues.some((issue) => issue.code === "PACKAGE_LIMIT_EXCEEDED"),
    true,
  );

  const controller = new AbortController();
  controller.abort();
  const cancelled = parseNpmDependencies({
    packageJson: {},
    packageJsonPath: "/workspace/package.json",
    lockfile: { lockfileVersion: 3, packages: { "": {} } },
    signal: controller.signal,
  });
  assert.equal(cancelled.cancelled, true);
  assert.equal(cancelled.dependencies.length, 0);
});
