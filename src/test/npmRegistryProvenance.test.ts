import { strict as assert } from "node:assert";
import { test } from "node:test";

import { DEPENDENCY_FILE_GLOB } from "../discovery/dependencyFiles";
import type { Dependency } from "../models/Dependency";
import {
  applyWorkspaceRegistryGate,
  applyWorkspaceRegistryGateToParseResult,
  inspectWorkspaceBunfigConfig,
  inspectWorkspaceRegistryConfig,
  unreadableWorkspaceRegistryConfig,
  workspaceRegistryCoverageError,
  type WorkspaceRegistryConfigAssessment,
  type WorkspaceRegistryConfigKind,
  type WorkspaceRegistrySnapshot,
} from "../package-managers/npm/NpmRegistryProvenance";
import type { JavaScriptParseResult } from "../package-managers/yarn/JavaScriptParserTypes";

function config(
  kind: WorkspaceRegistryConfigKind,
  content: string,
  directoryPath = "/workspace",
): WorkspaceRegistryConfigAssessment {
  return inspectWorkspaceRegistryConfig({
    path: `${directoryPath}/${kind}`,
    directoryPath,
    kind,
    content,
  });
}

function snapshot(
  configs: WorkspaceRegistrySnapshot["configs"],
  incomplete = false,
): WorkspaceRegistrySnapshot {
  return { configs, incomplete };
}

function dependency(
  name: string,
  manifestPath = "/workspace/package.json",
  overrides: Partial<Dependency> = {},
): Dependency {
  return {
    name,
    ecosystem: "npm",
    installedVersion: "1.2.3",
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
    manifestPath,
    packageJsonPath: manifestPath,
    lockfilePath: "/workspace/package-lock.json",
    packageManager: "npm",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    ...overrides,
  };
}

void test("allows canonical npm and Yarn Classic public registries", () => {
  const assessments = [
    config("npmrc", "registry=https://registry.npmjs.org/"),
    config("npmrc", "registry='https://registry.npmjs.com:443'"),
    config("yarnrc", 'registry "https://registry.yarnpkg.com/"'),
    config(
      "yarnrc-yaml",
      'npmRegistryServer: "https://registry.npmjs.org"',
    ),
  ];

  assert.equal(assessments.every((assessment) => !assessment.blockAll), true);
  assert.equal(
    applyWorkspaceRegistryGate(
      [dependency("public-package")],
      snapshot(assessments),
      "/workspace",
    ).affectedCount,
    0,
  );
});

void test("fails closed for custom, interpolated, malformed, and ambiguous defaults", () => {
  const unsafe = [
    config("npmrc", "registry=https://packages.example.test/npm"),
    config("npmrc", "registry=${PRIVATE_REGISTRY}"),
    config("npmrc", "registry https://registry.npmjs.org/"),
    config(
      "npmrc",
      [
        "registry=https://registry.npmjs.org/",
        "registry=https://registry.npmjs.com/",
      ].join("\n"),
    ),
    config("yarnrc", "--registry"),
    config("yarnrc-yaml", "npmRegistryServer: ["),
  ];

  assert.equal(unsafe.every((assessment) => assessment.blockAll), true);
});

void test("blocks only dependencies affected by a custom scope registry", () => {
  const assessment = config(
    "npmrc",
    [
      "registry=https://registry.npmjs.org/",
      "@private:registry=${PRIVATE_REGISTRY}",
    ].join("\n"),
  );
  const dependencies = [
    dependency("public-package"),
    dependency("@private/secret"),
    dependency("public-target", "/workspace/package.json", {
      manifestName: "@private/alias",
    }),
  ];

  const gated = applyWorkspaceRegistryGate(
    dependencies,
    snapshot([assessment]),
    "/workspace",
  );

  assert.equal(assessment.blockAll, false);
  assert.deepEqual(assessment.blockedScopes, ["@private"]);
  assert.equal(gated.affectedCount, 2);
  assert.equal(gated.dependencies[0]?.resolutionStatus, "resolved");
  assert.equal(gated.dependencies[1]?.resolutionStatus, "unsupported");
  assert.equal(gated.dependencies[1]?.installedVersion, "");
  assert.equal(gated.dependencies[2]?.resolutionStatus, "unsupported");
});

void test("reads Yarn Berry source mappings but ignores credentials-only npmRegistries", () => {
  const credentialsOnly = config(
    "yarnrc-yaml",
    [
      "npmRegistries:",
      '  "https://private.example.test":',
      "    npmAuthToken: ${TOKEN}",
    ].join("\n"),
  );
  const scopes = config(
    "yarnrc-yaml",
    [
      "npmScopes:",
      "  private:",
      "    npmRegistryServer: https://private.example.test",
      "  public:",
      "    npmRegistryServer: https://registry.npmjs.org/",
    ].join("\n"),
  );

  assert.equal(credentialsOnly.blockAll, false);
  assert.deepEqual(credentialsOnly.blockedScopes, []);
  assert.equal(scopes.blockAll, false);
  assert.deepEqual(scopes.blockedScopes, ["@private"]);
});

void test("gates only Bun dependencies affected by workspace bunfig registries", async () => {
  const canonical = await inspectWorkspaceBunfigConfig({
    path: "/workspace/bunfig.toml",
    directoryPath: "/workspace",
    content: [
      "[install]",
      'registry = { url = "https://registry.npmjs.org/", token = "$TOKEN" }',
    ].join("\n"),
  });
  const customScope = await inspectWorkspaceBunfigConfig({
    path: "/workspace/bunfig.toml",
    directoryPath: "/workspace",
    content: [
      "[install.scopes]",
      '"@private" = { url = "https://private.example.test", token = "$TOKEN" }',
    ].join("\n"),
  });
  const customDefault = await inspectWorkspaceBunfigConfig({
    path: "/workspace/bunfig.toml",
    directoryPath: "/workspace",
    content: '[install]\nregistry = "$PRIVATE_REGISTRY"',
  });
  const malformed = await inspectWorkspaceBunfigConfig({
    path: "/workspace/bunfig.toml",
    directoryPath: "/workspace",
    content: "[install\nregistry = 123",
  });

  assert.equal(canonical.blockAll, false);
  assert.deepEqual(canonical.packageManagers, ["bun"]);
  assert.deepEqual(customScope.blockedScopes, ["@private"]);
  assert.equal(customDefault.blockAll, true);
  assert.equal(malformed.blockAll, true);

  const gated = applyWorkspaceRegistryGate(
    [
      dependency("@private/bun-package", "/workspace/package.json", {
        packageManager: "bun",
      }),
      dependency("@private/npm-package"),
    ],
    snapshot([customScope]),
    "/workspace",
  );
  assert.equal(gated.affectedCount, 1);
  assert.equal(gated.dependencies[0]?.resolutionStatus, "unsupported");
  assert.equal(gated.dependencies[1]?.resolutionStatus, "resolved");
});

void test("applies a config only to manifests under its directory", () => {
  const assessment = config(
    "npmrc",
    "registry=https://private.example.test",
    "/workspace/apps/affected",
  );
  const gated = applyWorkspaceRegistryGate(
    [
      dependency("affected", "/workspace/apps/affected/package.json", {
        projectPath: "/workspace/apps/affected",
      }),
      dependency("sibling", "/workspace/apps/sibling/package.json", {
        projectPath: "/workspace/apps/sibling",
      }),
    ],
    snapshot([assessment]),
    "/workspace",
  );

  assert.equal(gated.affectedCount, 1);
  assert.equal(gated.dependencies[0]?.resolutionStatus, "unsupported");
  assert.equal(gated.dependencies[1]?.resolutionStatus, "resolved");
  assert.deepEqual(gated.affectedByProject, [
    { projectPath: "/workspace/apps/affected", count: 1 },
  ]);
});

void test("fails closed when config discovery or reading is incomplete", () => {
  const candidate = dependency("public-package");
  const unreadable = unreadableWorkspaceRegistryConfig(
    "/workspace/.npmrc",
    "/workspace",
  );

  assert.equal(
    applyWorkspaceRegistryGate(
      [candidate],
      snapshot([unreadable]),
      "/workspace",
    ).affectedCount,
    1,
  );
  assert.equal(
    applyWorkspaceRegistryGate(
      [candidate],
      snapshot([], true),
      "/workspace",
    ).affectedCount,
    1,
  );
});

void test("bounds registry config parsing independently of the file reader", () => {
  const assessment = config("npmrc", "x".repeat(64 * 1024 + 1));
  assert.equal(assessment.blockAll, true);
});

void test("recomputes adapter coverage counts after source gating", () => {
  const resolved = dependency("resolved");
  const unresolved = dependency("unresolved", "/workspace/package.json", {
    installedVersion: "",
    resolutionStatus: "unresolved",
  });
  const alreadyUnsupported = dependency(
    "already-unsupported",
    "/workspace/package.json",
    { installedVersion: "", resolutionStatus: "unsupported" },
  );
  const parsed: JavaScriptParseResult = {
    dependencies: [resolved, unresolved, alreadyUnsupported],
    issues: [],
    discovered: 3,
    resolved: 1,
    unresolved: 1,
    unsupported: 1,
    truncated: false,
    cancelled: false,
  };

  const gated = applyWorkspaceRegistryGateToParseResult(
    parsed,
    snapshot([config("npmrc", "registry=https://private.example.test")]),
    "/workspace",
  );

  assert.equal(gated.affectedCount, 2);
  assert.equal(gated.result.resolved, 0);
  assert.equal(gated.result.unresolved, 0);
  assert.equal(gated.result.unsupported, 3);
  assert.equal(
    gated.result.dependencies.every(
      (candidate) =>
        candidate.resolutionStatus === "unsupported" &&
        candidate.installedVersion === "",
    ),
    true,
  );
});

void test("coverage errors never expose registry values or dependency identities", () => {
  const error = workspaceRegistryCoverageError(2, "/workspace/project");

  assert.equal(error.code, "UNSUPPORTED_PACKAGE_SOURCE");
  assert.match(error.message, /^2 dependency record/u);
  assert.equal(error.message.includes("private.example.test"), false);
  assert.equal(error.message.includes("@private/secret"), false);
  assert.match(error.message, /user and global/u);
});

void test("dependency watcher includes every workspace registry config format", () => {
  assert.match(DEPENDENCY_FILE_GLOB, /\.npmrc/u);
  assert.match(DEPENDENCY_FILE_GLOB, /\.yarnrc,/u);
  assert.match(DEPENDENCY_FILE_GLOB, /\.yarnrc\.yml/u);
  assert.match(DEPENDENCY_FILE_GLOB, /bunfig\.toml/u);
});
