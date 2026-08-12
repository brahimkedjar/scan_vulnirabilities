import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { parseYarnDependencies } from "../package-managers/yarn/YarnDependencyParser";
import type { JavaScriptParseResult } from "../package-managers/yarn/JavaScriptParserTypes";

const fixtureRoot = join(process.cwd(), "src", "test", "fixtures", "yarn");
const options = {
  includeDevDependencies: true,
  includeTransitiveDependencies: true,
} as const;

function classicFixture(): JavaScriptParseResult {
  const root = join(fixtureRoot, "classic-graph");
  return parseYarnDependencies({
    manifests: [
      {
        path: "/workspace/package.json",
        relativeDirectory: ".",
        content: readFileSync(join(root, "package.json"), "utf8"),
      },
      {
        path: "/workspace/packages/app/package.json",
        relativeDirectory: "packages/app",
        content: readFileSync(
          join(root, "packages", "app", "package.json"),
          "utf8",
        ),
      },
    ],
    lockfile: readFileSync(join(root, "yarn.lock"), "utf8"),
    lockfilePath: "/workspace/yarn.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    options,
  });
}

void test("parses Yarn Classic graphs, aliases, environments, and workspaces", () => {
  const result = classicFixture();

  assert.equal(result.discovered, 7);
  assert.equal(result.resolved, 6);
  assert.equal(result.unsupported, 1);
  assert.equal(result.unresolved, 0);
  assert.equal(result.cancelled, false);
  const beta = result.dependencies.find((dependency) => dependency.name === "beta");
  assert.equal(beta?.dependencyType, "transitive");
  assert.deepEqual(beta?.dependencyPath, [
    "yarn-classic-root",
    "alpha@1.2.3",
    "beta@2.4.0",
  ]);
  const alias = result.dependencies.find(
    (dependency) => dependency.manifestName === "alias-util",
  );
  assert.equal(alias?.name, "real-util");
  assert.equal(alias?.installedVersion, "3.1.0");
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "optional-addon")
      ?.environment,
    "optional",
  );
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "dev-tool")
      ?.environment,
    "development",
  );
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "workspace-runtime")
      ?.manifestPath,
    "/workspace/packages/app/package.json",
  );
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "local-workspace")
      ?.resolutionStatus,
    "unsupported",
  );
});

void test("parses Yarn Berry YAML and optional dependency metadata", () => {
  const root = join(fixtureRoot, "berry-graph");
  const result = parseYarnDependencies({
    manifests: [
      {
        path: "/workspace/package.json",
        relativeDirectory: ".",
        content: readFileSync(join(root, "package.json"), "utf8"),
      },
    ],
    lockfile: readFileSync(join(root, "yarn.lock"), "utf8"),
    lockfilePath: "/workspace/yarn.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    options,
  });

  assert.equal(result.resolved, 2);
  assert.equal(result.dependencies[0]?.installedVersion, "1.5.0");
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "beta")
      ?.environment,
    "optional",
  );
});

void test("does not classify a private Yarn Berry URL containing @npm: as registry-backed", () => {
  const result = parseYarnDependencies({
    manifests: [
      {
        path: "/workspace/package.json",
        relativeDirectory: ".",
        content: '{"dependencies":{"secret":"1.2.3"}}',
      },
    ],
    lockfile: `__metadata:
  version: 8

"secret@npm:1.2.3":
  version: 1.2.3
  resolution: "https://user:credential@private.example/artifacts/secret@npm:1.2.3"
`,
    lockfilePath: "/workspace/yarn.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    options,
  });

  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  assert.equal(result.resolved, 0);
  assert.equal(result.unsupported, 1);
  assert.ok(
    result.issues.some(
      (issue) => issue.code === "UNSUPPORTED_PACKAGE_SOURCE",
    ),
  );
});

void test("accepts only the bounded Yarn virtual npm resolution structure", () => {
  const result = parseYarnDependencies({
    manifests: [
      {
        path: "/workspace/package.json",
        relativeDirectory: ".",
        content: '{"dependencies":{"peer-lib":"1.0.0"}}',
      },
    ],
    lockfile: `__metadata:
  version: 8

"peer-lib@npm:1.0.0":
  version: 1.0.0
  resolution: "peer-lib@virtual:abcdef123456#npm:1.0.0"
`,
    lockfilePath: "/workspace/yarn.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    options,
  });

  assert.equal(result.dependencies[0]?.resolutionStatus, "resolved");
  assert.equal(result.resolved, 1);
});

void test("rejects stale Yarn direct and transitive registry selections", () => {
  const classicLock = `# yarn lockfile v1

a@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz"
  dependencies:
    b "^2.0.0"

b@^2.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/b/-/b-1.0.0.tgz"
`;
  const transitive = parseYarnDependencies({
    manifests: [
      {
        path: "/workspace/package.json",
        relativeDirectory: ".",
        content: '{"dependencies":{"a":"^1.0.0"}}',
      },
    ],
    lockfile: classicLock,
    lockfilePath: "/workspace/yarn.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    options,
  });
  const staleTransitive = transitive.dependencies.find(
    (dependency) => dependency.name === "b",
  );
  assert.equal(staleTransitive?.resolutionStatus, "unresolved");
  assert.equal(staleTransitive?.installedVersion, "");
  assert.equal(
    transitive.issues.some(
      (issue) =>
        issue.code === "DEPENDENCY_UNRESOLVED" && issue.packageName === "b",
    ),
    true,
  );

  const classicDirect = parseYarnDependencies({
    manifests: [
      {
        path: "/workspace/package.json",
        relativeDirectory: ".",
        content: '{"dependencies":{"b":"^2.0.0"}}',
      },
    ],
    lockfile: classicLock,
    lockfilePath: "/workspace/yarn.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    options,
  });
  assert.equal(classicDirect.dependencies[0]?.resolutionStatus, "unresolved");

  const berryDirect = parseYarnDependencies({
    manifests: [
      {
        path: "/workspace/package.json",
        relativeDirectory: ".",
        content: '{"dependencies":{"b":"^2.0.0"}}',
      },
    ],
    lockfile: `__metadata:
  version: 8

"b@npm:^2.0.0":
  version: 1.0.0
  resolution: "b@npm:1.0.0"
`,
    lockfilePath: "/workspace/yarn.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    options,
  });
  assert.equal(berryDirect.dependencies[0]?.resolutionStatus, "unresolved");
  assert.equal(berryDirect.resolved, 0);
  assert.equal(berryDirect.unresolved, 1);
});

void test("honors Yarn development and transitive scan options", () => {
  const root = join(fixtureRoot, "classic-graph");
  const result = parseYarnDependencies({
    manifests: [
      {
        path: "/workspace/package.json",
        relativeDirectory: ".",
        content: readFileSync(join(root, "package.json"), "utf8"),
      },
    ],
    lockfile: readFileSync(join(root, "yarn.lock"), "utf8"),
    lockfilePath: "/workspace/yarn.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    options: {
      includeDevDependencies: false,
      includeTransitiveDependencies: false,
    },
  });

  assert.equal(result.dependencies.some((dependency) => dependency.name === "dev-tool"), false);
  assert.equal(result.dependencies.some((dependency) => dependency.name === "beta"), false);
});

void test("reports unsupported and malformed Yarn formats without guessing", () => {
  const manifest = {
    path: "/workspace/package.json",
    relativeDirectory: ".",
    content: '{"dependencies":{"alpha":"^1.0.0"}}',
  };
  const unsupported = parseYarnDependencies({
    manifests: [manifest],
    lockfile: "__metadata:\n  version: 999\n",
    lockfilePath: "/workspace/yarn.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    options,
  });
  assert.equal(
    unsupported.issues.some((issue) => issue.code === "UNSUPPORTED_LOCKFILE"),
    true,
  );

  const malformed = parseYarnDependencies({
    manifests: [manifest],
    lockfile: "# yarn lockfile v1\nalpha@^1:\n\tversion \"1.0.0\"\n",
    lockfilePath: "/workspace/yarn.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    options,
  });
  assert.equal(
    malformed.issues.some((issue) => issue.code === "INVALID_LOCKFILE"),
    true,
  );
  assert.equal(malformed.unresolved, 1);
});

void test("bounds Yarn cycles and supports cancellation", () => {
  const lockfile = `__metadata:\n  version: 8\n\n"a@npm:1.0.0":\n  version: 1.0.0\n  resolution: "a@npm:1.0.0"\n  dependencies:\n    b: "npm:1.0.0"\n\n"b@npm:1.0.0":\n  version: 1.0.0\n  resolution: "b@npm:1.0.0"\n  dependencies:\n    a: "npm:1.0.0"\n`;
  const result = parseYarnDependencies({
    manifests: [
      {
        path: "/workspace/package.json",
        relativeDirectory: ".",
        content: '{"dependencies":{"a":"1.0.0"}}',
      },
    ],
    lockfile,
    lockfilePath: "/workspace/yarn.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    options,
  });
  assert.equal(result.dependencies.length, 2);

  const controller = new AbortController();
  controller.abort();
  const cancelled = parseYarnDependencies({
    manifests: [],
    lockfile,
    lockfilePath: "/workspace/yarn.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    options,
    signal: controller.signal,
  });
  assert.equal(cancelled.cancelled, true);
  assert.equal(cancelled.dependencies.length, 0);
});

void test("bounds Yarn workspace brace expansion before glob matching", () => {
  const result = parseYarnDependencies({
    manifests: [
      {
        path: "/workspace/package.json",
        relativeDirectory: ".",
        content: JSON.stringify({
          workspaces: [`${"{a,b}".repeat(16)}/*`],
        }),
      },
    ],
    lockfile: "__metadata:\n  version: 8\n",
    lockfilePath: "/workspace/yarn.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    options,
  });

  assert.equal(result.truncated, true);
  assert.equal(
    result.issues.some(
      (issue) =>
        issue.code === "DEPENDENCY_LIMIT" &&
        issue.message.includes("workspace patterns"),
    ),
    true,
  );
});
