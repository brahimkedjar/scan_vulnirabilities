import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { parseBunDependencies } from "../package-managers/bun/BunDependencyParser";
import type {
  JavaScriptParseResult,
  ManifestInput,
} from "../package-managers/yarn/JavaScriptParserTypes";

const fixture = join(
  process.cwd(),
  "src",
  "test",
  "fixtures",
  "bun",
  "text-workspace",
  "bun.lock",
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
  return parseBunDependencies({
    lockfile: readFileSync(fixture, "utf8"),
    lockfilePath: "/workspace/bun.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: fixtureManifests,
    options,
  });
}

void test("parses Bun JSONC graphs, aliases, workspaces, and environments", () => {
  const result = parseFixture();

  assert.equal(result.discovered, 7);
  assert.equal(result.resolved, 6);
  assert.equal(result.unsupported, 1);
  assert.equal(result.unresolved, 0);
  const beta = result.dependencies.find((dependency) => dependency.name === "beta");
  assert.equal(beta?.dependencyType, "transitive");
  assert.equal(beta?.parent, "alpha@1.2.3");
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
});

void test("marks off-registry Bun package sources unsupported", () => {
  const result = parseBunDependencies({
    lockfile: `{"lockfileVersion":2,"workspaces":{"":{"dependencies":{"alpha":"1.0.0"}}},"packages":{"alpha":["alpha@1.0.0","https://example.invalid/alpha.tgz",{},"sha512-x"]}}`,
    lockfilePath: "/workspace/bun.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [manifest(".", { alpha: "1.0.0" })],
    options,
  });
  assert.equal(result.dependencies[0]?.installedVersion, "1.0.0");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unsupported");
  assert.equal(result.unsupported, 1);
});

void test("honors Bun development and transitive scan options", () => {
  const result = parseBunDependencies({
    lockfile: readFileSync(fixture, "utf8"),
    lockfilePath: "/workspace/bun.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: fixtureManifests,
    options: {
      includeDevDependencies: false,
      includeTransitiveDependencies: false,
    },
  });
  assert.equal(result.dependencies.some((dependency) => dependency.name === "dev-tool"), false);
  assert.equal(result.dependencies.some((dependency) => dependency.name === "beta"), false);
});

void test("rejects duplicate Bun JSONC keys and unsupported text versions", () => {
  const duplicate = parseBunDependencies({
    lockfile: '{"lockfileVersion":2,"lockfileVersion":2,"workspaces":{},"packages":{}}',
    lockfilePath: "/workspace/bun.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [],
    options,
  });
  assert.equal(
    duplicate.issues.some((issue) => issue.code === "INVALID_LOCKFILE"),
    true,
  );

  const unsupported = parseBunDependencies({
    lockfile: '{"lockfileVersion":99,"workspaces":{},"packages":{}}',
    lockfilePath: "/workspace/bun.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [],
    options,
  });
  assert.equal(unsupported.issues[0]?.code, "UNSUPPORTED_LOCKFILE");
});

void test("bounds Bun cycles and supports cancellation", () => {
  const cycle = parseBunDependencies({
    lockfile: `{"lockfileVersion":2,"workspaces":{"":{"dependencies":{"a":"1.0.0"}}},"packages":{"a":["a@1.0.0","",{"dependencies":{"b":"1.0.0"}}],"b":["b@1.0.0","",{"dependencies":{"a":"1.0.0"}}]}}`,
    lockfilePath: "/workspace/bun.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [manifest(".", { a: "1.0.0" })],
    options,
  });
  assert.equal(cycle.dependencies.length, 2);

  const controller = new AbortController();
  controller.abort();
  const cancelled = parseBunDependencies({
    lockfile: readFileSync(fixture, "utf8"),
    lockfilePath: "/workspace/bun.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: fixtureManifests,
    options,
    signal: controller.signal,
  });
  assert.equal(cancelled.cancelled, true);
  assert.equal(cancelled.dependencies.length, 0);
});

void test("does not seed Bun dependencies without a discovered workspace manifest", () => {
  const result = parseBunDependencies({
    lockfile: `{"lockfileVersion":2,"workspaces":{"":{"dependencies":{"alpha":"1.0.0"}}},"packages":{"alpha":["alpha@1.0.0","",{},"sha512-alpha"]}}`,
    lockfilePath: "/workspace/bun.lock",
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

void test("reports Bun manifest dependencies missing or stale in the lock", () => {
  const result = parseBunDependencies({
    lockfile: `{"lockfileVersion":2,"workspaces":{"":{"dependencies":{"alpha":"1.0.0"}}},"packages":{"alpha":["alpha@1.0.0","",{},"sha512-alpha"]}}`,
    lockfilePath: "/workspace/bun.lock",
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

void test("does not resolve a Bun direct dependency through an invalid semver range", () => {
  const malformedRange = ">=1.0.0 <";
  const result = parseBunDependencies({
    lockfile: JSON.stringify({
      lockfileVersion: 2,
      workspaces: { "": { dependencies: { alpha: malformedRange } } },
      packages: {
        alpha: ["alpha@1.2.3", "", {}, "sha512-alpha"],
      },
    }),
    lockfilePath: "/workspace/bun.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [manifest(".", { alpha: malformedRange })],
    options,
  });

  const alpha = result.dependencies.find(
    (dependency) => dependency.name === "alpha",
  );
  assert.equal(alpha?.installedVersion, "");
  assert.equal(alpha?.resolutionStatus, "unresolved");
  assert.ok(
    result.issues.some(
      (issue) =>
        issue.code === "DEPENDENCY_UNRESOLVED" &&
        issue.packageName === "alpha",
    ),
  );
});

void test("does not resolve a Bun transitive dependency through an invalid semver range", () => {
  const malformedRange = ">=2.0.0 <";
  const result = parseBunDependencies({
    lockfile: JSON.stringify({
      lockfileVersion: 2,
      workspaces: { "": { dependencies: { alpha: "1.0.0" } } },
      packages: {
        alpha: [
          "alpha@1.0.0",
          "",
          { dependencies: { beta: malformedRange } },
          "sha512-alpha",
        ],
        beta: ["beta@2.4.0", "", {}, "sha512-beta"],
      },
    }),
    lockfilePath: "/workspace/bun.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    manifests: [manifest(".", { alpha: "1.0.0" })],
    options,
  });

  const beta = result.dependencies.find(
    (dependency) => dependency.name === "beta",
  );
  assert.equal(beta?.installedVersion, "");
  assert.equal(beta?.resolutionStatus, "unresolved");
  assert.ok(
    result.issues.some(
      (issue) =>
        issue.code === "DEPENDENCY_UNRESOLVED" && issue.packageName === "beta",
    ),
  );
});
