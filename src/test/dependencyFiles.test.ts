import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  DEPENDENCY_FILE_GLOB,
  detectPackageManagers,
  findAmbiguousJavaScriptManagers,
  findUnsupportedPackageManagerHints,
} from "../discovery/dependencyFiles";

void test("watches and recognizes NuGet source and named-lock metadata", () => {
  for (const pattern of [
    "NuGet.Config",
    "NuGet.config",
    "nuget.config",
    "packages.*.lock.json",
    "Directory.Packages.props",
    "directory.packages.props",
    "Directory.Build.props",
    "directory.build.props",
    "Directory.Build.targets",
    "directory.build.targets",
  ]) {
    assert.ok(DEPENDENCY_FILE_GLOB.includes(pattern));
  }
  const managers = detectPackageManagers([
    "src/NuGet.Config",
    "src/packages.App.lock.json",
    "src/Directory.Build.targets",
  ]);
  assert.deepEqual(managers.map((manager) => manager.id), ["nuget"]);
});

void test("watches and recognizes workspace Maven CLI configuration", () => {
  assert.ok(DEPENDENCY_FILE_GLOB.includes(".mvn/maven.config"));
  assert.ok(DEPENDENCY_FILE_GLOB.includes(".mvn/jvm.config"));
  assert.ok(DEPENDENCY_FILE_GLOB.includes(".mvn/extensions.xml"));
  assert.deepEqual(
    detectPackageManagers([
      "service/.mvn/maven.config",
      "service/.mvn/jvm.config",
      "service/.mvn/extensions.xml",
    ]).map(
      (manager) => manager.id,
    ),
    ["maven"],
  );
  assert.deepEqual(detectPackageManagers(["service/maven.config"]), []);
  assert.deepEqual(detectPackageManagers(["service/jvm.config"]), []);
  assert.deepEqual(detectPackageManagers(["service/extensions.xml"]), []);
});

void test("detects every Phase 1 package-manager family from standard files", () => {
  const managers = detectPackageManagers([
    "web/package-lock.json",
    "legacy/yarn.lock",
    "workspace/pnpm-lock.yaml",
    "edge/bun.lock",
    "python/requirements.txt",
    "poetry/poetry.lock",
    "pipenv/Pipfile.lock",
    "java/pom.xml",
    "android/build.gradle.kts",
    "dotnet/App.csproj",
    "rust/Cargo.lock",
    "golang/go.mod",
    "php/composer.lock",
  ]);

  assert.deepEqual(
    managers.map((manager) => manager.id),
    [
      "npm",
      "yarn",
      "pnpm",
      "bun",
      "pip",
      "poetry",
      "pipenv",
      "maven",
      "gradle",
      "nuget",
      "cargo",
      "go",
      "composer",
    ],
  );
  assert.equal(managers.every((manager) => !manager.inferred), true);
});

void test("infers npm only when package.json has no stronger JavaScript signal", () => {
  const managers = detectPackageManagers(["apps/site/package.json"]);

  assert.deepEqual(managers, [
    {
      id: "npm",
      displayName: "npm",
      evidence: ["apps/site/package.json"],
      inferred: true,
    },
  ]);
});

void test("uses a packageManager hint instead of npm inference", () => {
  const managers = detectPackageManagers(
    ["package.json"],
    [{ source: "package.json", value: "pnpm@10.15.0+sha512.example" }],
  );

  assert.deepEqual(managers, [
    {
      id: "pnpm",
      displayName: "pnpm",
      evidence: ["package.json#packageManager"],
      inferred: false,
    },
  ]);
});

void test("infers pip from a lone pyproject.toml", () => {
  const managers = detectPackageManagers(["service/pyproject.toml"]);

  assert.equal(managers[0]?.id, "pip");
  assert.equal(managers[0]?.inferred, true);
});

void test("reports conflicting JavaScript lockfile signals deterministically", () => {
  const managers = detectPackageManagers([
    "package.json",
    "yarn.lock",
    "package-lock.json",
    "yarn.lock",
  ]);
  const ambiguous = findAmbiguousJavaScriptManagers(managers);

  assert.deepEqual(
    ambiguous.map((manager) => manager.id),
    ["npm", "yarn"],
  );
  assert.deepEqual(ambiguous[1]?.evidence, ["yarn.lock"]);
});

void test("ignores unrelated files and unsupported packageManager hints", () => {
  const managers = detectPackageManagers(
    ["README.md", "src/package.ts"],
    [{ source: "package.json", value: "unknown@1.0.0" }],
  );

  assert.deepEqual(managers, []);
});

void test("infers npm for a lockless sibling project in a mixed monorepo", () => {
  const managers = detectPackageManagers([
    "apps/yarn-app/package.json",
    "apps/yarn-app/yarn.lock",
    "tools/lockless/package.json",
  ]);

  assert.deepEqual(
    managers.map((manager) => [manager.id, manager.inferred]),
    [
      ["npm", true],
      ["yarn", false],
    ],
  );
  assert.deepEqual(managers[0]?.evidence, ["tools/lockless/package.json"]);
});

void test("does not misclassify an explicit unsupported manager as npm", () => {
  const hints = [{ source: "package.json", value: "deno@2.0.0" }];
  const managers = detectPackageManagers(["package.json"], hints);

  assert.deepEqual(managers, []);
  assert.deepEqual(findUnsupportedPackageManagerHints(hints), hints);
});

void test("rejects malformed or unbounded packageManager hints", () => {
  const hints = [
    { source: "one/package.json", value: "npm@" },
    { source: "two/package.json", value: `pnpm@${"1".repeat(300)}` },
    { source: "three/package.json", value: "yarn@4.1.0\nforged" },
  ];

  assert.deepEqual(findUnsupportedPackageManagerHints(hints), hints);
});
