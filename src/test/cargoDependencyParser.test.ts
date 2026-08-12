import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { parseCargoDependencies } from "../package-managers/cargo/CargoDependencyParser";

const fixtureDirectory = join(
  process.cwd(),
  "src",
  "test",
  "fixtures",
  "cargo",
  "graph",
);

function parseFixture(): ReturnType<typeof parseCargoDependencies> {
  return parseCargoDependencies({
    cargoToml: readFileSync(join(fixtureDirectory, "Cargo.toml"), "utf8"),
    manifestPath: "/workspace/Cargo.toml",
    cargoLock: readFileSync(join(fixtureDirectory, "Cargo.lock"), "utf8"),
    lockfilePath: "/workspace/Cargo.lock",
    projectPath: "/workspace",
    workspacePath: "/workspace",
  });
}

void test("parses Cargo.lock graph, aliases, optional and dev dependencies", () => {
  const result = parseFixture();
  assert.equal(result.cancelled, false);
  const serde = result.dependencies.find((dependency) => dependency.name === "serde");
  const derive = result.dependencies.find(
    (dependency) => dependency.name === "serde_derive",
  );
  const regex = result.dependencies.find((dependency) => dependency.name === "regex");
  assert.equal(serde?.installedVersion, "1.0.210");
  assert.equal(serde?.dependencyType, "direct");
  assert.equal(derive?.dependencyType, "transitive");
  assert.equal(derive?.parent, "serde@1.0.210");
  assert.equal(regex?.manifestName, "renamed-regex");
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "optional-crate")
      ?.environment,
    "optional",
  );
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "tempfile")
      ?.environment,
    "development",
  );
});

void test("does not submit local Cargo path dependencies as crates.io", () => {
  const result = parseFixture();
  const local = result.dependencies.find(
    (dependency) => dependency.name === "local-helper",
  );
  assert.equal(local?.resolutionStatus, "unsupported");
  assert.equal(local?.installedVersion, "");
});

void test("traverses local Cargo packages to find crates.io children", () => {
  const result = parseCargoDependencies({
    cargoToml: `
[package]
name = "application"
version = "0.1.0"
[dependencies]
local-helper = { path = "../local-helper" }
`,
    manifestPath: "/workspace/application/Cargo.toml",
    cargoLock: `
version = 4
[[package]]
name = "application"
version = "0.1.0"
dependencies = ["local-helper"]
[[package]]
name = "local-helper"
version = "0.2.0"
dependencies = ["serde"]
[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
`,
    lockfilePath: "/workspace/Cargo.lock",
  });

  const local = result.dependencies.find(
    (dependency) => dependency.name === "local-helper",
  );
  const serde = result.dependencies.find((dependency) => dependency.name === "serde");
  assert.equal(local?.resolutionStatus, "unsupported");
  assert.equal(serde?.resolutionStatus, "resolved");
  assert.equal(serde?.dependencyType, "transitive");
  assert.equal(serde?.parent, "local-helper@0.2.0");
});

void test("inherits Cargo workspace dependency declarations", () => {
  const result = parseCargoDependencies({
    cargoToml: `
[package]
name = "member"
version = "0.1.0"
[dependencies]
serde = { workspace = true }
`,
    workspaceToml: `
[workspace]
members = ["member"]
[workspace.dependencies]
serde = "1"
`,
    manifestPath: "/workspace/member/Cargo.toml",
    cargoLock: `
version = 4
[[package]]
name = "member"
version = "0.1.0"
dependencies = ["serde"]
[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
`,
  });
  assert.equal(result.dependencies[0]?.name, "serde");
  assert.equal(result.dependencies[0]?.installedVersion, "1.0.210");
  assert.equal(result.dependencies[0]?.requestedVersion, "1");
});

void test("reports unresolved Cargo ranges without a lockfile", () => {
  const result = parseCargoDependencies({
    cargoToml: `[package]\nname="x"\nversion="0.1.0"\n[dependencies]\nserde="1"`,
    manifestPath: "/workspace/Cargo.toml",
  });
  assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.issues.some((issue) => issue.code === "NO_LOCKFILE"), true);
});

void test("rejects non-exact versions forged into Cargo.lock", () => {
  const result = parseCargoDependencies({
    cargoToml:
      `[package]\nname="x"\nversion="0.1.0"\n[dependencies]\nserde="1"`,
    manifestPath: "/workspace/Cargo.toml",
    cargoLock: `
version = 4
[[package]]
name = "x"
version = "0.1.0"
dependencies = ["serde"]
[[package]]
name = "serde"
version = "^1"
source = "registry+https://github.com/rust-lang/crates.io-index"
`,
    lockfilePath: "/workspace/Cargo.lock",
  });
  const serde = result.dependencies.find((dependency) => dependency.name === "serde");
  assert.equal(serde?.installedVersion, "");
  assert.equal(serde?.resolutionStatus, "unresolved");
  assert.equal(
    result.issues.some((issue) => issue.code === "INVALID_LOCKFILE"),
    true,
  );
});

void test("rejects unsupported Cargo.lock versions and honors cancellation", () => {
  const unsupported = parseCargoDependencies({
    cargoToml: `[package]\nname="x"\nversion="0.1.0"\n[dependencies]\nserde="1"`,
    manifestPath: "/workspace/Cargo.toml",
    cargoLock: `version = 99\npackage = []`,
  });
  assert.equal(
    unsupported.issues.some((issue) => issue.code === "UNSUPPORTED_LOCKFILE"),
    true,
  );
  const controller = new AbortController();
  controller.abort();
  const cancelled = parseCargoDependencies({
    cargoToml: "",
    manifestPath: "/workspace/Cargo.toml",
    signal: controller.signal,
  });
  assert.equal(cancelled.cancelled, true);
});
