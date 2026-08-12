import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { parseGoModules } from "../package-managers/go/GoModulesParser";

const fixtureDirectory = join(
  process.cwd(),
  "src",
  "test",
  "fixtures",
  "go",
  "graph",
);

function parseFixture(): ReturnType<typeof parseGoModules> {
  return parseGoModules({
    goMod: readFileSync(join(fixtureDirectory, "go.mod"), "utf8"),
    goSum: readFileSync(join(fixtureDirectory, "go.sum"), "utf8"),
    manifestPath: "/workspace/go.mod",
    sumPath: "/workspace/go.sum",
  });
}

void test("parses direct and indirect Go module requirements", () => {
  const result = parseFixture();
  const gin = result.dependencies.find(
    (dependency) => dependency.name === "github.com/gin-gonic/gin",
  );
  const text = result.dependencies.find(
    (dependency) => dependency.name === "golang.org/x/text",
  );
  assert.equal(gin?.installedVersion, "v1.10.0");
  assert.equal(gin?.dependencyType, "direct");
  assert.equal(gin?.metadata?.checksumPresent, true);
  assert.equal(text?.dependencyType, "transitive");
  assert.equal(text?.parent, undefined);
  assert.equal(
    result.dependencies.some((dependency) => dependency.name === "example.com/stale"),
    false,
  );
});

void test("handles local and exact remote Go replacements conservatively", () => {
  const result = parseFixture();
  const local = result.dependencies.find(
    (dependency) => dependency.manifestName === "example.com/local",
  );
  const fork = result.dependencies.find(
    (dependency) => dependency.manifestName === "example.com/old-fork",
  );
  assert.equal(local?.resolutionStatus, "unsupported");
  assert.equal(local?.installedVersion, "");
  assert.equal(fork?.name, "example.com/new-fork");
  assert.equal(fork?.installedVersion, "v1.4.0");
});

void test("marks excluded and invalid Go versions unresolved", () => {
  const result = parseGoModules({
    goMod: `module example.com/x
require example.com/a v1.2.3
require example.com/b latest
exclude example.com/a v1.2.3
`,
    manifestPath: "/workspace/go.mod",
  });
  assert.equal(result.dependencies.length, 2);
  assert.equal(
    result.dependencies.every(
      (dependency) => dependency.resolutionStatus === "unresolved",
    ),
    true,
  );
});

void test("does not guess selected Go versions from incomplete static evidence", () => {
  const noChecksum = parseGoModules({
    goMod: `module example.com/x
go 1.22
require example.com/a v1.2.3
`,
    manifestPath: "/workspace/go.mod",
  });
  assert.equal(noChecksum.dependencies[0]?.resolutionStatus, "unresolved");
  assert.equal(noChecksum.dependencies[0]?.installedVersion, "");
  assert.equal(
    noChecksum.issues.some((issue) =>
      issue.message.includes("matching go.sum checksum"),
    ),
    true,
  );

  const legacyGraph = parseGoModules({
    goMod: `module example.com/x
go 1.16
require example.com/a v1.2.3
`,
    goSum: "example.com/a v1.2.3 h1:YWJjZA==\n",
    manifestPath: "/workspace/go.mod",
    sumPath: "/workspace/go.sum",
  });
  assert.equal(legacyGraph.dependencies[0]?.resolutionStatus, "unresolved");
  assert.equal(legacyGraph.dependencies[0]?.installedVersion, "");
  assert.equal(
    legacyGraph.issues.some((issue) =>
      issue.message.includes("Go 1.17+ selected-graph evidence"),
    ),
    true,
  );
});

void test("bounds Go dependency input and reports malformed blocks", () => {
  const bounded = parseGoModules({
    goMod: `module example.com/x
require (
example.com/a v1.0.0
example.com/b v1.0.0
)`,
    manifestPath: "/workspace/go.mod",
    limits: { maxDependencies: 1 },
  });
  assert.equal(bounded.truncated, true);
  const malformed = parseGoModules({
    goMod: "module example.com/x\nrequire (\nexample.com/a v1.0.0",
    manifestPath: "/workspace/go.mod",
  });
  assert.equal(
    malformed.issues.some((issue) => issue.code === "INVALID_MANIFEST"),
    true,
  );
});

void test("honors Go parser cancellation", () => {
  const controller = new AbortController();
  controller.abort();
  const result = parseGoModules({
    goMod: "module example.com/x",
    manifestPath: "/workspace/go.mod",
    signal: controller.signal,
  });
  assert.equal(result.cancelled, true);
  assert.equal(result.dependencies.length, 0);
});
