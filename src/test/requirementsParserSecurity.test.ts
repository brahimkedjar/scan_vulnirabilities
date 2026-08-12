import { strict as assert } from "node:assert";
import { test } from "node:test";

import { DEFAULT_CARGO_PARSER_LIMITS } from "../package-managers/cargo/CargoDependencyParser";
import { DEFAULT_COMPOSER_PARSER_LIMITS } from "../package-managers/composer/ComposerDependencyParser";
import { MAX_WORKSPACE_DEPENDENCY_RECORDS } from "../package-managers/dependencyRecordBudget";
import { DEFAULT_GO_MODULES_PARSER_LIMITS } from "../package-managers/go/GoModulesParser";
import { DEFAULT_NPM_DEPENDENCY_PARSER_LIMITS } from "../package-managers/npm/NpmDependencyParser";
import { DEFAULT_NUGET_PARSER_LIMITS } from "../package-managers/nuget/NugetDependencyParser";
import { MAX_PARSED_DEPENDENCIES } from "../package-managers/python/parserLimits";
import { parseRequirements } from "../package-managers/python/requirementsParser";
import {
  MAX_EDGES,
  MAX_PACKAGES,
} from "../package-managers/yarn/JavaScriptParserTypes";

function parse(text: string): ReturnType<typeof parseRequirements> {
  return parseRequirements({
    text,
    manifestPath: "/workspace/requirements.txt",
    projectPath: "/workspace",
    workspacePath: "/workspace",
    environment: "production",
  });
}

void test("source-changing pip directives make every requirement unsupported", () => {
  const directives = [
    "--no-index",
    "--no-index=unexpected",
    "-f https://packages.example/simple",
    "-f",
    "--find-links=https://packages.example/wheels",
    "--find-links",
    "--index-url",
    "--extra-index-url=https://packages.example/simple",
  ];

  for (const directive of directives) {
    const result = parse(`${directive}\nrequests==2.31.0\nidna==3.7\n`);
    assert.equal(result.dependencies.length, 2, directive);
    assert.equal(
      result.dependencies.every(
        (dependency) =>
          dependency.resolutionStatus === "unsupported" &&
          dependency.installedVersion === "",
      ),
      true,
      directive,
    );
    assert.equal(
      result.errors.filter(
        (error) => error.code === "UNSUPPORTED_PACKAGE_SOURCE",
      ).length,
      2,
      directive,
    );
  }
});

void test("the official PyPI simple index preserves exact resolution", () => {
  const result = parse(
    "--index-url https://pypi.org/simple/\nrequests==2.31.0\n",
  );

  assert.equal(result.errors.length, 0);
  assert.equal(result.dependencies[0]?.resolutionStatus, "resolved");
  assert.equal(result.dependencies[0]?.installedVersion, "2.31.0");
});

void test("pure parser record ceilings stay aligned with the scan-wide memory bound", () => {
  assert.equal(MAX_WORKSPACE_DEPENDENCY_RECORDS, 10_000);
  assert.equal(MAX_PARSED_DEPENDENCIES, MAX_WORKSPACE_DEPENDENCY_RECORDS);
  assert.equal(MAX_PACKAGES, MAX_WORKSPACE_DEPENDENCY_RECORDS);
  assert.equal(
    DEFAULT_NPM_DEPENDENCY_PARSER_LIMITS.maxPackages,
    MAX_WORKSPACE_DEPENDENCY_RECORDS,
  );
  assert.equal(
    DEFAULT_CARGO_PARSER_LIMITS.maxPackages,
    MAX_WORKSPACE_DEPENDENCY_RECORDS,
  );
  assert.equal(
    DEFAULT_GO_MODULES_PARSER_LIMITS.maxDependencies,
    MAX_WORKSPACE_DEPENDENCY_RECORDS,
  );
  assert.equal(
    DEFAULT_NUGET_PARSER_LIMITS.maxPackages,
    MAX_WORKSPACE_DEPENDENCY_RECORDS,
  );
  assert.equal(
    DEFAULT_COMPOSER_PARSER_LIMITS.maxPackages,
    MAX_WORKSPACE_DEPENDENCY_RECORDS,
  );
  assert.equal(MAX_EDGES, 50_000);

  const text = Array.from(
    { length: MAX_PARSED_DEPENDENCIES + 1 },
    (_value, index) => `package-${index.toString()}==1.0.0`,
  ).join("\n");
  const result = parse(text);
  assert.equal(result.dependencies.length, MAX_PARSED_DEPENDENCIES);
  assert.equal(result.truncated, true);
  assert.ok(result.errors.some((error) => error.code === "DEPENDENCY_LIMIT"));
});
