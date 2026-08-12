import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import { findManifestDependencyOffsets } from "../diagnostics/manifestDependencyLocator";

function dependency(
  manifestName: string,
  packageManager: string,
  manifestPath: string,
): Dependency {
  return {
    name: manifestName,
    manifestName,
    ecosystem: "test",
    installedVersion: "1.0.0",
    dependencyType: "direct",
    environment: "production",
    packageManager,
    manifestPath,
  };
}

function assertLocated(
  text: string,
  name: string,
  packageManager: string,
  manifestPath: string,
): void {
  const offsets = findManifestDependencyOffsets(text, manifestPath, [
    dependency(name, packageManager, manifestPath),
  ]);
  const offset = offsets.get(name);
  assert.ok(offset !== undefined, `${packageManager} declaration was not located`);
  assert.equal(text.slice(offset, offset + name.length), name);
}

void test("locates direct declarations across supported manifest syntaxes", () => {
  const cases: ReadonlyArray<readonly [string, string, string, string]> = [
    ['{"require":{"vendor/package":"1.0.0"}}', "vendor/package", "composer", "composer.json"],
    ["requests==2.19.0 # pinned", "requests", "pip", "requirements.txt"],
    ["[tool.poetry.dependencies]\nrequests = \"2.19.0\"", "requests", "poetry", "pyproject.toml"],
    ["[packages]\nrequests = \"==2.19.0\"", "requests", "pipenv", "Pipfile"],
    ["[dependencies]\nserde = \"1.0\"", "serde", "cargo", "Cargo.toml"],
    ["require (\n  golang.org/x/text v0.3.0\n)", "golang.org/x/text", "go", "go.mod"],
    ["dependencies {\n implementation 'org.example:library:1.0.0'\n}", "org.example:library", "gradle", "build.gradle"],
    ["<dependency><artifactId>commons-text</artifactId></dependency>", "commons-text", "maven", "pom.xml"],
    ["<PackageReference Include=\"Newtonsoft.Json\" Version=\"12.0.1\" />", "Newtonsoft.Json", "nuget", "sample.csproj"],
  ];
  for (const [text, name, manager, path] of cases) {
    assertLocated(text, name, manager, path);
  }
});

void test("prefers a validated adapter-provided offset and rejects forged offsets", () => {
  const text = "prefix requests suffix";
  const manifestPath = "requirements.txt";
  const valid = {
    ...dependency("requests", "pip", manifestPath),
    metadata: { sourceOffset: 7 },
  } satisfies Dependency;
  const forged = {
    ...dependency("requests", "pip", manifestPath),
    metadata: { sourceOffset: 0 },
  } satisfies Dependency;

  assert.equal(
    findManifestDependencyOffsets(text, manifestPath, [valid]).get("requests"),
    7,
  );
  assert.equal(
    findManifestDependencyOffsets(text, manifestPath, [forged]).has("requests"),
    false,
  );
});

void test("does not anchor names from unrelated comments, strings, or sections", () => {
  const text = [
    "# requests==2.19.0",
    "[tool.unrelated]",
    'requests = "2.19.0"',
    "[tool.poetry.dependencies]",
    'safe = "1.0.0"',
  ].join("\n");
  const offsets = findManifestDependencyOffsets(text, "pyproject.toml", [
    dependency("requests", "poetry", "pyproject.toml"),
  ]);
  assert.equal(offsets.has("requests"), false);
});
