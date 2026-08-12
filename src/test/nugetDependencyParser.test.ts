import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { parseNugetDependencies } from "../package-managers/nuget/NugetDependencyParser";

const fixtureDirectory = join(
  process.cwd(),
  "src",
  "test",
  "fixtures",
  "nuget",
  "graph",
);

function parseFixture(): ReturnType<typeof parseNugetDependencies> {
  return parseNugetDependencies({
    projectXml: readFileSync(join(fixtureDirectory, "Fixture.csproj"), "utf8"),
    manifestPath: "/workspace/Fixture.csproj",
    lockfile: readFileSync(
      join(fixtureDirectory, "packages.lock.json"),
      "utf8",
    ),
    lockfilePath: "/workspace/packages.lock.json",
  });
}

void test("parses NuGet direct and transitive lock graph", () => {
  const result = parseFixture();
  const json = result.dependencies.find(
    (dependency) => dependency.name === "Newtonsoft.Json",
  );
  const transitive = result.dependencies.find(
    (dependency) => dependency.name === "Example.Transitive",
  );
  assert.equal(json?.installedVersion, "13.0.3");
  assert.equal(json?.requestedVersion, "[13.0.3, )");
  assert.equal(json?.dependencyType, "direct");
  assert.equal(transitive?.dependencyType, "transitive");
  assert.equal(transitive?.parent, "Example.Direct");
  assert.deepEqual(transitive?.metadata?.targetFrameworks, ["net8.0"]);
});

void test("does not pretend PackageReference constraints are installed versions", () => {
  const result = parseNugetDependencies({
    projectXml:
      '<Project><ItemGroup><PackageReference Include="Example.Package" Version="1.2.3" /></ItemGroup></Project>',
    manifestPath: "/workspace/App.csproj",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
  assert.equal(result.issues.some((issue) => issue.code === "NO_LOCKFILE"), true);
});

void test("parses exact packages.config versions and development markers", () => {
  const result = parseNugetDependencies({
    packagesConfigXml: `<?xml version="1.0"?>
<packages>
  <package id="NLog" version="5.3.4" />
  <package id="Build.Tool" version="2.0.0" developmentDependency="true" />
</packages>`,
    manifestPath: "/workspace/packages.config",
  });
  assert.equal(result.dependencies.length, 2);
  assert.equal(
    result.dependencies.find((dependency) => dependency.name === "Build.Tool")
      ?.environment,
    "development",
  );
  assert.equal(
    result.dependencies.every(
      (dependency) => dependency.resolutionStatus === "resolved",
    ),
    true,
  );
});

void test("supports version 3 NuGet lock target aliases", () => {
  const result = parseNugetDependencies({
    projectXml:
      '<Project><ItemGroup><PackageReference Include="Example" /></ItemGroup></Project>',
    manifestPath: "/workspace/App.csproj",
    lockfile: JSON.stringify({
      version: 3,
      "net8.0/win-x64": {
        framework: "net8.0",
        dependencies: {
          Example: { type: "Direct", requested: "[1.0.0, )", resolved: "1.2.0" },
        },
      },
    }),
  });
  assert.equal(result.dependencies[0]?.installedVersion, "1.2.0");
  assert.deepEqual(result.dependencies[0]?.metadata?.targetFrameworks, ["net8.0"]);
});

void test("rejects non-exact versions forged into packages.lock.json", () => {
  const result = parseNugetDependencies({
    projectXml:
      '<Project><ItemGroup><PackageReference Include="Example" Version="1.2.0" /></ItemGroup></Project>',
    manifestPath: "/workspace/App.csproj",
    lockfile: JSON.stringify({
      version: 1,
      dependencies: {
        "net8.0": {
          Example: {
            type: "Direct",
            requested: "[1.2.0, )",
            resolved: "*",
          },
        },
      },
    }),
    lockfilePath: "/workspace/packages.lock.json",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "");
  assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
  assert.equal(
    result.issues.some((issue) => issue.code === "INVALID_LOCKFILE"),
    true,
  );
});

void test("normalizes NuGet build metadata before provider identity mapping", () => {
  const result = parseNugetDependencies({
    projectXml:
      '<Project><ItemGroup><PackageReference Include="Example" Version="1.2.3" /></ItemGroup></Project>',
    manifestPath: "/workspace/App.csproj",
    lockfile: JSON.stringify({
      version: 1,
      dependencies: {
        "net8.0": {
          Example: {
            type: "Direct",
            requested: "[1.2.3, )",
            resolved: "1.2.3+private.7",
          },
        },
      },
    }),
    lockfilePath: "/workspace/packages.lock.json",
  });
  assert.equal(result.dependencies[0]?.installedVersion, "1.2.3");
  assert.equal(
    result.dependencies[0]?.metadata?.originalResolvedVersion,
    "1.2.3+private.7",
  );
  assert.equal(result.dependencies[0]?.resolutionStatus, "resolved");
});

void test("rejects unsafe XML and unsupported NuGet lock versions", () => {
  const unsafe = parseNugetDependencies({
    projectXml:
      '<!DOCTYPE Project [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Project>&xxe;</Project>',
    manifestPath: "/workspace/App.csproj",
  });
  assert.equal(unsafe.dependencies.length, 0);
  assert.equal(
    unsafe.issues.some((issue) => issue.code === "INVALID_MANIFEST"),
    true,
  );
  const unsupported = parseNugetDependencies({
    projectXml: "<Project />",
    manifestPath: "/workspace/App.csproj",
    lockfile: '{"version":99,"dependencies":{}}',
  });
  assert.equal(
    unsupported.issues.some((issue) => issue.code === "UNSUPPORTED_LOCKFILE"),
    true,
  );
});

void test("honors NuGet parser cancellation", () => {
  const controller = new AbortController();
  controller.abort();
  const result = parseNugetDependencies({
    projectXml: "<Project />",
    manifestPath: "/workspace/App.csproj",
    signal: controller.signal,
  });
  assert.equal(result.cancelled, true);
});
