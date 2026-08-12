import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { Module } from "node:module";
import { join } from "node:path";
import { test } from "node:test";

import {
  detectPoetryManifest,
  isPoetryManifest,
  MAX_POETRY_MANIFEST_DETECTION_CHARACTERS,
  MAX_POETRY_MANIFEST_DETECTION_LINES,
} from "../package-managers/poetry/poetryManifestDetection";
import { parsePoetryManifest } from "../package-managers/poetry/poetryParser";
import type {
  DependencyScanResult,
  DetectionResult,
  ScanOptions,
} from "../package-managers/PackageManagerAdapter";

const fixturePath = join(
  process.cwd(),
  "src",
  "test",
  "fixtures",
  "poetry",
  "pep621-pyproject.toml",
);
const manifestText = readFileSync(fixturePath, "utf8");

function lineLimitedPoetryManifest(): string {
  return `[project]
name = "bounded-poetry"
version = "1.0.0"
dependencies = ["requests>=2.31,<3"]
${"\n".repeat(MAX_POETRY_MANIFEST_DETECTION_LINES + 1)}[build-system]
requires = ["poetry-core>=2.0"]
build-backend = "poetry.core.masonry.api"
`;
}

function longMarkerPoetryManifest(): string {
  return `[project]
name = "bounded-poetry"
version = "1.0.0"
dependencies = ["requests>=2.31,<3"]
[build-system]
requires = ["poetry-core>=2.0"]
build-backend = "poetry.core.masonry.api" # ${"x".repeat(20 * 1024)}
`;
}

interface FakeUri {
  readonly scheme: "file";
  readonly path: string;
  readonly fsPath: string;
  toString(): string;
}

function fakeUri(path: string): FakeUri {
  return {
    scheme: "file",
    path,
    fsPath: `C:${path.replaceAll("/", "\\")}`,
    toString: () => `file://${path}`,
  };
}

type ModuleLoader = (
  request: string,
  parent: unknown,
  isMain: boolean,
) => unknown;

interface PoetryAdapterInstance {
  scan(
    workspaceFolder: FakeUri,
    options: ScanOptions,
    signal?: AbortSignal,
  ): Promise<DependencyScanResult>;
}

interface PoetryAdapterModule {
  readonly PoetryAdapter: new () => PoetryAdapterInstance;
}

async function loadPoetryAdapter(
  vscode: object,
): Promise<PoetryAdapterModule> {
  const loader = Module as unknown as { _load: ModuleLoader };
  const originalLoad = loader._load;
  loader._load = function loadWithVscodeStub(
    this: unknown,
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    return request === "vscode"
      ? vscode
      : originalLoad.call(this, request, parent, isMain);
  };
  try {
    return (await import(
      "../package-managers/poetry/PoetryAdapter.js"
    )) as unknown as PoetryAdapterModule;
  } finally {
    loader._load = originalLoad;
  }
}

void test("recognizes Poetry 2 PEP 621 manifests only with the Poetry build backend", () => {
  assert.equal(isPoetryManifest(manifestText), true);
  assert.equal(
    isPoetryManifest('[tool.poetry.dependencies]\nrequests = "^2"\n'),
    true,
  );
  assert.equal(
    isPoetryManifest(
      '[project]\nname = "not-poetry"\n[build-system]\nbuild-backend = "hatchling.build"\n',
    ),
    false,
  );
  assert.equal(
    isPoetryManifest(
      '[project]\nname = "not-poetry"\n# build-backend = "poetry.core.masonry.api"\n',
    ),
    false,
  );
  assert.equal(
    isPoetryManifest(
      `${" ".repeat(MAX_POETRY_MANIFEST_DETECTION_CHARACTERS + 1)}\n[tool.poetry]\n`,
    ),
    false,
  );
});

void test("returns indeterminate when bounded line inspection cannot disprove Poetry", () => {
  for (const text of [
    lineLimitedPoetryManifest(),
    longMarkerPoetryManifest(),
  ]) {
    assert.ok(Buffer.byteLength(text, "utf8") < 2 * 1024 * 1024);
    assert.equal(detectPoetryManifest(text), "indeterminate");
    assert.equal(isPoetryManifest(text), false);
  }
  assert.equal(
    detectPoetryManifest('[project]\nname = "hatch"\n'),
    "not-poetry",
  );
});

void test("parses unlocked Poetry 2 PEP 621 dependencies as unresolved", async () => {
  const parsed = await parsePoetryManifest({
    pyprojectText: manifestText,
    manifestPath: "/workspace/pyproject.toml",
    projectPath: "/workspace",
    workspacePath: "/workspace",
  });

  assert.equal(parsed.dependencies.length, 1);
  assert.equal(parsed.dependencies[0]?.name, "requests");
  assert.equal(parsed.dependencies[0]?.requestedVersion, ">=2.31,<3");
  assert.equal(parsed.dependencies[0]?.installedVersion, "");
  assert.equal(parsed.dependencies[0]?.resolutionStatus, "unresolved");
  assert.ok(
    parsed.errors.some(
      (error) =>
        error.code === "DEPENDENCY_UNRESOLVED" &&
        error.packageName === "requests",
    ),
  );
});

void test("adapter keeps an unlocked Poetry 2 project in unresolved coverage", async () => {
  let bytes = new TextEncoder().encode(manifestText);
  const workspaceUri = fakeUri("/workspace");
  const manifestUri = fakeUri("/workspace/pyproject.toml");
  const project: DetectionResult["projects"][number] = {
    id: "poetry:file:///workspace",
    rootUri: workspaceUri as never,
    manifestUris: [manifestUri as never],
    lockfileUris: [],
  };
  const detection: DetectionResult = {
    detected: true,
    projects: [project],
    errors: [],
    truncated: false,
  };
  const { PoetryAdapter } = await loadPoetryAdapter({
    workspace: {
      fs: {
        stat: async () => ({ size: bytes.byteLength }),
        readFile: async () => bytes,
      },
    },
  });
  const adapter = new PoetryAdapter();
  const scan = async (text: string): Promise<DependencyScanResult> => {
    bytes = new TextEncoder().encode(text);
    return adapter.scan(workspaceUri, {
      includeDevDependencies: true,
      includeTransitiveDependencies: true,
      preDetectedResult: detection,
    });
  };
  const result = await scan(manifestText);

  assert.ok(result.errors.some((error) => error.code === "NO_LOCKFILE"));
  assert.ok(
    result.errors.some(
      (error) =>
        error.code === "DEPENDENCY_UNRESOLVED" &&
        error.packageName === "requests",
    ),
  );
  assert.equal(result.dependencies[0]?.resolutionStatus, "unresolved");
  assert.equal(result.projectCoverage.length, 1);
  assert.equal(result.projectCoverage[0]?.discovered, 1);
  assert.equal(result.projectCoverage[0]?.resolved, 0);
  assert.equal(result.projectCoverage[0]?.checked, 0);
  assert.equal(result.projectCoverage[0]?.unresolved, 1);

  for (const indeterminateManifest of [
    lineLimitedPoetryManifest(),
    longMarkerPoetryManifest(),
  ]) {
    const bounded = await scan(indeterminateManifest);
    assert.equal(bounded.dependencies.length, 0);
    assert.ok(
      bounded.errors.some((error) => error.code === "DEPENDENCY_LIMIT"),
    );
    assert.equal(bounded.projectCoverage.length, 1);
    assert.equal(bounded.projectCoverage[0]?.discovered, 0);
    assert.equal(bounded.projectCoverage[0]?.checked, 0);
  }
});
