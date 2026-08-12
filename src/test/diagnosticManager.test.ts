import { strict as assert } from "node:assert";
import { Module } from "node:module";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type { ScanResult } from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";

interface FakeUri {
  readonly path: string;
  toString(): string;
}

class FakePosition {
  public constructor(
    public readonly line: number,
    public readonly character: number,
  ) {}
}

class FakeRange {
  public constructor(
    public readonly start: FakePosition,
    public readonly end: FakePosition,
  ) {}
}

class FakeDiagnostic {
  public code: string | undefined;
  public source: string | undefined;
  public relatedInformation: unknown[] | undefined;

  public constructor(
    public readonly range: FakeRange,
    public readonly message: string,
    public readonly severity: number,
  ) {}
}

class FakeLocation {
  public constructor(
    public readonly uri: FakeUri,
    public readonly range: FakeRange,
  ) {}
}

class FakeDiagnosticRelatedInformation {
  public constructor(
    public readonly location: FakeLocation,
    public readonly message: string,
  ) {}
}

interface FakeDocument {
  readonly lineCount: number;
  getText(): string;
  offsetAt(position: FakePosition): number;
  positionAt(offset: number): FakePosition;
}

type FakeStat = (uri: FakeUri) => Promise<{ readonly size: number }>;
type FakeOpen = (uri: FakeUri) => Promise<FakeDocument>;

interface FakeVscodeState {
  stat: FakeStat;
  open: FakeOpen;
}

function fakeUri(filePath: string): FakeUri {
  return {
    path: filePath,
    toString: () => `file:${filePath}`,
  };
}

function fakeDocument(text: string): FakeDocument {
  return {
    lineCount: 1,
    getText: () => text,
    offsetAt: (position) =>
      position.line >= 1 ? text.length : Math.min(position.character, text.length),
    positionAt: (offset) => new FakePosition(0, offset),
  };
}

function fakeVscode(state: FakeVscodeState): object {
  return {
    workspace: {
      fs: {
        stat: (uri: FakeUri) => state.stat(uri),
      },
      openTextDocument: (uri: FakeUri) => state.open(uri),
    },
    Uri: {
      file: (filePath: string) => fakeUri(filePath),
      parse: (value: string) => fakeUri(value),
    },
    Position: FakePosition,
    Range: FakeRange,
    Diagnostic: FakeDiagnostic,
    Location: FakeLocation,
    DiagnosticRelatedInformation: FakeDiagnosticRelatedInformation,
    DiagnosticSeverity: {
      Error: 0,
      Warning: 1,
      Information: 2,
    },
  };
}

type ModuleLoader = (
  request: string,
  parent: unknown,
  isMain: boolean,
) => unknown;

interface DiagnosticManagerInstance {
  replace(
    scanResults: readonly ScanResult[],
    signal?: AbortSignal,
  ): Promise<boolean>;
  dispose(): void;
}

interface DiagnosticManagerModule {
  readonly DiagnosticManager: new (
    collection: unknown,
  ) => DiagnosticManagerInstance;
}

async function loadDiagnosticManager(
  vscode: object,
): Promise<DiagnosticManagerModule> {
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
      "../diagnostics/DiagnosticManager.js"
    )) as unknown as DiagnosticManagerModule;
  } finally {
    loader._load = originalLoad;
  }
}

function scanResult(count: number): ScanResult {
  const dependencies: Dependency[] = [];
  const vulnerabilities: Vulnerability[] = [];
  for (let index = 0; index < count; index += 1) {
    const name = `package-${index.toString()}`;
    dependencies.push({
      name,
      ecosystem: "npm",
      manifestName: name,
      installedVersion: "1.0.0",
      dependencyType: "direct",
      environment: "production",
      dependencyPath: ["application", `${name}@1.0.0`],
      packageJsonPath: `C:\\workspace\\${name}\\package.json`,
    });
    vulnerabilities.push({
      id: `GHSA-TEST-${index.toString()}`,
      aliases: [],
      packageName: name,
      ecosystem: "npm",
      installedVersion: "1.0.0",
      severity: "HIGH",
      summary: "Test vulnerability",
      references: [],
      source: "OSV",
    });
  }
  return {
    workspacePath: "C:\\workspace",
    scannedAt: "2026-08-11T00:00:00.000Z",
    durationMs: 1,
    packageManagers: ["npm"],
    dependenciesScanned: count,
    vulnerableDependencies: count,
    dependencies,
    vulnerabilities,
    errors: [],
    providerResults: [
      {
        provider: "OSV",
        status: "available",
        dependenciesEligible: count,
        dependenciesSubmitted: count,
        successful: count,
        failed: 0,
        cacheHits: 0,
        staleCacheFallbacks: 0,
        vulnerabilitiesFound: count,
      },
    ],
    cancelled: false,
  };
}

void test("preflights and charges manifest sizes before opening diagnostic documents", async () => {
  let statCalls = 0;
  let openCalls = 0;
  let collectionUpdates: unknown;
  const state: FakeVscodeState = {
    stat: async () => {
      statCalls += 1;
      return { size: 2 * 1024 * 1024 + 1 };
    },
    open: async () => {
      openCalls += 1;
      throw new Error("oversized documents must not be opened");
    },
  };
  const { DiagnosticManager } = await loadDiagnosticManager(fakeVscode(state));
  const collection = {
    set: (updates: unknown) => {
      collectionUpdates = updates;
    },
    clear: () => undefined,
    dispose: () => undefined,
  };
  const manager = new DiagnosticManager(collection);

  assert.equal(await manager.replace([scanResult(20)]), true);
  assert.equal(openCalls, 0);
  assert.equal(
    statCalls,
    8,
    "oversized stat sizes must consume the 16 MiB aggregate budget",
  );
  assert.deepEqual(collectionUpdates, []);

  statCalls = 0;
  state.stat = async () => {
    statCalls += 1;
    throw new Error("virtual file stat unavailable");
  };
  assert.equal(await manager.replace([scanResult(1)]), true);
  assert.equal(statCalls, 1);
  assert.equal(openCalls, 0, "a stat failure must not fall through to open");

  const manifest = '{"dependencies":{"package-0":"^1.0.0"}}';
  state.stat = async () => ({ size: manifest.length });
  state.open = async () => {
    openCalls += 1;
    return fakeDocument(manifest);
  };
  assert.equal(await manager.replace([scanResult(1)]), true);
  assert.equal(openCalls, 1);
  const updates = collectionUpdates as Array<[FakeUri, FakeDiagnostic[]]>;
  assert.equal(updates.length, 1);
  assert.equal(updates[0]?.[1].length, 1);
  assert.equal(updates[0]?.[1][0]?.message.includes("package-0@1.0.0"), true);

  manager.dispose();
});
