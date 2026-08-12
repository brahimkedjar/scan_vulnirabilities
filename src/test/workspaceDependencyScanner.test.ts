import { strict as assert } from "node:assert";
import { test } from "node:test";

import type * as vscode from "vscode";

import type { Dependency } from "../models/Dependency";
import { registerDependencyRecordBudget } from "../package-managers/dependencyRecordBudget";
import type { Logger } from "../services/Logger";
import type {
  DependencyScanResult,
  DetectedDependencyProject,
  DetectionResult,
  PackageManagerAdapter,
  ScanOptions,
} from "../package-managers/PackageManagerAdapter";
import { projectsSelectedForScan } from "../package-managers/PackageManagerAdapter";
import { WorkspaceDependencyScanner } from "../package-managers/WorkspaceDependencyScanner";

const WORKSPACE_URI = {
  scheme: "file",
  fsPath: "C:\\fixture",
  path: "/fixture",
} as vscode.Uri;

const LOGGER: Logger = {
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  show: () => undefined,
};

function emptyDetection(detected: boolean): DetectionResult {
  return {
    detected,
    projects: [],
    errors: [],
    truncated: false,
  };
}

function emptyScan(adapter: PackageManagerAdapter): DependencyScanResult {
  return {
    adapterId: adapter.id,
    displayName: adapter.displayName,
    ecosystems: adapter.ecosystems,
    dependencies: [],
    errors: [],
    projectCoverage: [],
    cancelled: false,
  };
}

function project(index: number): DetectedDependencyProject {
  const rootUri = {
    scheme: "file",
    fsPath: `C:\\fixture\\project-${index.toString()}`,
    path: `/fixture/project-${index.toString()}`,
  } as vscode.Uri;
  return {
    id: `project-${index.toString()}`,
    rootUri,
    manifestUris: [] as readonly vscode.Uri[],
    lockfileUris: [] as readonly vscode.Uri[],
  };
}

function dependency(name: string): Dependency {
  return {
    name,
    ecosystem: "npm",
    installedVersion: "1.0.0",
    dependencyType: "direct",
    environment: "production",
    resolutionStatus: "resolved",
    packageManager: "fixture",
    projectPath: "C:\\fixture",
    workspacePath: "C:\\fixture",
  };
}

class ReusingFakeAdapter implements PackageManagerAdapter {
  public readonly id = "fixture";
  public readonly displayName = "Fixture";
  public readonly ecosystems = ["npm"] as const;
  public readonly detection = emptyDetection(true);
  public detectCalls = 0;
  public scanCalls = 0;
  public detectionToken: vscode.CancellationToken | undefined;
  public scannedDetection: DetectionResult | undefined;

  public detect(
    _workspaceFolder: vscode.Uri,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<DetectionResult> {
    this.detectCalls += 1;
    this.detectionToken = cancellationToken;
    return Promise.resolve(this.detection);
  }

  public async scan(
    workspaceFolder: vscode.Uri,
    options: ScanOptions,
  ): Promise<DependencyScanResult> {
    this.scanCalls += 1;
    const detection =
      options.preDetectedResult ??
      (await this.detect(workspaceFolder, options.cancellationToken));
    this.scannedDetection = detection;
    return emptyScan(this);
  }
}

void test("workspace scanning detects each adapter once and reuses that result", async () => {
  const adapter = new ReusingFakeAdapter();
  const scanner = new WorkspaceDependencyScanner([adapter], LOGGER, 1);
  const token = { isCancellationRequested: false } as vscode.CancellationToken;

  const result = await scanner.scan(
    WORKSPACE_URI,
    {
      includeDevDependencies: true,
      includeTransitiveDependencies: true,
      enabledEcosystems: new Set(["npm"]),
      cancellationToken: token,
    },
    new AbortController().signal,
  );

  assert.equal(adapter.detectCalls, 1);
  assert.equal(adapter.scanCalls, 1);
  assert.notEqual(adapter.detectionToken, token);
  assert.equal(adapter.detectionToken?.isCancellationRequested, false);
  assert.equal(adapter.scannedDetection, adapter.detection);
  assert.deepEqual(result.packageManagers, [adapter.id]);
  assert.equal(result.cancelled, false);
});

void test("detection cancellation stops scheduling additional adapters", async () => {
  let cancellationRequested = false;
  let firstDetectCalls = 0;
  let secondDetectCalls = 0;
  const token = {
    get isCancellationRequested(): boolean {
      return cancellationRequested;
    },
  } as vscode.CancellationToken;
  const first: PackageManagerAdapter = {
    id: "a-first",
    displayName: "First",
    ecosystems: ["npm"],
    detect: (_workspaceFolder, receivedToken) => {
      firstDetectCalls += 1;
      assert.ok(receivedToken);
      assert.equal(receivedToken.isCancellationRequested, false);
      cancellationRequested = true;
      return Promise.resolve(emptyDetection(false));
    },
    scan: () => Promise.resolve(emptyScan(first)),
  };
  const second: PackageManagerAdapter = {
    id: "b-second",
    displayName: "Second",
    ecosystems: ["npm"],
    detect: () => {
      secondDetectCalls += 1;
      return Promise.resolve(emptyDetection(false));
    },
    scan: () => Promise.resolve(emptyScan(second)),
  };
  const scanner = new WorkspaceDependencyScanner([second, first], LOGGER, 1);

  const result = await scanner.scan(
    WORKSPACE_URI,
    {
      includeDevDependencies: true,
      includeTransitiveDependencies: true,
      enabledEcosystems: new Set(["npm"]),
      cancellationToken: token,
    },
    new AbortController().signal,
  );

  assert.equal(firstDetectCalls, 1);
  assert.equal(secondDetectCalls, 0);
  assert.equal(result.cancelled, true);
});

void test("AbortSignal cancellation interrupts in-flight project detection", async () => {
  let markStarted: (() => void) | undefined;
  const started = new Promise<void>((resolve) => {
    markStarted = resolve;
  });
  let scanCalls = 0;
  let receivedToken: vscode.CancellationToken | undefined;
  const adapter: PackageManagerAdapter = {
    id: "abort-detection",
    displayName: "Abort detection",
    ecosystems: ["npm"],
    detect: (_workspaceFolder, cancellationToken) => {
      receivedToken = cancellationToken;
      markStarted?.();
      return new Promise<DetectionResult>((resolve) => {
        cancellationToken?.onCancellationRequested(() => {
          resolve(emptyDetection(false));
        });
      });
    },
    scan: () => {
      scanCalls += 1;
      return Promise.resolve(emptyScan(adapter));
    },
  };
  const scanner = new WorkspaceDependencyScanner([adapter], LOGGER, 1);
  const controller = new AbortController();
  const pending = scanner.scan(
    WORKSPACE_URI,
    {
      includeDevDependencies: true,
      includeTransitiveDependencies: true,
      enabledEcosystems: new Set(["npm"]),
    },
    controller.signal,
  );
  await started;
  controller.abort();
  const result = await pending;

  assert.equal(receivedToken?.isCancellationRequested, true);
  assert.equal(scanCalls, 0);
  assert.equal(result.cancelled, true);
});

void test("bounds actual project scans at four while preserving full project context", async () => {
  let active = 0;
  let maximumActive = 0;
  let scanCalls = 0;
  const scannedProjectIds: string[] = [];
  const adapter: PackageManagerAdapter = {
    id: "projects",
    displayName: "Projects",
    ecosystems: ["npm"],
    detect: () =>
      Promise.resolve({
        detected: true,
        projects: Array.from({ length: 8 }, (_value, index) => project(index)),
        errors: [],
        truncated: false,
      }),
    scan: async (_workspaceFolder, options) => {
      const detection = options.preDetectedResult;
      assert.ok(detection);
      assert.equal(detection.projects.length, 8);
      const selectedProjects = projectsSelectedForScan(detection, options);
      assert.equal(selectedProjects.length, 1);
      const selected = selectedProjects[0];
      assert.ok(selected);
      scannedProjectIds.push(selected.id);
      scanCalls += 1;
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
      active -= 1;
      return emptyScan(adapter);
    },
  };
  const scanner = new WorkspaceDependencyScanner([adapter], LOGGER, 4);

  const result = await scanner.scan(
    WORKSPACE_URI,
    {
      includeDevDependencies: true,
      includeTransitiveDependencies: true,
      enabledEcosystems: new Set(["npm"]),
    },
    new AbortController().signal,
  );

  assert.equal(result.cancelled, false);
  assert.equal(scanCalls, 8);
  assert.equal(maximumActive, 4);
  assert.deepEqual(
    scannedProjectIds.sort(),
    Array.from({ length: 8 }, (_value, index) => `project-${index.toString()}`),
  );
});

void test("stops scheduling projects and truncates retained records at the scan-wide cap", async () => {
  let scanCalls = 0;
  const adapter: PackageManagerAdapter = {
    id: "bounded",
    displayName: "Bounded",
    ecosystems: ["npm"],
    detect: () =>
      Promise.resolve({
        detected: true,
        projects: Array.from({ length: 5 }, (_value, index) => project(index)),
        errors: [],
        truncated: false,
      }),
    scan: (_workspaceFolder, options) => {
      const detection = options.preDetectedResult;
      assert.ok(detection);
      const id = projectsSelectedForScan(detection, options)[0]?.id ?? "missing";
      scanCalls += 1;
      return Promise.resolve({
        ...emptyScan(adapter),
        dependencies: [dependency(`${id}-a`), dependency(`${id}-b`)],
      });
    },
  };
  const scanner = new WorkspaceDependencyScanner([adapter], LOGGER, 2, 3);

  const result = await scanner.scan(
    WORKSPACE_URI,
    {
      includeDevDependencies: true,
      includeTransitiveDependencies: true,
      enabledEcosystems: new Set(["npm"]),
    },
    new AbortController().signal,
  );

  assert.equal(result.cancelled, false);
  assert.equal(scanCalls, 3);
  assert.equal(result.dependencies.length, 3);
  assert.deepEqual(
    result.dependencies.map((entry) => entry.name),
    ["project-0-a", "project-0-b", "project-1-a"],
  );
  assert.ok(
    result.errors.some(
      (error) =>
        error.code === "DEPENDENCY_LIMIT" &&
        error.message.includes("record limit of 3"),
    ),
  );
});

void test("bounds project scans globally across multi-root workspaces", async () => {
  let active = 0;
  let maximumActive = 0;
  let detectCalls = 0;
  let scanCalls = 0;
  const adapter: PackageManagerAdapter = {
    id: "global-projects",
    displayName: "Global projects",
    ecosystems: ["npm"],
    detect: (workspaceFolder) => {
      detectCalls += 1;
      const selectedProject: DetectedDependencyProject = {
        id: workspaceFolder.path,
        rootUri: workspaceFolder,
        manifestUris: [],
        lockfileUris: [],
      };
      return Promise.resolve({
        detected: true,
        projects: [selectedProject],
        errors: [],
        truncated: false,
      });
    },
    scan: async (_workspaceFolder, options) => {
      const detection = options.preDetectedResult;
      assert.ok(detection);
      assert.equal(projectsSelectedForScan(detection, options).length, 1);
      scanCalls += 1;
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
      active -= 1;
      return emptyScan(adapter);
    },
  };
  const scanner = new WorkspaceDependencyScanner([adapter], LOGGER, 4);
  const roots = Array.from(
    { length: 8 },
    (_value, index) =>
      ({
        ...WORKSPACE_URI,
        fsPath: `C:\\fixture-${index.toString()}`,
        path: `/fixture-${index.toString()}`,
      }) as vscode.Uri,
  );

  const result = await scanner.scanMany(
    roots,
    {
      includeDevDependencies: true,
      includeTransitiveDependencies: true,
      enabledEcosystems: new Set(["npm"]),
    },
    new AbortController().signal,
  );

  assert.equal(result.cancelled, false);
  assert.equal(detectCalls, 8);
  assert.equal(scanCalls, 8);
  assert.equal(maximumActive, 4);
});

void test("deduplicates overlapping roots and scans from the shallowest owner", async () => {
  const outer = {
    ...WORKSPACE_URI,
    fsPath: "C:\\repo",
    path: "/repo",
  } as vscode.Uri;
  const inner = {
    ...WORKSPACE_URI,
    fsPath: "C:\\repo\\app",
    path: "/repo/app",
  } as vscode.Uri;
  const sharedProject: DetectedDependencyProject = {
    id: "shared-project",
    rootUri: inner,
    manifestUris: [],
    lockfileUris: [],
  };
  const scannedFrom: string[] = [];
  const adapter: PackageManagerAdapter = {
    id: "overlap",
    displayName: "Overlap",
    ecosystems: ["npm"],
    detect: () =>
      Promise.resolve({
        detected: true,
        projects: [sharedProject],
        errors: [],
        truncated: false,
      }),
    scan: (workspaceFolder, options) => {
      assert.equal(
        projectsSelectedForScan(
          options.preDetectedResult ?? emptyDetection(false),
          options,
        ).length,
        1,
      );
      scannedFrom.push(workspaceFolder.path);
      return Promise.resolve(emptyScan(adapter));
    },
  };
  const scanner = new WorkspaceDependencyScanner([adapter], LOGGER, 2);

  const result = await scanner.scanMany(
    [inner, outer],
    {
      includeDevDependencies: true,
      includeTransitiveDependencies: true,
      enabledEcosystems: new Set(["npm"]),
    },
    new AbortController().signal,
  );

  assert.equal(result.cancelled, false);
  assert.deepEqual(scannedFrom, ["/repo"]);
});

void test("deduplicates mixed-case Windows file roots under the shallow owner", async () => {
  const outer = {
    ...WORKSPACE_URI,
    fsPath: "C:\\Repo",
    path: "/C:/Repo",
  } as vscode.Uri;
  const inner = {
    ...WORKSPACE_URI,
    fsPath: "c:\\repo\\app",
    path: "/c:/repo/app",
  } as vscode.Uri;
  const scannedFrom: string[] = [];
  const adapter: PackageManagerAdapter = {
    id: "mixed-case-overlap",
    displayName: "Mixed-case overlap",
    ecosystems: ["npm"],
    detect: (workspaceFolder) => {
      const rootUri =
        workspaceFolder.path === outer.path
          ? ({ ...inner, path: "/C:/Repo/App" } as vscode.Uri)
          : inner;
      const inheritedSourcePolicy = {
        ...outer,
        fsPath: "C:\\Repo\\settings.gradle",
        path: "/C:/Repo/settings.gradle",
      } as vscode.Uri;
      return Promise.resolve({
        detected: true,
        projects: [
          {
            id: rootUri.path,
            rootUri,
            manifestUris:
              workspaceFolder.path === outer.path
                ? [rootUri, inheritedSourcePolicy]
                : [rootUri],
            lockfileUris: [],
          },
        ],
        errors: [],
        truncated: false,
      });
    },
    scan: (workspaceFolder) => {
      scannedFrom.push(workspaceFolder.path);
      return Promise.resolve(emptyScan(adapter));
    },
  };
  const scanner = new WorkspaceDependencyScanner([adapter], LOGGER, 2);

  const result = await scanner.scanMany(
    [inner, outer],
    {
      includeDevDependencies: true,
      includeTransitiveDependencies: true,
      enabledEcosystems: new Set(["npm"]),
    },
    new AbortController().signal,
  );

  assert.equal(result.cancelled, false);
  assert.deepEqual(scannedFrom, ["/C:/Repo"]);
});

void test("shares the outer dependency-record cap across sequential workspace roots", async () => {
  let scanCalls = 0;
  const adapter: PackageManagerAdapter = {
    id: "multi-root",
    displayName: "Multi-root",
    ecosystems: ["npm"],
    detect: () =>
      Promise.resolve({
        detected: true,
        projects: [project(0)],
        errors: [],
        truncated: false,
      }),
    scan: () => {
      scanCalls += 1;
      return Promise.resolve({
        ...emptyScan(adapter),
        dependencies: [
          dependency(`root-${scanCalls.toString()}-a`),
          dependency(`root-${scanCalls.toString()}-b`),
        ],
      });
    },
  };
  const scanner = new WorkspaceDependencyScanner([adapter], LOGGER, 1, 3);
  const signal = new AbortController().signal;
  const outerBudget = registerDependencyRecordBudget(signal, 3);
  try {
    const first = await scanner.scan(
      WORKSPACE_URI,
      {
        includeDevDependencies: true,
        includeTransitiveDependencies: true,
        enabledEcosystems: new Set(["npm"]),
      },
      signal,
    );
    const second = await scanner.scan(
      {
        ...WORKSPACE_URI,
        fsPath: "C:\\fixture-two",
        path: "/fixture-two",
      } as vscode.Uri,
      {
        includeDevDependencies: true,
        includeTransitiveDependencies: true,
        enabledEcosystems: new Set(["npm"]),
      },
      signal,
    );

    assert.equal(first.dependencies.length, 2);
    assert.equal(second.dependencies.length, 1);
    assert.equal(scanCalls, 2);
    assert.ok(
      second.errors.some((error) => error.code === "DEPENDENCY_LIMIT"),
    );
  } finally {
    outerBudget.dispose();
  }
});
