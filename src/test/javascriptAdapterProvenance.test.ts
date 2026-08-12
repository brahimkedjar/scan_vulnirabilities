import { strict as assert } from "node:assert";
import { test } from "node:test";

import type * as vscode from "vscode";

import { missingJavaScriptProjectManifest } from "../package-managers/JavaScriptProjectProvenance";
import type { ScanResult } from "../models/ScanResult";
import { scanCoverageIsComplete } from "../status/statusModel";

function uri(path: string): vscode.Uri {
  return {
    scheme: "file",
    fsPath: path,
    path: path.replaceAll("\\", "/"),
  } as vscode.Uri;
}

void test("pnpm, Bun, and Yarn adapter gates reject orphan lockfiles", () => {
  for (const [adapterId, displayName, lockName] of [
    ["pnpm", "pnpm", "pnpm-lock.yaml"],
    ["bun", "Bun", "bun.lock"],
    ["yarn", "Yarn", "yarn.lock"],
  ] as const) {
    const workspace = uri("C:\\workspace");
    const failure = missingJavaScriptProjectManifest(
      adapterId,
      displayName,
      workspace,
      {
        id: `${adapterId}:fixture`,
        rootUri: workspace,
        manifestUris: [],
        lockfileUris: [uri(`C:\\workspace\\${lockName}`)],
      },
    );
    assert.notEqual(failure, undefined, adapterId);
    if (failure === undefined) {
      continue;
    }
    assert.equal(failure.error.code, "INVALID_MANIFEST", adapterId);
    assert.equal(failure.coverage.resolved, 0, adapterId);
    assert.deepEqual(failure.coverage.manifestPaths, [], adapterId);

    const scanResult: ScanResult = {
      workspacePath: workspace.fsPath,
      scannedAt: "2026-08-12T00:00:00.000Z",
      durationMs: 0,
      packageManagers: [adapterId],
      dependenciesScanned: 0,
      vulnerableDependencies: 0,
      vulnerabilities: [],
      dependencies: [],
      errors: [failure.error],
      providerResults: [],
      projectCoverage: [failure.coverage],
      cancelled: false,
    };
    assert.equal(scanCoverageIsComplete([scanResult]), false, adapterId);
  }
});

void test("the adapter gate accepts a discovered package.json", () => {
  const workspace = uri("C:\\workspace");
  const failure = missingJavaScriptProjectManifest(
    "pnpm",
    "pnpm",
    workspace,
    {
      id: "pnpm:fixture",
      rootUri: workspace,
      manifestUris: [uri("C:\\workspace\\package.json")],
      lockfileUris: [uri("C:\\workspace\\pnpm-lock.yaml")],
    },
  );

  assert.equal(failure, undefined);
});
