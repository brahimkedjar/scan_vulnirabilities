import assert from "node:assert/strict";
import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { NodeFileSystem } from "../core/host/NodeFileSystem";
import {
  scanHeadlessWorkspaces,
  type HeadlessScannerOptions,
} from "../core/scanner/HeadlessScanner";
import type { VulnerabilityProvider } from "../vulnerability/VulnerabilityProvider";

const fixture = join(
  process.cwd(),
  "src",
  "test",
  "fixtures",
  "npm",
  "modern-graph",
);

async function fixtureCopy(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "dependency-auditor-scan-"));
  await cp(fixture, directory, { recursive: true });
  return directory;
}

function options(
  workspacePath: string,
  offline: boolean,
): HeadlessScannerOptions {
  return {
    workspacePaths: [workspacePath],
    includeDevelopment: true,
    includeProduction: true,
    includeTransitive: true,
    offline,
    minimumSeverity: "UNKNOWN" as const,
    maximumDependencies: 10_000,
    maximumFiles: 10_000,
    maximumBytes: 64 * 1024 * 1024,
    timeoutMs: 30_000,
  };
}

void test("headless scanner reuses static npm parsing and can prove complete fake-provider coverage", async () => {
  const directory = await fixtureCopy();
  let queries = 0;
  const provider: VulnerabilityProvider = {
    name: "TEST",
    checkPackage: async () => {
      queries += 1;
      return [];
    },
    checkPackages: async () => [],
  };
  try {
    const result = await scanHeadlessWorkspaces(options(directory, false), {
      fileSystem: new NodeFileSystem(),
      provider,
      clock: { now: () => Date.parse("2026-08-13T00:00:00.000Z") },
    });
    assert.equal(result.status, "complete");
    assert.equal(result.coverage, "complete");
    assert.ok((result.results[0]?.dependencies.length ?? 0) > 0);
    assert.ok(queries > 0);
    assert.equal(result.results[0]?.packageManagers.includes("npm"), true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test("offline scanning performs no provider query and never reports a clean state", async () => {
  const directory = await fixtureCopy();
  let queries = 0;
  const provider: VulnerabilityProvider = {
    name: "MUST_NOT_RUN",
    checkPackage: async () => {
      queries += 1;
      throw new Error("offline provider call");
    },
    checkPackages: async () => {
      queries += 1;
      throw new Error("offline provider call");
    },
  };
  try {
    const result = await scanHeadlessWorkspaces(options(directory, true), {
      fileSystem: new NodeFileSystem(),
      provider,
    });
    assert.equal(queries, 0);
    assert.equal(result.status, "incomplete");
    assert.equal(result.coverage, "unavailable");
    assert.equal(
      result.reasons.some((reason) =>
        reason.message.includes("no authenticated local vulnerability database"),
      ),
      true,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test("a pre-cancelled headless scan exits with cancelled coverage", async () => {
  const directory = await fixtureCopy();
  const controller = new AbortController();
  controller.abort();
  try {
    const result = await scanHeadlessWorkspaces(
      { ...options(directory, true), signal: controller.signal },
      { fileSystem: new NodeFileSystem() },
    );
    assert.equal(result.status, "cancelled");
    assert.equal(result.coverage, "cancelled");
    assert.equal(result.results[0]?.cancelled, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
