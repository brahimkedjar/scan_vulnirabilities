import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type { Vulnerability } from "../models/Vulnerability";
import {
  DependencyAuditService,
  type DependencyAuditCache,
} from "../services/DependencyAuditService";
import type { VulnerabilityProvider } from "../vulnerability/VulnerabilityProvider";

function dependency(
  name: string,
  ecosystem: string,
  version: string,
  resolutionStatus: "resolved" | "unresolved" = "resolved",
): Dependency {
  return {
    name,
    ecosystem,
    installedVersion: version,
    resolutionStatus,
    dependencyType: "direct",
    environment: "production",
    manifestPath: "/fixture/manifest",
    packageManager: "fixture",
  };
}

class RecordingProvider implements VulnerabilityProvider {
  public readonly name = "OSV";
  public readonly calls: string[][] = [];

  public async checkPackage(
    packageName: string,
    ecosystem: string,
    version: string,
  ): Promise<Vulnerability[]> {
    this.calls.push([ecosystem, packageName, version]);
    return [];
  }

  public async checkPackages(): Promise<Vulnerability[]> {
    return [];
  }
}

void test("audits and deduplicates canonical identities across ecosystems", async () => {
  const provider = new RecordingProvider();
  const writes: unknown[] = [];
  const cache: DependencyAuditCache = {
    get: () => ({ status: "miss" }),
    setMany: async (entries) => {
      writes.push(...entries);
    },
  };
  const service = new DependencyAuditService(provider, cache, {
    maximumConcurrency: 5,
  });

  const result = await service.audit([
    dependency("Requests", "PyPI", "2.31.0"),
    dependency("requests", "PyPI", "2.31.0"),
    dependency("org.example:demo", "Maven", "1.2.3"),
    dependency("range-only", "PyPI", "", "unresolved"),
  ]);

  assert.deepEqual(provider.calls.sort(), [
    ["Maven", "org.example:demo", "1.2.3"],
    ["PyPI", "requests", "2.31.0"],
  ]);
  assert.equal(result.providerResult.dependenciesEligible, 2);
  assert.equal(result.providerResult.successful, 2);
  assert.equal(result.subjectResults.length, 2);
  assert.ok(result.subjectResults.every((subject) => subject.checked));
  assert.ok(
    result.errors.some(
      (error) =>
        error.code === "DEPENDENCY_UNRESOLVED" &&
        error.packageName === "range-only",
    ),
  );
  assert.equal(writes.length, 2);
});
