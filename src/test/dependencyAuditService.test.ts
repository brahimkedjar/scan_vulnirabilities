import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type { Vulnerability } from "../models/Vulnerability";
import {
  DependencyAuditService,
  type DependencyAuditCache,
  type DependencyAuditProgress,
} from "../services/DependencyAuditService";
import {
  type MementoLike,
  VulnerabilityCache,
  type VulnerabilityCacheKey,
} from "../services/VulnerabilityCache";
import type { VulnerabilityProvider } from "../vulnerability/VulnerabilityProvider";

class MemoryMemento implements MementoLike {
  private readonly values = new Map<string, unknown>();
  public updateCount = 0;

  public get<T>(key: string): T | undefined {
    return this.values.get(key) as T | undefined;
  }

  public async update(key: string, value: unknown): Promise<void> {
    this.updateCount += 1;
    if (value === undefined) {
      this.values.delete(key);
    } else {
      this.values.set(key, value);
    }
  }
}

type ProviderHandler = (
  packageName: string,
  ecosystem: string,
  version: string,
  signal?: AbortSignal,
) => Promise<Vulnerability[]>;

class StubProvider implements VulnerabilityProvider {
  public readonly name = "OSV";
  public readonly calls: Array<{
    readonly packageName: string;
    readonly ecosystem: string;
    readonly version: string;
  }> = [];
  public activeCalls = 0;
  public maximumActiveCalls = 0;

  public constructor(private readonly handler: ProviderHandler) {}

  public async checkPackage(
    packageName: string,
    ecosystem: string,
    version: string,
    signal?: AbortSignal,
  ): Promise<Vulnerability[]> {
    this.calls.push({ packageName, ecosystem, version });
    this.activeCalls += 1;
    this.maximumActiveCalls = Math.max(
      this.maximumActiveCalls,
      this.activeCalls,
    );
    try {
      return await this.handler(packageName, ecosystem, version, signal);
    } finally {
      this.activeCalls -= 1;
    }
  }

  public async checkPackages(
    dependencies: Dependency[],
    signal?: AbortSignal,
  ): Promise<Vulnerability[]> {
    const results = await Promise.all(
      dependencies.map((dependency) =>
        this.checkPackage(
          dependency.name,
          dependency.ecosystem,
          dependency.installedVersion,
          signal,
        ),
      ),
    );
    return results.flat();
  }
}

function dependency(
  name: string,
  installedVersion = "1.0.0",
  ecosystem = "npm",
): Dependency {
  return {
    name,
    ecosystem,
    installedVersion,
    dependencyType: "direct",
    environment: "production",
    packageJsonPath: "package.json",
  };
}

function vulnerability(
  packageName: string,
  installedVersion: string,
  id = `OSV-${packageName}`,
): Vulnerability {
  return {
    id,
    aliases: [],
    packageName,
    ecosystem: "npm",
    installedVersion,
    severity: "HIGH",
    summary: "Test vulnerability",
    fixedVersions: [],
    remediationCandidates: [],
    references: ["https://osv.dev/vulnerability/example"],
    source: "OSV",
  };
}

function isVulnerabilityArray(value: unknown): value is Vulnerability[] {
  return (
    Array.isArray(value) &&
    value.every(
      (entry: unknown) =>
        typeof entry === "object" &&
        entry !== null &&
        "id" in entry &&
        typeof entry.id === "string",
    )
  );
}

function createCache(
  memento: MementoLike,
  clock: () => number,
): VulnerabilityCache<Vulnerability[]> {
  return new VulnerabilityCache(memento, {
    ttlMs: 100,
    maximumEntries: 100,
    validateValue: isVulnerabilityArray,
    clock,
  });
}

function cacheKey(packageName: string, version = "1.0.0"): VulnerabilityCacheKey {
  return {
    provider: "OSV",
    ecosystem: "npm",
    packageName,
    version,
  };
}

function providerFailure(): Error {
  return new Error("offline provider failure that must not escape");
}

void test("deduplicates exact ecosystem queries, caps concurrency at five, and reports progress", async () => {
  let releaseGate: () => void = () => undefined;
  const gate = new Promise<void>((resolve) => {
    releaseGate = resolve;
  });
  const provider = new StubProvider(async () => {
    await gate;
    return [];
  });
  const cache = createCache(new MemoryMemento(), () => 0);
  const service = new DependencyAuditService(provider, cache);
  const validDependencies = Array.from({ length: 7 }, (_value, index) =>
    dependency(`package-${index.toString()}`),
  );
  const progress: DependencyAuditProgress[] = [];

  const audit = service.audit(
    [
      ...validDependencies,
      dependency("package-0"),
      dependency("range", "^1.0.0"),
      dependency("range", "^1.0.0"),
      dependency("python-package", "1.0.0", "PyPI"),
    ],
    { onProgress: (update) => progress.push(update) },
  );
  await Promise.resolve();

  assert.equal(provider.calls.length, 5);
  assert.equal(provider.maximumActiveCalls, 5);
  releaseGate();
  const result = await audit;

  assert.equal(provider.calls.length, 8);
  assert.equal(provider.maximumActiveCalls, 5);
  assert.deepEqual(result.providerResult, {
    provider: "OSV",
    status: "available",
    dependenciesEligible: 8,
    dependenciesSubmitted: 8,
    successful: 8,
    failed: 0,
    cacheHits: 0,
    staleCacheFallbacks: 0,
    vulnerabilitiesFound: 0,
  });
  assert.equal(
    result.errors.filter((error) => error.code === "UNSUPPORTED_VERSION").length,
    1,
  );
  assert.deepEqual(
    progress.map((update) => update.completed),
    [1, 2, 3, 4, 5, 6, 7, 8],
  );
  assert.equal(progress.every((update) => update.total === 8), true);
});

void test("caches successful empty responses and reuses them as fresh hits", async () => {
  const memento = new MemoryMemento();
  const cache = createCache(memento, () => 10);
  const firstProvider = new StubProvider(async () => []);
  const firstService = new DependencyAuditService(firstProvider, cache);

  const firstResult = await firstService.audit([dependency("safe-package")]);

  assert.equal(firstProvider.calls.length, 1);
  assert.equal(firstResult.providerResult.successful, 1);
  assert.equal(memento.updateCount, 1);
  assert.deepEqual(cache.get(cacheKey("safe-package")), {
    status: "fresh",
    value: [],
    fetchedAt: 10,
    expiresAt: 110,
  });

  const secondProvider = new StubProvider(async () => {
    throw providerFailure();
  });
  const secondResult = await new DependencyAuditService(
    secondProvider,
    cache,
  ).audit([dependency("safe-package")]);

  assert.equal(secondProvider.calls.length, 0);
  assert.equal(secondResult.providerResult.cacheHits, 1);
  assert.equal(secondResult.providerResult.successful, 1);
  assert.equal(secondResult.providerResult.dependenciesSubmitted, 0);
  assert.deepEqual(secondResult.vulnerabilities, []);
  assert.deepEqual(secondResult.errors, []);
  assert.equal(memento.updateCount, 1);
});

void test("uses stale data only on provider error and never caches errors as safe", async () => {
  let now = 0;
  const memento = new MemoryMemento();
  const cache = createCache(memento, () => now);
  const staleFailure = vulnerability("stale-failure", "1.0.0");
  const staleSuccess = vulnerability("stale-success", "1.0.0");
  await cache.setMany([
    { key: cacheKey("stale-failure"), value: [staleFailure] },
    { key: cacheKey("stale-success"), value: [staleSuccess] },
  ]);
  now = 200;

  const provider = new StubProvider(async (packageName) => {
    if (packageName === "stale-success") {
      return [];
    }
    throw providerFailure();
  });
  const result = await new DependencyAuditService(provider, cache).audit([
    dependency("stale-failure"),
    dependency("stale-success"),
    dependency("uncached-failure"),
  ]);

  assert.deepEqual(result.vulnerabilities, [staleFailure]);
  assert.equal(result.errors.filter((error) => error.code === "PROVIDER_ERROR").length, 2);
  assert.deepEqual(result.providerResult, {
    provider: "OSV",
    status: "partial",
    dependenciesEligible: 3,
    dependenciesSubmitted: 3,
    successful: 1,
    failed: 2,
    cacheHits: 0,
    staleCacheFallbacks: 1,
    vulnerabilitiesFound: 1,
  });
  assert.equal(cache.get(cacheKey("stale-failure")).status, "stale");
  assert.deepEqual(cache.get(cacheKey("stale-success")), {
    status: "fresh",
    value: [],
    fetchedAt: 200,
    expiresAt: 300,
  });
  assert.equal(cache.get(cacheKey("uncached-failure")).status, "miss");
  assert.equal(memento.updateCount, 2);
});

void test("reports unavailable when every submitted provider query fails", async () => {
  const cache = createCache(new MemoryMemento(), () => 0);
  const provider = new StubProvider(async () => {
    throw providerFailure();
  });

  const result = await new DependencyAuditService(provider, cache).audit([
    dependency("one"),
    dependency("two"),
  ]);

  assert.equal(result.providerResult.status, "unavailable");
  assert.equal(result.providerResult.successful, 0);
  assert.equal(result.providerResult.failed, 2);
  assert.equal(result.errors.length, 2);
});

void test("rejects noncanonical SemVer inputs instead of silently normalizing", async () => {
  const provider = new StubProvider(async () => []);
  const cache = createCache(new MemoryMemento(), () => 0);

  const result = await new DependencyAuditService(provider, cache).audit([
    dependency("canonical", "1.2.3"),
    dependency("leading-space", " 1.2.3"),
    dependency("v-prefix", "v1.2.3"),
    dependency("equals-prefix", "=1.2.3"),
    dependency("control", "1.2.3\n"),
  ]);

  assert.deepEqual(provider.calls, [
    { packageName: "canonical", ecosystem: "npm", version: "1.2.3" },
  ]);
  assert.equal(result.providerResult.dependenciesEligible, 1);
  assert.equal(result.providerResult.successful, 1);
  assert.equal(
    result.errors.filter((error) => error.code === "UNSUPPORTED_VERSION").length,
    4,
  );
});

void test("bounds unique audit subjects at 5000 with one coverage error", async () => {
  const cache: DependencyAuditCache = {
    get: () => ({
      status: "fresh",
      value: [],
      fetchedAt: 0,
      expiresAt: 1,
    }),
    setMany: async () => undefined,
  };
  const provider = new StubProvider(async () => {
    throw new Error("fresh cache entries must not query the provider");
  });
  const dependencies = Array.from({ length: 5_002 }, (_value, index) =>
    dependency(`bounded-${index.toString()}`),
  );

  const result = await new DependencyAuditService(provider, cache).audit(
    dependencies,
  );

  assert.equal(provider.calls.length, 0);
  assert.equal(result.providerResult.dependenciesEligible, 5_000);
  assert.equal(result.providerResult.successful, 5_000);
  assert.equal(result.providerResult.failed, 0);
  assert.equal(result.providerResult.cacheHits, 5_000);
  assert.equal(
    result.errors.filter((error) => error.code === "DEPENDENCY_LIMIT").length,
    1,
  );
});

void test("rejects cached and provider results for a different package identity", async () => {
  const memento = new MemoryMemento();
  const cache = createCache(memento, () => 0);
  await cache.setSuccessful(
    cacheKey("requested"),
    [vulnerability("different", "1.0.0")],
  );
  const provider = new StubProvider(async () => [
    vulnerability("also-different", "1.0.0"),
  ]);

  const result = await new DependencyAuditService(provider, cache).audit([
    dependency("requested"),
  ]);

  assert.equal(provider.calls.length, 1);
  assert.equal(result.vulnerabilities.length, 0);
  assert.equal(result.providerResult.status, "unavailable");
  assert.equal(result.providerResult.failed, 1);
  assert.equal(
    result.errors.some((error) => error.code === "CACHE_ERROR"),
    true,
  );
  assert.equal(
    result.errors.some((error) => error.code === "PROVIDER_ERROR"),
    true,
  );
});

void test("marks coverage partial when the scan-wide result budget is exceeded", async () => {
  const memento = new MemoryMemento();
  const cache = createCache(memento, () => 0);
  const provider = new StubProvider(async (packageName, _ecosystem, version) => [
    vulnerability(packageName, version),
  ]);
  const service = new DependencyAuditService(provider, cache, {
    maximumConcurrency: 1,
    maximumVulnerabilities: 1,
  });

  const result = await service.audit([
    dependency("first"),
    dependency("second"),
  ]);

  assert.equal(result.cancelled, false);
  assert.equal(result.providerResult.status, "partial");
  assert.equal(result.providerResult.successful, 1);
  assert.equal(result.providerResult.failed, 1);
  assert.equal(result.vulnerabilities.length, 1);
  assert.equal(
    result.errors.some((error) => error.code === "DEPENDENCY_LIMIT"),
    true,
  );
  assert.equal(memento.updateCount, 0);
});

void test("cancellation discards every staged cache write atomically", async () => {
  const memento = new MemoryMemento();
  const cache = createCache(memento, () => 0);
  const controller = new AbortController();
  const fastVulnerability = vulnerability("fast", "1.0.0");
  const slowVulnerability = vulnerability("slow", "1.0.0");
  const provider = new StubProvider(async (packageName) =>
    packageName === "fast" ? [fastVulnerability] : [slowVulnerability],
  );
  const service = new DependencyAuditService(provider, cache, {
    maximumConcurrency: 2,
  });

  const result = await service.audit(
    [dependency("fast"), dependency("slow")],
    {
      signal: controller.signal,
      onProgress: (progress) => {
        if (progress.completed === 2) {
          queueMicrotask(() => controller.abort());
        }
      },
    },
  );

  assert.equal(result.cancelled, true);
  assert.equal(result.providerResult.status, "partial");
  assert.deepEqual(result.vulnerabilities, [fastVulnerability, slowVulnerability]);
  assert.equal(result.providerResult.successful, 2);
  assert.equal(memento.updateCount, 0);
  assert.equal(cache.get(cacheKey("fast")).status, "miss");
  assert.equal(cache.get(cacheKey("slow")).status, "miss");
});
