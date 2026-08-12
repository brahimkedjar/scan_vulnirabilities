import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type {
  EcosystemCoverage,
  ProviderResult,
} from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";
import {
  buildCycloneDxBom,
  exportCycloneDxJson,
  SbomExportError,
  type SbomScanResult,
} from "../sbom";

const TIMESTAMP = "2026-08-12T10:11:12.000Z";
const SERIAL = "urn:uuid:12345678-1234-4234-8234-123456789abc";
const WORKSPACE = "C:\\repo";

const PACKAGES = [
  ["npm", "@scope/pkg", "1.2.3", "javascript/package.json", "npm"],
  ["PyPI", "requests", "2.32.0", "python/requirements.txt", "pip"],
  ["Maven", "org.example:core", "3.1.4", "java/pom.xml", "maven"],
  ["crates.io", "serde", "1.0.210", "rust/Cargo.toml", "cargo"],
  ["Go", "example.com/mod", "v1.2.3", "go/go.mod", "go"],
  ["NuGet", "Newtonsoft.Json", "13.0.3", "dotnet/app.csproj", "nuget"],
  ["Packagist", "vendor/package", "4.5.6", "php/composer.json", "composer"],
] as const;

function absolutePath(relative: string): string {
  return `${WORKSPACE}\\${relative.replaceAll("/", "\\")}`;
}

function resolvedDependency(
  ecosystem: string,
  name: string,
  installedVersion: string,
  relativeManifest: string,
  packageManager: string,
  overrides: Partial<Dependency> = {},
): Dependency {
  return {
    name,
    ecosystem,
    installedVersion,
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
    dependencyPath: [name],
    manifestPath: absolutePath(relativeManifest),
    packageManager,
    projectPath: absolutePath(relativeManifest.split("/")[0] ?? "project"),
    workspacePath: WORKSPACE,
    ...overrides,
  };
}

function finding(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: "OSV-2026-FIXTURE",
    aliases: ["GHSA-aaaa-bbbb-cccc", "CVE-2026-12345"],
    packageName: "@scope/pkg",
    ecosystem: "npm",
    installedVersion: "1.2.3",
    severity: "HIGH",
    cvssScore: 8.7,
    summary: "Fixture dependency vulnerability",
    affectedRange: ">=1.0.0 <1.2.4",
    fixedVersions: ["1.2.4"],
    fixedVersion: "1.2.4",
    references: ["https://osv.dev/vulnerability/OSV-2026-FIXTURE"],
    published: "2026-08-01T00:00:00Z",
    modified: "2026-08-02T00:00:00Z",
    source: "OSV",
    ...overrides,
  };
}

function coverageFor(dependencies: readonly Dependency[]): EcosystemCoverage[] {
  const values = new Map<string, EcosystemCoverage>();
  for (const dependency of dependencies) {
    const previous = values.get(dependency.ecosystem);
    const manager = dependency.packageManager ?? "fixture";
    values.set(dependency.ecosystem, {
      ecosystem: dependency.ecosystem,
      packageManagers: [
        ...new Set([...(previous?.packageManagers ?? []), manager]),
      ],
      discovered: (previous?.discovered ?? 0) + 1,
      resolved: (previous?.resolved ?? 0) + 1,
      checked: (previous?.checked ?? 0) + 1,
      vulnerable:
        (previous?.vulnerable ?? 0) +
        (dependency.name === "@scope/pkg" ? 1 : 0),
      unresolved: 0,
      unsupported: 0,
    });
  }
  return [...values.values()];
}

function providerResult(
  dependencyCount: number,
  status: ProviderResult["status"] = "available",
): ProviderResult {
  return {
    provider: "OSV",
    status,
    dependenciesEligible: dependencyCount,
    dependenciesSubmitted: dependencyCount,
    successful: status === "unavailable" ? 0 : dependencyCount,
    failed: status === "available" ? 0 : 1,
    cacheHits: 0,
    staleCacheFallbacks: 0,
    vulnerabilitiesFound: 1,
  };
}

function scanResult(
  dependencies: readonly Dependency[],
  overrides: Partial<SbomScanResult> = {},
): SbomScanResult {
  return {
    workspacePath: WORKSPACE,
    scannedAt: TIMESTAMP,
    durationMs: 25,
    packageManagers: [
      ...new Set(
        dependencies.flatMap((item) =>
          item.packageManager === undefined ? [] : [item.packageManager],
        ),
      ),
    ],
    dependenciesScanned: dependencies.length,
    vulnerableDependencies: 1,
    vulnerabilities: [],
    allVulnerabilities: [finding()],
    dependencies,
    errors: [],
    providerResults: [providerResult(dependencies.length)],
    ecosystemCoverage: coverageFor(dependencies),
    cancelled: false,
    ...overrides,
  };
}

function options(signal?: AbortSignal): {
  readonly timestamp: string;
  readonly serialNumber: string;
  readonly workspaceRoots: readonly string[];
  readonly signal?: AbortSignal;
} {
  return {
    timestamp: TIMESTAMP,
    serialNumber: SERIAL,
    workspaceRoots: [WORKSPACE],
    ...(signal === undefined ? {} : { signal }),
  } as const;
}

void test("exports deterministic CycloneDX 1.6 for all supported package identities", () => {
  const dependencies = PACKAGES.map((item) =>
    resolvedDependency(item[0], item[1], item[2], item[3], item[4]),
  );
  const child = resolvedDependency(
    "npm",
    "nested-child",
    "2.0.0",
    "javascript/package.json",
    "npm",
    {
      dependencyType: "transitive",
      dependencyPath: ["@scope/pkg", "nested-child"],
    },
  );
  const input = scanResult([...dependencies, child]);
  const bom = buildCycloneDxBom([input], options());

  assert.equal(bom.bomFormat, "CycloneDX");
  assert.equal(bom.specVersion, "1.6");
  assert.equal(bom.metadata.timestamp, TIMESTAMP);
  assert.deepEqual(
    bom.components.map((component) => component.purl).sort(),
    [
      "pkg:cargo/serde@1.0.210",
      "pkg:composer/vendor/package@4.5.6",
      "pkg:golang/example.com/mod@v1.2.3",
      "pkg:maven/org.example/core@3.1.4",
      "pkg:npm/%40scope/pkg@1.2.3",
      "pkg:npm/nested-child@2.0.0",
      "pkg:nuget/Newtonsoft.Json@13.0.3",
      "pkg:pypi/requests@2.32.0",
    ].sort(),
  );
  const parent = bom.components.find(
    (component) => component.purl === "pkg:npm/%40scope/pkg@1.2.3",
  );
  const nested = bom.components.find(
    (component) => component.purl === "pkg:npm/nested-child@2.0.0",
  );
  assert.ok(parent);
  assert.ok(nested);
  assert.ok(
    bom.dependencies
      .find((relationship) => relationship.ref === parent["bom-ref"])
      ?.dependsOn?.includes(nested["bom-ref"]),
  );
  assert.equal(bom.vulnerabilities.length, 1);
  assert.equal(bom.vulnerabilities[0]?.source.name, "OSV");
  assert.equal(bom.vulnerabilities[0]?.affects[0]?.ref, parent["bom-ref"]);
  assert.deepEqual(
    bom.compositions.map((composition) => composition.aggregate),
    ["complete", "complete"],
  );

  const serialized = exportCycloneDxJson([input], options());
  assert.equal(
    serialized,
    exportCycloneDxJson(
      [
        scanResult([...input.dependencies].reverse(), {
          ecosystemCoverage: [...(input.ecosystemCoverage ?? [])].reverse(),
        }),
      ],
      options(),
    ),
  );
  assert.doesNotMatch(serialized, /C:\\\\repo/iu);
  assert.doesNotMatch(serialized, /"(?:licenses|hashes|provenance)"\s*:/iu);
  assert.match(serialized, /javascript\/package\.json/u);
});

void test("marks incomplete coverage and never invents an unsafe occurrence", () => {
  const dependency = resolvedDependency(
    "npm",
    "@scope/pkg",
    "1.2.3",
    "javascript/package.json",
    "npm",
    { manifestPath: "D:\\private\\package.json" },
  );
  const input = scanResult([dependency], {
    providerResults: [providerResult(1, "partial")],
    ecosystemCoverage: [
      {
        ecosystem: "npm",
        packageManagers: ["npm"],
        discovered: 2,
        resolved: 1,
        checked: 0,
        vulnerable: 1,
        unresolved: 1,
        unsupported: 0,
      },
    ],
  });
  const bom = buildCycloneDxBom([input], options());

  assert.equal(bom.components[0]?.evidence, undefined);
  assert.deepEqual(
    bom.compositions.map((composition) => composition.aggregate),
    ["incomplete", "incomplete"],
  );
  assert.doesNotMatch(JSON.stringify(bom), /D:\\\\private/iu);
});

void test("marks vulnerability coverage incomplete when a present complete-finding field is truncated", () => {
  const base = scanResult([
    resolvedDependency(
      "npm",
      "@scope/pkg",
      "1.2.3",
      "javascript/package.json",
      "npm",
    ),
  ]);
  const { allVulnerabilities: _legacyComplete, ...withoutLegacyComplete } = base;
  assert.equal(_legacyComplete?.length, 1);
  const input: SbomScanResult = {
    ...withoutLegacyComplete,
    unfilteredVulnerabilities: [],
  };

  const bom = buildCycloneDxBom([input], options());

  assert.equal(bom.vulnerabilities.length, 0);
  assert.equal(bom.compositions[1]?.aggregate, "incomplete");
});

void test("keeps identical relative occurrences distinct across workspace roots", () => {
  const roots = ["C:\\work\\b", "C:\\work\\a"];
  const dependencies = [
    resolvedDependency(
      "npm",
      "@scope/pkg",
      "1.2.3",
      "unused/package.json",
      "npm",
      { manifestPath: "C:\\work\\a\\package.json" },
    ),
    resolvedDependency(
      "npm",
      "@scope/pkg",
      "1.2.3",
      "unused/package.json",
      "npm",
      { manifestPath: "C:\\work\\b\\package.json" },
    ),
  ];

  const bom = buildCycloneDxBom([scanResult(dependencies)], {
    ...options(),
    workspaceRoots: roots,
  });
  const component = bom.components.find(
    (value) => value.purl === "pkg:npm/%40scope/pkg@1.2.3",
  );

  assert.deepEqual(
    component?.evidence?.occurrences.map((occurrence) => occurrence.location).sort(),
    ["workspace-root-1/package.json", "workspace-root-2/package.json"],
  );
  assert.doesNotMatch(JSON.stringify(bom), /C:\\\\work/iu);
});

void test("fails closed on cancellation and bounded component output", () => {
  const dependencies = PACKAGES.map((item) =>
    resolvedDependency(item[0], item[1], item[2], item[3], item[4]),
  );
  const input = scanResult(dependencies);
  const controller = new AbortController();
  controller.abort();

  assert.throws(
    () => buildCycloneDxBom([input], options(controller.signal)),
    (error: unknown) =>
      error instanceof SbomExportError && error.code === "CANCELLED",
  );
  assert.throws(
    () =>
      buildCycloneDxBom([input], {
        ...options(),
        limits: { maximumComponents: 1 },
      }),
    (error: unknown) =>
      error instanceof SbomExportError && error.code === "LIMIT_EXCEEDED",
  );
});

void test("rejects nondeterministic metadata and conflicting advisory evidence", () => {
  const dependencies = PACKAGES.map((item) =>
    resolvedDependency(item[0], item[1], item[2], item[3], item[4]),
  );
  const conflict = finding({ summary: "Contradictory fixture evidence" });
  const input = scanResult(dependencies, {
    allVulnerabilities: [finding(), conflict],
  });

  assert.throws(
    () =>
      buildCycloneDxBom([input], {
        ...options(),
        serialNumber: "not-a-uuid",
      }),
    (error: unknown) =>
      error instanceof SbomExportError && error.code === "INVALID_INPUT",
  );
  assert.throws(
    () => buildCycloneDxBom([input], options()),
    /Conflicting vulnerability evidence/u,
  );
  assert.throws(
    () =>
      buildCycloneDxBom(
        [
          scanResult(dependencies, {
            allVulnerabilities: [finding({ published: "not-a-timestamp" })],
          }),
        ],
        options(),
      ),
    (error: unknown) =>
      error instanceof SbomExportError && error.code === "INVALID_INPUT",
  );
});

void test("rejects conflicting complete-finding compatibility fields", () => {
  const dependencies = PACKAGES.map((item) =>
    resolvedDependency(item[0], item[1], item[2], item[3], item[4]),
  );
  const input = scanResult(dependencies, {
    unfilteredVulnerabilities: [],
  });

  assert.throws(
    () => buildCycloneDxBom([input], options()),
    (error: unknown) =>
      error instanceof SbomExportError && error.code === "INVALID_INPUT",
  );
});
