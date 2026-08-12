import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import {
  mapDependencyToOsv,
  mapEcosystem,
  normalizePypiName,
  SUPPORTED_OSV_ECOSYSTEMS,
} from "../vulnerability/EcosystemMapper";
import { normalizeOsvResponse } from "../vulnerability/VulnerabilityNormalizer";

function dependency(
  name: string,
  ecosystem: string,
  installedVersion: string,
): Dependency {
  return {
    name,
    ecosystem,
    installedVersion,
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
    manifestPath: "/fixture/manifest",
    packageManager: "fixture",
  };
}

void test("maps only documented canonical OSV ecosystems", () => {
  assert.deepEqual(SUPPORTED_OSV_ECOSYSTEMS, [
    "npm",
    "PyPI",
    "Maven",
    "crates.io",
    "Go",
    "NuGet",
    "Packagist",
  ]);
  assert.equal(mapEcosystem("python"), "PyPI");
  assert.equal(mapEcosystem("gradle"), "Maven");
  assert.equal(mapEcosystem("unknown"), undefined);
});

void test("preserves canonical compound identities and normalizes PyPI names", () => {
  assert.equal(normalizePypiName("Requests_Socks.Extra"), "requests-socks-extra");
  assert.deepEqual(
    mapDependencyToOsv(dependency("Requests", "PyPI", "2.31.0")),
    {
      supported: true,
      identity: {
        packageName: "requests",
        ecosystem: "PyPI",
        version: "2.31.0",
      },
    },
  );
  assert.equal(
    mapDependencyToOsv(
      dependency(
        "org.springframework:spring-core",
        "Maven",
        "6.1.2",
      ),
    ).supported,
    true,
  );
  assert.equal(
    mapDependencyToOsv(
      dependency("github.com/gin-gonic/gin", "Go", "v1.9.1"),
    ).supported,
    true,
  );
});

void test("never maps unresolved, ranged npm, or unsafe identities", () => {
  const unresolved: Dependency = {
    ...dependency("requests", "PyPI", ""),
    resolutionStatus: "unresolved",
  };
  assert.deepEqual(mapDependencyToOsv(unresolved), {
    supported: false,
    kind: "unresolved",
    reason: "Dependency does not have a safely resolved version.",
  });
  assert.equal(
    mapDependencyToOsv(dependency("axios", "npm", "^1.2.3")).supported,
    false,
  );
  assert.equal(
    mapDependencyToOsv(
      dependency("org.example:safe\nspoof", "Maven", "1.0.0"),
    ).supported,
    false,
  );
});

void test("rejects range, wildcard, mutable, and non-canonical versions for every ecosystem", () => {
  const unsafeVersions: ReadonlyArray<readonly [string, string]> = [
    ["PyPI", ">=2.0"],
    ["PyPI", "2.0+private.1"],
    ["PyPI", "01.02"],
    ["PyPI", "1.0rc01"],
    ["Maven", "[1.0,2.0)"],
    ["Maven", "1.+"],
    ["Maven", "1.*"],
    ["Maven", "latest.release"],
    ["Maven", "${revision}"],
    ["Maven", "1.0-SNAPSHOT"],
    ["crates.io", "^1.0"],
    ["Go", "master"],
    ["Go", "v1.2.3+private"],
    ["NuGet", "*"],
    ["NuGet", "[1.0,2.0)"],
    ["NuGet", "01.2.3"],
    ["NuGet", "1.0.0-01"],
    ["Packagist", "^7"],
    ["Packagist", "dev-main"],
    ["Packagist", "01.2.3"],
    ["Packagist", "1.0.0-01"],
  ];
  for (const [ecosystem, version] of unsafeVersions) {
    const name =
      ecosystem === "Maven"
        ? "org.example:demo"
        : ecosystem === "Go"
          ? "example.com/demo"
          : ecosystem === "Packagist"
            ? "vendor/package"
            : "example";
    const mapping = mapDependencyToOsv(dependency(name, ecosystem, version));
    assert.equal(mapping.supported, false, `${ecosystem}@${version}`);
    if (!mapping.supported) {
      assert.equal(mapping.kind, "version");
    }
  }
});

void test("accepts representative canonical exact versions for every ecosystem", () => {
  const exactVersions: ReadonlyArray<readonly [string, string, string]> = [
    ["npm", "example", "1.2.3-beta.1"],
    ["PyPI", "example", "1!2.0rc1.post2.dev3"],
    ["Maven", "org.example:demo", "2.15.2-alpha"],
    ["crates.io", "example", "1.2.3-beta.1"],
    ["Go", "example.com/demo", "v0.0.0-20191109021931-daa7c04131f5"],
    ["NuGet", "Example", "1.2.3-rc.1"],
    ["Packagist", "vendor/package", "v6.4.12"],
    ["Packagist", "vendor/package", "v6.4.12+build.01"],
  ];
  for (const [ecosystem, name, version] of exactVersions) {
    assert.equal(
      mapDependencyToOsv(dependency(name, ecosystem, version)).supported,
      true,
      `${ecosystem}@${version}`,
    );
  }
});

void test("normalizes a provider-filtered PyPI result without npm ordering", () => {
  const vulnerabilities = normalizeOsvResponse(
    {
      vulns: [
        {
          id: "PYSEC-TEST-1",
          modified: "2026-08-01T00:00:00Z",
          summary: "Fixture advisory",
          affected: [
            {
              package: { ecosystem: "PyPI", name: "requests" },
              ranges: [
                {
                  type: "ECOSYSTEM",
                  events: [
                    { introduced: "0" },
                    { fixed: "2.32.0" },
                  ],
                },
              ],
            },
          ],
        },
      ],
    },
    {
      packageName: "requests",
      ecosystem: "PyPI",
      installedVersion: "2.31.0",
    },
  );
  assert.equal(vulnerabilities.length, 1);
  assert.equal(vulnerabilities[0]?.ecosystem, "PyPI");
  assert.equal(vulnerabilities[0]?.fixedVersion, "2.32.0");
  assert.match(vulnerabilities[0]?.affectedRange ?? "", /ECOSYSTEM/u);
});

void test("omits an ambiguous non-npm fixed version", () => {
  const vulnerability = normalizeOsvResponse(
    {
      vulns: [
        {
          id: "MAVEN-TEST-1",
          modified: "2026-08-01T00:00:00Z",
          affected: [
            {
              package: { ecosystem: "Maven", name: "g:a" },
              ranges: [
                {
                  type: "ECOSYSTEM",
                  events: [
                    { introduced: "0" },
                    { fixed: "1.2.0" },
                    { introduced: "2.0.0" },
                    { fixed: "2.1.0" },
                  ],
                },
              ],
            },
          ],
        },
      ],
    },
    { packageName: "g:a", ecosystem: "Maven", installedVersion: "1.1.0" },
  )[0];
  assert.ok(vulnerability !== undefined);
  assert.equal(vulnerability.fixedVersion, undefined);
});
