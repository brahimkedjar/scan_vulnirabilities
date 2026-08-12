import { strict as assert } from "node:assert";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type { Vulnerability } from "../models/Vulnerability";
import {
  DEPENDENCY_AUDITOR_CONFIGURATION_DEFAULTS,
  filterDependencies,
  filterVulnerabilitiesBySeverity,
  meetsMinimumSeverity,
  readDependencyAuditorConfiguration,
  shouldIncludeDependency,
  type ConfigurationReader,
} from "../services/DependencyAuditorConfiguration";

class ObjectConfigurationReader implements ConfigurationReader {
  public constructor(private readonly values: Readonly<Record<string, unknown>>) {}

  public get<T>(section: string): T | undefined {
    return this.values[section] as T | undefined;
  }
}

function dependency(
  name: string,
  dependencyType: Dependency["dependencyType"],
  environment: Dependency["environment"],
): Dependency {
  return {
    name,
    ecosystem: "npm",
    installedVersion: "1.0.0",
    dependencyType,
    environment,
    packageJsonPath: "/workspace/package.json",
  };
}

function vulnerability(
  severity: Vulnerability["severity"],
): Vulnerability {
  return {
    id: `OSV-${severity}`,
    aliases: [],
    packageName: "example",
    ecosystem: "npm",
    installedVersion: "1.0.0",
    severity,
    summary: "Test advisory",
    references: [],
    source: "OSV",
  };
}

void test("uses network-safe defaults that preserve Phase 2 dependency coverage", () => {
  const configuration = readDependencyAuditorConfiguration(
    new ObjectConfigurationReader({}),
  );
  assert.deepEqual(
    configuration,
    DEPENDENCY_AUDITOR_CONFIGURATION_DEFAULTS,
  );
  assert.equal(configuration.enabled, true);
  assert.equal(configuration.scanOnStartup, false);
  assert.equal(configuration.scanOnChange, false);
  assert.equal(configuration.minimumSeverity, "UNKNOWN");
  assert.equal(configuration.includeDevDependencies, true);
  assert.equal(configuration.includeTransitiveDependencies, true);
});

void test("parses valid booleans and case-insensitive minimum severity", () => {
  const configuration = readDependencyAuditorConfiguration(
    new ObjectConfigurationReader({
      enabled: false,
      scanOnStartup: true,
      scanOnChange: true,
      minimumSeverity: "  HiGh ",
      includeDevDependencies: false,
      includeTransitiveDependencies: false,
      cacheDuration: 12.5,
      networkTimeout: 4_500.6,
    }),
  );
  assert.deepEqual(configuration, {
    enabled: false,
    scanOnStartup: true,
    scanOnChange: true,
    minimumSeverity: "HIGH",
    includeDevDependencies: false,
    includeTransitiveDependencies: false,
    enabledEcosystems: [
      "npm",
      "PyPI",
      "Maven",
      "crates.io",
      "Go",
      "NuGet",
      "Packagist",
    ],
    cacheDuration: 12.5,
    networkTimeout: 4_501,
  });
});

void test("accepts only canonical supported ecosystem settings", () => {
  const configuration = readDependencyAuditorConfiguration(
    new ObjectConfigurationReader({
      enabledEcosystems: ["PyPI", "Maven", "python", "Unknown", "PyPI"],
    }),
  );
  assert.deepEqual(configuration.enabledEcosystems, ["PyPI", "Maven"]);
  assert.deepEqual(
    readDependencyAuditorConfiguration(
      new ObjectConfigurationReader({ enabledEcosystems: [] }),
    ).enabledEcosystems,
    [],
  );
});

void test("falls back for malformed settings and clamps numeric resource bounds", () => {
  const low = readDependencyAuditorConfiguration(
    new ObjectConfigurationReader({
      enabled: "false",
      minimumSeverity: "urgent",
      includeDevDependencies: 0,
      cacheDuration: -10,
      networkTimeout: 2,
    }),
  );
  assert.equal(low.enabled, true);
  assert.equal(low.minimumSeverity, "UNKNOWN");
  assert.equal(low.includeDevDependencies, true);
  assert.equal(low.cacheDuration, 0.25);
  assert.equal(low.networkTimeout, 1_000);

  const high = readDependencyAuditorConfiguration(
    new ObjectConfigurationReader({
      cacheDuration: Number.POSITIVE_INFINITY,
      networkTimeout: 100_000,
    }),
  );
  assert.equal(high.cacheDuration, 24);
  assert.equal(high.networkTimeout, 60_000);
});

void test("reader failures cannot prevent safe default configuration", () => {
  const throwingReader: ConfigurationReader = {
    get: <T>(_section: string): T | undefined => {
      throw new Error("configuration unavailable");
    },
  };
  assert.deepEqual(
    readDependencyAuditorConfiguration(throwingReader),
    DEPENDENCY_AUDITOR_CONFIGURATION_DEFAULTS,
  );
});

void test("filters development and transitive dependencies without mutating input", () => {
  const values = [
    dependency("direct-production", "direct", "production"),
    dependency("direct-development", "direct", "development"),
    dependency("transitive-production", "transitive", "production"),
    dependency("transitive-development", "transitive", "development"),
    dependency("direct-optional", "direct", "optional"),
  ];
  const filtered = filterDependencies(values, {
    includeDevDependencies: false,
    includeTransitiveDependencies: false,
  });
  assert.deepEqual(
    filtered.map((value) => value.name),
    ["direct-production", "direct-optional"],
  );
  assert.equal(values.length, 5);
  assert.equal(
    shouldIncludeDependency(values[3] as Dependency, {
      includeDevDependencies: true,
      includeTransitiveDependencies: true,
    }),
    true,
  );
});

void test("applies deterministic severity thresholds and retains unscored advisories", () => {
  assert.equal(meetsMinimumSeverity("CRITICAL", "HIGH"), true);
  assert.equal(meetsMinimumSeverity("HIGH", "HIGH"), true);
  assert.equal(meetsMinimumSeverity("MEDIUM", "HIGH"), false);
  assert.equal(meetsMinimumSeverity("LOW", "HIGH"), false);
  assert.equal(meetsMinimumSeverity("UNKNOWN", "HIGH"), true);
  assert.equal(meetsMinimumSeverity("LOW", "UNKNOWN"), true);

  const values = [
    vulnerability("LOW"),
    vulnerability("UNKNOWN"),
    vulnerability("CRITICAL"),
    vulnerability("MEDIUM"),
    vulnerability("HIGH"),
  ];
  const filtered = filterVulnerabilitiesBySeverity(values, "HIGH");
  assert.deepEqual(
    filtered.map((value) => value.severity),
    ["UNKNOWN", "CRITICAL", "HIGH"],
  );
  assert.equal(values.length, 5);
});
