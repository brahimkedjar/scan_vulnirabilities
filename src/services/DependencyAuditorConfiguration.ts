import type { Dependency } from "../models/Dependency";
import type { Severity, Vulnerability } from "../models/Vulnerability";
import {
  mapEcosystem,
  SUPPORTED_OSV_ECOSYSTEMS,
  type SupportedOsvEcosystem,
} from "../vulnerability/EcosystemMapper";

export type MinimumSeverity = Severity;

export interface ConfigurationReader {
  get<T>(section: string): T | undefined;
}

export interface DependencyAuditorConfiguration {
  readonly enabled: boolean;
  readonly scanOnStartup: boolean;
  readonly scanOnChange: boolean;
  readonly minimumSeverity: MinimumSeverity;
  readonly includeDevDependencies: boolean;
  readonly includeTransitiveDependencies: boolean;
  readonly enabledEcosystems: readonly SupportedOsvEcosystem[];
  /** Successful-provider cache lifetime, in hours. */
  readonly cacheDuration: number;
  /** Per-request provider timeout, in milliseconds. */
  readonly networkTimeout: number;
}

export const DEPENDENCY_AUDITOR_CONFIGURATION_DEFAULTS: Readonly<DependencyAuditorConfiguration> =
  Object.freeze({
    enabled: true,
    scanOnStartup: false,
    scanOnChange: false,
    minimumSeverity: "UNKNOWN",
    includeDevDependencies: true,
    includeTransitiveDependencies: true,
    enabledEcosystems: Object.freeze([...SUPPORTED_OSV_ECOSYSTEMS]),
    cacheDuration: 24,
    networkTimeout: 10_000,
  });

export const DEPENDENCY_AUDITOR_CONFIGURATION_BOUNDS = Object.freeze({
  cacheDuration: Object.freeze({ minimum: 0.25, maximum: 720 }),
  networkTimeout: Object.freeze({ minimum: 1_000, maximum: 60_000 }),
});

const SEVERITY_RANK: Readonly<Record<Severity, number>> = Object.freeze({
  UNKNOWN: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
});
const MINIMUM_SEVERITIES: ReadonlySet<string> = new Set([
  "UNKNOWN",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
]);

function readUnknown(
  reader: ConfigurationReader,
  section: string,
): unknown {
  try {
    return reader.get<unknown>(section);
  } catch {
    return undefined;
  }
}

function readBoolean(
  reader: ConfigurationReader,
  section: string,
  fallback: boolean,
): boolean {
  const value = readUnknown(reader, section);
  return typeof value === "boolean" ? value : fallback;
}

function readBoundedNumber(
  reader: ConfigurationReader,
  section: string,
  fallback: number,
  minimum: number,
  maximum: number,
  round: boolean,
): number {
  const value = readUnknown(reader, section);
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fallback;
  }
  const bounded = Math.min(maximum, Math.max(minimum, value));
  return round ? Math.round(bounded) : bounded;
}

function readMinimumSeverity(
  reader: ConfigurationReader,
): MinimumSeverity {
  const value = readUnknown(reader, "minimumSeverity");
  if (typeof value !== "string") {
    return DEPENDENCY_AUDITOR_CONFIGURATION_DEFAULTS.minimumSeverity;
  }
  const normalized = value.trim().toUpperCase();
  return MINIMUM_SEVERITIES.has(normalized)
    ? (normalized as MinimumSeverity)
    : DEPENDENCY_AUDITOR_CONFIGURATION_DEFAULTS.minimumSeverity;
}

function readEnabledEcosystems(
  reader: ConfigurationReader,
): readonly SupportedOsvEcosystem[] {
  const value = readUnknown(reader, "enabledEcosystems");
  if (!Array.isArray(value)) {
    return DEPENDENCY_AUDITOR_CONFIGURATION_DEFAULTS.enabledEcosystems;
  }
  const enabled = new Set<SupportedOsvEcosystem>();
  for (const item of value.slice(0, SUPPORTED_OSV_ECOSYSTEMS.length * 2)) {
    if (typeof item !== "string") {
      continue;
    }
    const mapped = mapEcosystem(item);
    if (mapped === item) {
      enabled.add(mapped);
    }
  }
  return Object.freeze(
    SUPPORTED_OSV_ECOSYSTEMS.filter((ecosystem) => enabled.has(ecosystem)),
  );
}

export function readDependencyAuditorConfiguration(
  reader: ConfigurationReader,
): DependencyAuditorConfiguration {
  const defaults = DEPENDENCY_AUDITOR_CONFIGURATION_DEFAULTS;
  const bounds = DEPENDENCY_AUDITOR_CONFIGURATION_BOUNDS;
  return {
    enabled: readBoolean(reader, "enabled", defaults.enabled),
    scanOnStartup: readBoolean(
      reader,
      "scanOnStartup",
      defaults.scanOnStartup,
    ),
    scanOnChange: readBoolean(reader, "scanOnChange", defaults.scanOnChange),
    minimumSeverity: readMinimumSeverity(reader),
    includeDevDependencies: readBoolean(
      reader,
      "includeDevDependencies",
      defaults.includeDevDependencies,
    ),
    includeTransitiveDependencies: readBoolean(
      reader,
      "includeTransitiveDependencies",
      defaults.includeTransitiveDependencies,
    ),
    enabledEcosystems: readEnabledEcosystems(reader),
    cacheDuration: readBoundedNumber(
      reader,
      "cacheDuration",
      defaults.cacheDuration,
      bounds.cacheDuration.minimum,
      bounds.cacheDuration.maximum,
      false,
    ),
    networkTimeout: readBoundedNumber(
      reader,
      "networkTimeout",
      defaults.networkTimeout,
      bounds.networkTimeout.minimum,
      bounds.networkTimeout.maximum,
      true,
    ),
  };
}

export function shouldIncludeDependency(
  dependency: Dependency,
  configuration: Pick<
    DependencyAuditorConfiguration,
    "includeDevDependencies" | "includeTransitiveDependencies"
  >,
): boolean {
  return (
    (configuration.includeDevDependencies ||
      dependency.environment !== "development") &&
    (configuration.includeTransitiveDependencies ||
      dependency.dependencyType === "direct")
  );
}

export function filterDependencies(
  dependencies: readonly Dependency[],
  configuration: Pick<
    DependencyAuditorConfiguration,
    "includeDevDependencies" | "includeTransitiveDependencies"
  >,
): Dependency[] {
  return dependencies.filter((dependency) =>
    shouldIncludeDependency(dependency, configuration),
  );
}

/** Unknown/unscored advisories remain visible at every threshold. */
export function meetsMinimumSeverity(
  severity: Severity,
  minimumSeverity: MinimumSeverity,
): boolean {
  return (
    severity === "UNKNOWN" ||
    SEVERITY_RANK[severity] >= SEVERITY_RANK[minimumSeverity]
  );
}

export function filterVulnerabilitiesBySeverity(
  vulnerabilities: readonly Vulnerability[],
  minimumSeverity: MinimumSeverity,
): Vulnerability[] {
  return vulnerabilities.filter((vulnerability) =>
    meetsMinimumSeverity(vulnerability.severity, minimumSeverity),
  );
}
