import type { Dependency } from "./Dependency";
import type { Vulnerability } from "./Vulnerability";

export type ScanErrorCode =
  | "NO_LOCKFILE"
  | "INVALID_MANIFEST"
  | "INVALID_LOCKFILE"
  | "UNSUPPORTED_LOCKFILE"
  | "UNSUPPORTED_PACKAGE_MANAGER"
  | "UNSUPPORTED_PACKAGE_SOURCE"
  | "UNSUPPORTED_PACKAGE_IDENTITY"
  | "DEPENDENCY_UNRESOLVED"
  | "DEPENDENCY_LIMIT"
  | "UNSUPPORTED_VERSION"
  | "PROVIDER_ERROR"
  | "CACHE_ERROR"
  | "WORKSPACE_ERROR";

export interface ScanError {
  readonly code: ScanErrorCode;
  readonly message: string;
  readonly packageName?: string;
  readonly provider?: string;
  readonly path?: string;
}

export type ProviderStatus = "available" | "partial" | "unavailable";

export interface ProviderResult {
  readonly provider: string;
  readonly status: ProviderStatus;
  readonly dependenciesEligible: number;
  readonly dependenciesSubmitted: number;
  readonly successful: number;
  readonly failed: number;
  readonly cacheHits: number;
  readonly staleCacheFallbacks: number;
  readonly vulnerabilitiesFound: number;
}

export interface EcosystemCoverage {
  readonly ecosystem: string;
  readonly packageManagers: readonly string[];
  readonly discovered: number;
  readonly resolved: number;
  readonly checked: number;
  readonly vulnerable: number;
  readonly unresolved: number;
  readonly unsupported: number;
}

export interface ProjectCoverage extends EcosystemCoverage {
  readonly workspacePath: string;
  readonly projectPath: string;
  readonly manifestPaths: readonly string[];
}

export interface ScanResult {
  readonly workspacePath: string;
  readonly scannedAt: string;
  readonly durationMs: number;
  readonly packageManagers: readonly string[];
  readonly dependenciesScanned: number;
  readonly vulnerableDependencies: number;
  /**
   * Complete provider findings before the user-facing severity filter is
   * applied. Security gates, intelligence enrichment, and standards exports
   * must use this collection. Existing UI continues to use `vulnerabilities`.
   */
  readonly unfilteredVulnerabilities?: readonly Vulnerability[];
  readonly vulnerabilities: readonly Vulnerability[];
  readonly dependencies: readonly Dependency[];
  readonly errors: readonly ScanError[];
  readonly providerResults: readonly ProviderResult[];
  /** Phase 4 coverage, aggregated by canonical OSV ecosystem. */
  readonly ecosystemCoverage?: readonly EcosystemCoverage[];
  /** Phase 4 coverage kept separate for each detected dependency project. */
  readonly projectCoverage?: readonly ProjectCoverage[];
  readonly cancelled: boolean;
}

/** Returns the complete stored finding set when the scan produced one. */
export function scanResultKnownVulnerabilities(
  result: ScanResult,
): readonly Vulnerability[] {
  return result.unfilteredVulnerabilities ?? result.vulnerabilities;
}
