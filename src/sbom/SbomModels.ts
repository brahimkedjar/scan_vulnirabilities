import type { ScanResult } from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";

export interface SbomScanResult extends ScanResult {
  /**
   * Optional unfiltered finding collection. The extension can keep the
   * severity-filtered `vulnerabilities` field for presentation while exports
   * retain every normalized provider finding.
   */
  readonly allVulnerabilities?: readonly Vulnerability[];
}

export interface CycloneDxExportLimits {
  readonly maximumScanResults: number;
  readonly maximumDependencies: number;
  readonly maximumComponents: number;
  readonly maximumOccurrences: number;
  readonly maximumRelationships: number;
  readonly maximumVulnerabilities: number;
  readonly maximumOutputBytes: number;
}

export const CYCLONE_DX_EXPORT_LIMITS: Readonly<CycloneDxExportLimits> =
  Object.freeze({
    maximumScanResults: 64,
    maximumDependencies: 10_000,
    maximumComponents: 10_000,
    maximumOccurrences: 50_000,
    maximumRelationships: 100_000,
    maximumVulnerabilities: 25_000,
    maximumOutputBytes: 64 * 1024 * 1024,
  });

export interface CycloneDxJsonExportOptions {
  /** RFC 3339 UTC timestamp supplied by the caller for deterministic output. */
  readonly timestamp: string;
  /** Canonical lower-case `urn:uuid:...` supplied by the caller. */
  readonly serialNumber: string;
  /** Roots used only to turn observed local paths into privacy-safe paths. */
  readonly workspaceRoots?: readonly string[];
  readonly toolVersion?: string;
  readonly signal?: AbortSignal;
  /** Lower limits are useful to enforce stricter caller-specific budgets. */
  readonly limits?: Partial<CycloneDxExportLimits>;
}

export type SbomExportErrorCode =
  | "CANCELLED"
  | "INVALID_INPUT"
  | "LIMIT_EXCEEDED";

export class SbomExportError extends Error {
  public constructor(
    public readonly code: SbomExportErrorCode,
    message: string,
    options: { readonly cause?: unknown } = {},
  ) {
    super(message, options);
    this.name = "SbomExportError";
  }
}

export interface CycloneDxProperty {
  readonly name: string;
  readonly value: string;
}

export interface CycloneDxOccurrence {
  readonly "bom-ref": string;
  readonly location: string;
  readonly line?: number;
}

export interface CycloneDxComponent {
  readonly type: "library";
  readonly "bom-ref": string;
  readonly group?: string;
  readonly name: string;
  readonly version: string;
  readonly purl: string;
  readonly evidence?: {
    readonly occurrences: readonly CycloneDxOccurrence[];
  };
  readonly properties: readonly CycloneDxProperty[];
}

export interface CycloneDxDependencyRelationship {
  readonly ref: string;
  readonly dependsOn?: readonly string[];
}

export interface CycloneDxVulnerabilitySource {
  readonly name: string;
}

export interface CycloneDxVulnerability {
  readonly "bom-ref": string;
  readonly id: string;
  readonly source: CycloneDxVulnerabilitySource;
  readonly ratings: readonly {
    readonly source: CycloneDxVulnerabilitySource;
    readonly score?: number;
    readonly severity: "critical" | "high" | "medium" | "low" | "unknown";
  }[];
  readonly description: string;
  readonly advisories?: readonly { readonly url: string }[];
  readonly published?: string;
  readonly updated?: string;
  readonly affects: readonly {
    readonly ref: string;
    readonly versions: readonly {
      readonly version: string;
      readonly status: "affected";
    }[];
  }[];
  readonly properties?: readonly CycloneDxProperty[];
}

export type CycloneDxAggregate = "complete" | "incomplete" | "unknown";

export interface CycloneDxComposition {
  readonly "bom-ref": string;
  readonly aggregate: CycloneDxAggregate;
  readonly dependencies?: readonly string[];
  readonly vulnerabilities?: readonly string[];
}

export interface CycloneDxBom {
  readonly $schema: "https://cyclonedx.org/schema/bom-1.6.schema.json";
  readonly bomFormat: "CycloneDX";
  readonly specVersion: "1.6";
  readonly serialNumber: string;
  readonly version: 1;
  readonly metadata: {
    readonly timestamp: string;
    readonly lifecycles: readonly [{ readonly phase: "pre-build" }];
    readonly tools: {
      readonly components: readonly [
        {
          readonly type: "application";
          readonly name: "Dependency Vulnerability Auditor";
          readonly version?: string;
        },
      ];
    };
  };
  readonly components: readonly CycloneDxComponent[];
  readonly dependencies: readonly CycloneDxDependencyRelationship[];
  readonly vulnerabilities: readonly CycloneDxVulnerability[];
  readonly compositions: readonly CycloneDxComposition[];
}
