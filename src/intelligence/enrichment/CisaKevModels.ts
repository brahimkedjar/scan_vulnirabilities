export type CisaKevRansomwareUse = "known" | "unknown";

export interface CisaKevEntry {
  readonly cveId: string;
  readonly vendorProject: string;
  readonly product: string;
  readonly vulnerabilityName: string;
  readonly dateAdded: string;
  readonly dueDate: string;
  readonly requiredAction: string;
  readonly ransomwareUse: CisaKevRansomwareUse;
  readonly cwes: readonly string[];
}

export interface CisaKevCatalog {
  readonly schemaVersion: 1;
  readonly source: "CISA KEV";
  readonly catalogVersion: string;
  readonly releasedAt: string;
  readonly fetchedAt: string;
  readonly entries: readonly CisaKevEntry[];
}

export type CisaKevSourceStatus =
  | "available"
  | "stale"
  | "unavailable"
  | "cancelled";

export interface CisaKevSourceResult {
  readonly source: "CISA KEV";
  readonly status: CisaKevSourceStatus;
  readonly catalog?: CisaKevCatalog;
  readonly fetchedAt?: string;
  readonly errorCode?:
    | "CACHE_ERROR"
    | "NETWORK_ERROR"
    | "INVALID_RESPONSE"
    | "CANCELLED";
}

export type KnownExploitationStatus =
  | "KNOWN_EXPLOITED"
  | "NOT_LISTED"
  | "UNKNOWN";

export interface CisaKevAssessment {
  readonly status: KnownExploitationStatus;
  readonly source: "CISA KEV";
  readonly cveIds: readonly string[];
  readonly matchedEntries: readonly CisaKevEntry[];
  readonly freshness: "fresh" | "stale" | "unavailable";
  readonly reason:
    | "catalog-match"
    | "fresh-catalog-no-match"
    | "no-cve-identity"
    | "stale-catalog"
    | "catalog-unavailable";
}

export interface VulnerabilityIdentifierLike {
  readonly id: string;
  readonly aliases: readonly string[];
}
