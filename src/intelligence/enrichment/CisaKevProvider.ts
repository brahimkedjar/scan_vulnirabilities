import type { Vulnerability } from "../../models/Vulnerability";
import type { NetworkService } from "../../services/NetworkService";
import type {
  CacheLookup,
  VulnerabilityCacheKey,
} from "../../services/VulnerabilityCache";
import type {
  CisaKevAssessment,
  CisaKevCatalog,
  CisaKevEntry,
  CisaKevSourceResult,
  VulnerabilityIdentifierLike,
} from "./CisaKevModels";
import {
  isCisaKevCatalog,
  normalizeCisaKevCatalog,
} from "./CisaKevNormalizer";

export const CISA_KEV_CATALOG_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export const CISA_KEV_CACHE_KEY: VulnerabilityCacheKey = Object.freeze({
  provider: "CISA-KEV",
  ecosystem: "catalog",
  packageName: "known-exploited-vulnerabilities",
  version: "schema-1",
});

const CVE_PATTERN = /^CVE-(?:19|20)\d{2}-\d{4,19}$/u;
const DEFAULT_MAXIMUM_CATALOG_AGE_MS = 7 * 24 * 60 * 60 * 1_000;

export interface CisaKevCache {
  get(key: VulnerabilityCacheKey): CacheLookup<CisaKevCatalog>;
  setSuccessful(key: VulnerabilityCacheKey, value: CisaKevCatalog): Promise<void>;
}

export interface CisaKevProviderOptions {
  readonly clock?: () => number;
}

export interface CisaKevAssessmentOptions {
  readonly clock?: () => number;
  readonly maximumCatalogAgeMs?: number;
}

const catalogIndexes = new WeakMap<
  CisaKevCatalog,
  ReadonlyMap<string, CisaKevEntry>
>();

/** Validates each catalog object once and caches its exact-CVE lookup weakly. */
function indexCisaKevCatalog(
  source: CisaKevSourceResult,
): ReadonlyMap<string, CisaKevEntry> | undefined {
  if (source.status !== "available" || source.catalog === undefined) {
    return undefined;
  }
  const cached = catalogIndexes.get(source.catalog);
  if (cached !== undefined) {
    return cached;
  }
  if (!isCisaKevCatalog(source.catalog)) {
    return undefined;
  }
  const created = new Map(
    source.catalog.entries.map((entry) => [entry.cveId, entry]),
  );
  catalogIndexes.set(source.catalog, created);
  return created;
}

function checkedTimestamp(clock: () => number): { milliseconds: number; iso: string } {
  const milliseconds = clock();
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) {
    throw new RangeError("CISA KEV clock must return a non-negative safe integer");
  }
  return { milliseconds, iso: new Date(milliseconds).toISOString() };
}

function cancellation(error: unknown, signal: AbortSignal | undefined): boolean {
  return (
    signal?.aborted === true ||
    (error instanceof Error && error.name === "AbortError") ||
    (typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "CANCELLED")
  );
}

export class CisaKevProvider {
  private readonly clock: () => number;

  public constructor(
    private readonly network: Pick<NetworkService, "requestJson">,
    private readonly cache: CisaKevCache,
    options: CisaKevProviderOptions = {},
  ) {
    this.clock = options.clock ?? Date.now;
  }

  public async load(signal?: AbortSignal): Promise<CisaKevSourceResult> {
    if (signal?.aborted === true) {
      return Object.freeze({
        source: "CISA KEV",
        status: "cancelled",
        errorCode: "CANCELLED",
      });
    }
    let cached: CacheLookup<CisaKevCatalog> = { status: "miss" };
    let cacheReadFailed = false;
    try {
      cached = this.cache.get(CISA_KEV_CACHE_KEY);
      if (cached.status === "fresh") {
        return Object.freeze({
          source: "CISA KEV",
          status: "available",
          catalog: cached.value,
          fetchedAt: cached.value.fetchedAt,
        });
      }
    } catch {
      cacheReadFailed = true;
    }

    try {
      const now = checkedTimestamp(this.clock);
      const raw = await this.network.requestJson(
        CISA_KEV_CATALOG_URL,
        { method: "GET" },
        signal,
      );
      const catalog = normalizeCisaKevCatalog(raw, now.iso);
      try {
        await this.cache.setSuccessful(CISA_KEV_CACHE_KEY, catalog);
      } catch {
        cacheReadFailed = true;
      }
      return Object.freeze({
        source: "CISA KEV",
        status: "available",
        catalog,
        fetchedAt: catalog.fetchedAt,
        ...(cacheReadFailed ? { errorCode: "CACHE_ERROR" as const } : {}),
      });
    } catch (error: unknown) {
      if (cancellation(error, signal)) {
        return Object.freeze({
          source: "CISA KEV",
          status: "cancelled",
          errorCode: "CANCELLED",
        });
      }
      if (cached.status === "stale") {
        return Object.freeze({
          source: "CISA KEV",
          status: "stale",
          catalog: cached.value,
          fetchedAt: cached.value.fetchedAt,
          errorCode: cacheReadFailed ? "CACHE_ERROR" : "NETWORK_ERROR",
        });
      }
      return Object.freeze({
        source: "CISA KEV",
        status: "unavailable",
        errorCode:
          error instanceof TypeError
            ? "INVALID_RESPONSE"
            : cacheReadFailed
              ? "CACHE_ERROR"
              : "NETWORK_ERROR",
      });
    }
  }
}

function cveIds(value: VulnerabilityIdentifierLike): readonly string[] {
  const unique = new Set<string>();
  for (const identifier of [value.id, ...value.aliases]) {
    const normalized = identifier.trim().toUpperCase();
    if (CVE_PATTERN.test(normalized)) {
      unique.add(normalized);
    }
  }
  return Object.freeze([...unique].sort());
}

export function assessCisaKev(
  vulnerability: Pick<Vulnerability, "id" | "aliases">,
  source: CisaKevSourceResult,
  options: CisaKevAssessmentOptions = {},
): CisaKevAssessment {
  const identifiers = cveIds(vulnerability);
  if (identifiers.length === 0) {
    return Object.freeze({
      status: "UNKNOWN",
      source: "CISA KEV",
      cveIds: identifiers,
      matchedEntries: Object.freeze([]),
      freshness: source.status === "stale" ? "stale" : source.status === "available" ? "fresh" : "unavailable",
      reason: "no-cve-identity",
    });
  }
  const index = indexCisaKevCatalog(source);
  if (source.status !== "available" || source.catalog === undefined || index === undefined) {
    return Object.freeze({
      status: "UNKNOWN",
      source: "CISA KEV",
      cveIds: identifiers,
      matchedEntries: Object.freeze([]),
      freshness: source.status === "stale" ? "stale" : "unavailable",
      reason: source.status === "stale" ? "stale-catalog" : "catalog-unavailable",
    });
  }
  const maximumAge = options.maximumCatalogAgeMs ?? DEFAULT_MAXIMUM_CATALOG_AGE_MS;
  if (!Number.isSafeInteger(maximumAge) || maximumAge < 1) {
    throw new RangeError("maximumCatalogAgeMs must be a positive safe integer");
  }
  const now = checkedTimestamp(options.clock ?? Date.now).milliseconds;
  const evidenceTimestamps = [
    Date.parse(source.catalog.releasedAt),
    Date.parse(source.catalog.fetchedAt),
  ];
  if (
    evidenceTimestamps.some(
      (value) =>
        !Number.isFinite(value) || now < value || now - value > maximumAge,
    )
  ) {
    return Object.freeze({
      status: "UNKNOWN",
      source: "CISA KEV",
      cveIds: identifiers,
      matchedEntries: Object.freeze([]),
      freshness: "stale",
      reason: "stale-catalog",
    });
  }
  const matches = identifiers.flatMap((identifier) => {
    const entry = index.get(identifier);
    return entry === undefined ? [] : [entry];
  });
  Object.freeze(matches);
  return Object.freeze({
    status: matches.length > 0 ? "KNOWN_EXPLOITED" : "NOT_LISTED",
    source: "CISA KEV",
    cveIds: identifiers,
    matchedEntries: matches,
    freshness: "fresh",
    reason: matches.length > 0 ? "catalog-match" : "fresh-catalog-no-match",
  });
}
