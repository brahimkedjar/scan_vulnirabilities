import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  assessCisaKev,
  CISA_KEV_CATALOG_URL,
  CisaKevProvider,
  isCisaKevCatalog,
  normalizeCisaKevCatalog,
  type CisaKevCatalog,
} from "../intelligence/enrichment";
import type { CacheLookup } from "../services/VulnerabilityCache";

const NOW = Date.parse("2026-08-12T12:00:00.000Z");

function rawCatalog(overrides: Readonly<Record<string, unknown>> = {}): unknown {
  return {
    title: "CISA Catalog of Known Exploited Vulnerabilities",
    catalogVersion: "2026.08.12",
    dateReleased: "2026-08-12T10:00:00.000Z",
    count: 1,
    vulnerabilities: [
      {
        cveID: "CVE-2021-44228",
        vendorProject: "Apache",
        product: "Log4j",
        vulnerabilityName: "Apache Log4j Remote Code Execution Vulnerability",
        dateAdded: "2021-12-10",
        shortDescription: "Bounded fixture text.",
        requiredAction: "Apply updates per vendor instructions.",
        dueDate: "2021-12-24",
        knownRansomwareCampaignUse: "Known",
        notes: "",
        cwes: ["CWE-502", "CWE-917"],
      },
    ],
    ...overrides,
  };
}

function catalog(): CisaKevCatalog {
  return normalizeCisaKevCatalog(
    rawCatalog(),
    "2026-08-12T12:00:00.000Z",
  );
}

class MemoryCache {
  public lookup: CacheLookup<CisaKevCatalog> = { status: "miss" };
  public writes: CisaKevCatalog[] = [];

  public get(): CacheLookup<CisaKevCatalog> {
    return this.lookup;
  }

  public async setSuccessful(
    _key: unknown,
    value: CisaKevCatalog,
  ): Promise<void> {
    this.writes.push(value);
  }
}

void test("normalizes a bounded CISA KEV catalog and preserves auditable evidence", () => {
  const value = catalog();
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.source, "CISA KEV");
  assert.equal(value.entries[0]?.cveId, "CVE-2021-44228");
  assert.equal(value.entries[0]?.ransomwareUse, "known");
  assert.deepEqual(value.entries[0]?.cwes, ["CWE-502", "CWE-917"]);
  assert.ok(isCisaKevCatalog(value));
  assert.ok(Object.isFrozen(value));
  assert.ok(Object.isFrozen(value.entries));
  assert.ok(Object.isFrozen(value.entries[0]));
});

void test("rejects malformed counts, CVEs, dates, unsafe keys, conflicts, and bounds", () => {
  assert.throws(() => normalizeCisaKevCatalog(rawCatalog({ count: 2 }), new Date(NOW).toISOString()));
  assert.throws(() =>
    normalizeCisaKevCatalog(
      rawCatalog({ vulnerabilities: [{ ...(rawCatalog() as { vulnerabilities: Record<string, unknown>[] }).vulnerabilities[0], cveID: "CVE-../../secret" }] }),
      new Date(NOW).toISOString(),
    ),
  );
  assert.throws(() =>
    normalizeCisaKevCatalog(
      rawCatalog({ vulnerabilities: [{ ...(rawCatalog() as { vulnerabilities: Record<string, unknown>[] }).vulnerabilities[0], dueDate: "2026-02-30" }] }),
      new Date(NOW).toISOString(),
    ),
  );
  const unsafe = Object.create(null) as Record<string, unknown>;
  Object.defineProperty(unsafe, "__proto__", { value: "bad", enumerable: true });
  assert.throws(() => normalizeCisaKevCatalog(unsafe, new Date(NOW).toISOString()));

  const first = (rawCatalog() as { vulnerabilities: Record<string, unknown>[] }).vulnerabilities[0];
  assert.ok(first !== undefined);
  assert.throws(() =>
    normalizeCisaKevCatalog(
      rawCatalog({
        count: 2,
        vulnerabilities: [first, { ...first, product: "Conflicting product" }],
      }),
      new Date(NOW).toISOString(),
    ),
  );
  assert.throws(() =>
    normalizeCisaKevCatalog(
      rawCatalog({
        count: 10_001,
        vulnerabilities: Array.from({ length: 10_001 }, () => first),
      }),
      new Date(NOW).toISOString(),
    ),
  );
});

void test("loads only the fixed CISA endpoint and caches a validated catalog", async () => {
  const cache = new MemoryCache();
  let requestUrl = "";
  let requestBody: unknown = "not-called";
  const provider = new CisaKevProvider(
    {
      requestJson: async (url, options) => {
        requestUrl = url;
        requestBody = options?.body;
        return rawCatalog();
      },
    },
    cache,
    { clock: () => NOW },
  );

  const result = await provider.load();
  assert.equal(requestUrl, CISA_KEV_CATALOG_URL);
  assert.equal(requestBody, undefined);
  assert.equal(result.status, "available");
  assert.equal(cache.writes.length, 1);
  assert.equal(result.catalog?.entries.length, 1);
});

void test("uses fresh cache without networking and stale cache never proves absence", async () => {
  const cache = new MemoryCache();
  const value = catalog();
  cache.lookup = {
    status: "fresh",
    value,
    fetchedAt: NOW,
    expiresAt: NOW + 1_000,
  };
  let networkCalls = 0;
  const provider = new CisaKevProvider(
    {
      requestJson: async () => {
        networkCalls += 1;
        return rawCatalog();
      },
    },
    cache,
    { clock: () => NOW },
  );
  assert.equal((await provider.load()).status, "available");
  assert.equal(networkCalls, 0);

  cache.lookup = {
    status: "stale",
    value,
    fetchedAt: NOW - 100_000,
    expiresAt: NOW - 1,
  };
  const failing = new CisaKevProvider(
    { requestJson: async () => Promise.reject(new Error("offline")) },
    cache,
    { clock: () => NOW },
  );
  const stale = await failing.load();
  assert.equal(stale.status, "stale");
  assert.equal(
    assessCisaKev(
      { id: "CVE-2021-44228", aliases: [] },
      stale,
      { clock: () => NOW },
    ).status,
    "UNKNOWN",
  );
});

void test("classifies only a fresh exact CVE match as known exploited", () => {
  const source = {
    source: "CISA KEV" as const,
    status: "available" as const,
    catalog: catalog(),
  };
  const match = assessCisaKev(
    { id: "GHSA-test", aliases: ["cve-2021-44228"] },
    source,
    { clock: () => NOW },
  );
  assert.equal(match.status, "KNOWN_EXPLOITED");
  assert.equal(match.matchedEntries[0]?.cveId, "CVE-2021-44228");

  const absent = assessCisaKev(
    { id: "CVE-2024-12345", aliases: [] },
    source,
    { clock: () => NOW },
  );
  assert.equal(absent.status, "NOT_LISTED");
  assert.equal(absent.reason, "fresh-catalog-no-match");

  const noCve = assessCisaKev(
    { id: "GHSA-no-cve", aliases: [] },
    source,
    { clock: () => NOW },
  );
  assert.equal(noCve.status, "UNKNOWN");
  assert.equal(noCve.reason, "no-cve-identity");
});

void test("staleness, cancellation, and provider failure stay UNKNOWN", async () => {
  const staleCatalog = normalizeCisaKevCatalog(
    rawCatalog(),
    "2026-07-01T00:00:00.000Z",
  );
  const stale = assessCisaKev(
    { id: "CVE-2021-44228", aliases: [] },
    { source: "CISA KEV", status: "available", catalog: staleCatalog },
    { clock: () => NOW },
  );
  assert.equal(stale.status, "UNKNOWN");
  assert.equal(stale.freshness, "stale");

  const staleRelease = assessCisaKev(
    { id: "CVE-2024-12345", aliases: [] },
    {
      source: "CISA KEV",
      status: "available",
      catalog: normalizeCisaKevCatalog(
        rawCatalog({ dateReleased: "2020-01-01T00:00:00.000Z" }),
        "2026-08-12T11:59:00.000Z",
      ),
    },
    { clock: () => NOW },
  );
  assert.equal(staleRelease.status, "UNKNOWN");
  assert.equal(staleRelease.reason, "stale-catalog");

  const controller = new AbortController();
  controller.abort();
  const provider = new CisaKevProvider(
    { requestJson: async () => rawCatalog() },
    new MemoryCache(),
    { clock: () => NOW },
  );
  assert.equal((await provider.load(controller.signal)).status, "cancelled");

  const failed = await new CisaKevProvider(
    { requestJson: async () => Promise.reject(new Error("offline")) },
    new MemoryCache(),
    { clock: () => NOW },
  ).load();
  assert.equal(failed.status, "unavailable");
  assert.equal(
    assessCisaKev(
      { id: "CVE-2021-44228", aliases: [] },
      failed,
      { clock: () => NOW },
    ).status,
    "UNKNOWN",
  );
});

void test("a forged available envelope cannot prove known exploitation or absence", () => {
  const assessment = assessCisaKev(
    {
      id: "CVE-2021-44228",
      aliases: [],
    },
    {
      source: "CISA KEV",
      status: "available",
      catalog: {
        schemaVersion: 1,
        source: "CISA KEV",
        catalogVersion: "forged",
        releasedAt: "not-a-date",
        fetchedAt: new Date(NOW).toISOString(),
        entries: [],
      },
    },
    { clock: () => NOW },
  );

  assert.equal(assessment.status, "UNKNOWN");
  assert.equal(assessment.reason, "catalog-unavailable");
});

void test("a noncanonical cached CVE cannot prove catalog absence", () => {
  const canonical = catalog();
  const entry = canonical.entries[0];
  assert.ok(entry !== undefined);
  const forged = {
    ...canonical,
    entries: [{ ...entry, cveId: entry.cveId.toLowerCase() }],
  };

  assert.equal(isCisaKevCatalog(forged), false);
  const assessment = assessCisaKev(
    { id: "CVE-2021-44228", aliases: [] },
    { source: "CISA KEV", status: "available", catalog: forged },
    { clock: () => NOW },
  );
  assert.equal(assessment.status, "UNKNOWN");
  assert.equal(assessment.reason, "catalog-unavailable");
});

void test("a malformed live catalog is unavailable, never a clean empty source", async () => {
  const provider = new CisaKevProvider(
    { requestJson: async () => ({ count: 0, vulnerabilities: [] }) },
    new MemoryCache(),
    { clock: () => NOW },
  );

  const result = await provider.load();
  assert.equal(result.status, "unavailable");
  assert.equal(result.errorCode, "INVALID_RESPONSE");
});

void test("repeated assessment reuses one validated exact-CVE index", () => {
  const source = {
    source: "CISA KEV" as const,
    status: "available" as const,
    catalog: catalog(),
  };
  const first = assessCisaKev(
    { id: "CVE-2021-44228", aliases: [] },
    source,
    { clock: () => NOW },
  );
  const second = assessCisaKev(
    { id: "CVE-2024-12345", aliases: [] },
    source,
    { clock: () => NOW },
  );
  assert.equal(first.status, "KNOWN_EXPLOITED");
  assert.equal(second.status, "NOT_LISTED");
});
