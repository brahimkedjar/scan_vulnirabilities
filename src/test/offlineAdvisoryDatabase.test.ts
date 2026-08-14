import assert from "node:assert/strict";
import { test } from "node:test";

import type { Vulnerability } from "../models/Vulnerability";
import {
  createOfflineAdvisoryProvider,
  OfflineAdvisoryDatabaseError,
  offlineAdvisoryPayloadSha256,
  type OfflineAdvisoryDatabaseDocument,
  type OfflineAdvisoryDatabasePayload,
} from "../core/vulnerability";

const NOW = Date.parse("2026-08-13T10:00:00.000Z");

function finding(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: "OSV-LOCAL-1",
    aliases: ["CVE-2026-10001"],
    packageName: "fixture-package",
    ecosystem: "npm",
    installedVersion: "1.0.0",
    severity: "HIGH",
    cvssScore: 8.1,
    summary: "Bounded offline fixture",
    fixedVersions: ["1.0.1"],
    remediationCandidates: ["1.0.1"],
    fixedVersion: "1.0.1",
    references: ["https://example.test/advisories/OSV-LOCAL-1"],
    source: "LOCAL-OSV",
    ...overrides,
  };
}

function payload(
  overrides: Partial<OfflineAdvisoryDatabasePayload> = {},
): OfflineAdvisoryDatabasePayload {
  return {
    schemaVersion: 1,
    provider: "LOCAL-OSV",
    generatedAt: "2026-08-12T10:00:00.000Z",
    validUntil: "2026-08-20T10:00:00.000Z",
    entries: [
      {
        ecosystem: "npm",
        packageName: "fixture-package",
        version: "1.0.0",
        vulnerabilities: [finding()],
      },
    ],
    ...overrides,
  };
}

function document(
  value: OfflineAdvisoryDatabasePayload = payload(),
): OfflineAdvisoryDatabaseDocument {
  return {
    ...value,
    payloadSha256: offlineAdvisoryPayloadSha256(value),
  };
}

void test("offline database serves exact current evidence without network access", async () => {
  const provider = createOfflineAdvisoryProvider(JSON.stringify(document()), {
    now: NOW,
  });

  assert.equal(provider.name, "LOCAL-OSV");
  assert.equal(provider.metadata.status, "current");
  assert.equal(provider.metadata.entries, 1);
  assert.equal(provider.metadata.vulnerabilities, 1);
  const result = await provider.checkPackage(
    "fixture-package",
    "npm",
    "1.0.0",
  );
  assert.deepEqual(result.map((entry) => entry.id), ["OSV-LOCAL-1"]);
  await assert.rejects(
    provider.checkPackage("other-package", "npm", "1.0.0"),
    (error: unknown) =>
      error instanceof OfflineAdvisoryDatabaseError &&
      error.code === "SUBJECT_NOT_COVERED",
  );

  const explicitEmptyPayload = payload({
    entries: [
      ...payload().entries,
      {
        ecosystem: "npm",
        packageName: "other-package",
        version: "1.0.0",
        vulnerabilities: [],
      },
    ],
  });
  const explicitEmpty = createOfflineAdvisoryProvider(
    JSON.stringify(document(explicitEmptyPayload)),
    { now: NOW },
  );
  assert.deepEqual(
    await explicitEmpty.checkPackage("other-package", "npm", "1.0.0"),
    [],
  );

  result[0]?.aliases.push("MUTATION");
  const repeated = await provider.checkPackage(
    "fixture-package",
    "npm",
    "1.0.0",
  );
  assert.deepEqual(repeated[0]?.aliases, ["CVE-2026-10001"]);
});

void test("offline database rejects tampering before exposing a provider", () => {
  const valid = document();
  const tampered = {
    ...valid,
    entries: [
      {
        ...valid.entries[0],
        vulnerabilities: [finding({ severity: "LOW" })],
      },
    ],
  };
  assert.throws(
    () => createOfflineAdvisoryProvider(JSON.stringify(tampered), { now: NOW }),
    (error: unknown) =>
      error instanceof OfflineAdvisoryDatabaseError &&
      error.code === "INTEGRITY_MISMATCH",
  );
});

void test("offline database fails closed when its evidence is stale", () => {
  assert.throws(
    () =>
      createOfflineAdvisoryProvider(JSON.stringify(document()), {
        now: Date.parse("2026-09-20T10:00:00.000Z"),
      }),
    (error: unknown) =>
      error instanceof OfflineAdvisoryDatabaseError &&
      error.code === "STALE_DATABASE",
  );
});

void test("offline database rejects duplicate JSON keys and duplicate coordinates", () => {
  const validText = JSON.stringify(document());
  assert.throws(
    () =>
      createOfflineAdvisoryProvider(
        validText.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'),
        { now: NOW },
      ),
    (error: unknown) =>
      error instanceof OfflineAdvisoryDatabaseError &&
      error.code === "INVALID_DATABASE",
  );

  const duplicatePayload = payload({
    entries: [payload().entries[0]!, payload().entries[0]!],
  });
  assert.throws(
    () =>
      createOfflineAdvisoryProvider(
        JSON.stringify(document(duplicatePayload)),
        { now: NOW },
      ),
    (error: unknown) =>
      error instanceof OfflineAdvisoryDatabaseError &&
      error.code === "INVALID_DATABASE",
  );
});

void test("offline database rejects coordinate/provider forgery", () => {
  const wrongProviderPayload = payload({
    entries: [
      {
        ecosystem: "npm",
        packageName: "fixture-package",
        version: "1.0.0",
        vulnerabilities: [finding({ source: "OSV" })],
      },
    ],
  });
  assert.throws(
    () =>
      createOfflineAdvisoryProvider(
        JSON.stringify(document(wrongProviderPayload)),
        { now: NOW },
      ),
    OfflineAdvisoryDatabaseError,
  );

  const noncanonicalPayload = payload({
    entries: [
      {
        ecosystem: "npm",
        packageName: "fixture-package",
        version: "01.0.0",
        vulnerabilities: [
          finding({ installedVersion: "01.0.0" }),
        ],
      },
    ],
  });
  assert.throws(
    () =>
      createOfflineAdvisoryProvider(
        JSON.stringify(document(noncanonicalPayload)),
        { now: NOW },
      ),
    OfflineAdvisoryDatabaseError,
  );
});

void test("offline database observes cancellation during parsing and queries", async () => {
  const cancelled = new AbortController();
  cancelled.abort();
  assert.throws(
    () =>
      createOfflineAdvisoryProvider(JSON.stringify(document()), {
        now: NOW,
        signal: cancelled.signal,
      }),
    (error: unknown) =>
      error instanceof OfflineAdvisoryDatabaseError &&
      error.code === "CANCELLED",
  );

  const provider = createOfflineAdvisoryProvider(JSON.stringify(document()), {
    now: NOW,
  });
  await assert.rejects(
    provider.checkPackage(
      "fixture-package",
      "npm",
      "1.0.0",
      cancelled.signal,
    ),
    (error: unknown) =>
      error instanceof OfflineAdvisoryDatabaseError &&
      error.code === "CANCELLED",
  );
});
