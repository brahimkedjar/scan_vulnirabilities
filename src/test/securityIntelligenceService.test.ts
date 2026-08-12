import assert from "node:assert/strict";
import test from "node:test";

import {
  SecurityIntelligenceError,
  SecurityIntelligenceService,
} from "../intelligence/SecurityIntelligenceService";
import type { CisaKevSourceResult } from "../intelligence/enrichment";
import type { Vulnerability } from "../models/Vulnerability";

const NOW = Date.parse("2026-08-12T20:00:00.000Z");

function vulnerability(
  overrides: Partial<Vulnerability> = {},
): Vulnerability {
  return {
    id: "GHSA-test-0001",
    aliases: ["CVE-2026-12345"],
    packageName: "example",
    ecosystem: "npm",
    installedVersion: "1.0.0",
    severity: "HIGH",
    cvssScore: 8,
    summary: "A bounded test advisory",
    fixedVersions: ["1.0.1"],
    remediationCandidates: ["1.0.1"],
    references: ["https://osv.dev/vulnerability/GHSA-test-0001"],
    source: "OSV",
    ...overrides,
  };
}

function availableKev(): CisaKevSourceResult {
  return {
    source: "CISA KEV",
    status: "available",
    fetchedAt: "2026-08-12T19:00:00.000Z",
    catalog: {
      schemaVersion: 1,
      source: "CISA KEV",
      catalogVersion: "2026.08.12",
      releasedAt: "2026-08-12T18:00:00.000Z",
      fetchedAt: "2026-08-12T19:00:00.000Z",
      entries: [
        {
          cveId: "CVE-2026-12345",
          vendorProject: "Example",
          product: "Example",
          vulnerabilityName: "Example vulnerability",
          dateAdded: "2026-08-10",
          dueDate: "2026-08-31",
          requiredAction: "Apply mitigations",
          ransomwareUse: "unknown",
          cwes: ["CWE-79"],
        },
      ],
    },
  };
}

void test("correlates exact CVE evidence and exposes an explainable risk ledger", async () => {
  const service = new SecurityIntelligenceService(
    { load: async () => availableKev() },
    { clock: () => NOW },
  );

  const result = await service.analyze([vulnerability()]);

  // The KEV lookup is complete, but missing reachability/CWE evidence keeps the
  // combined intelligence snapshot explicitly incomplete.
  assert.equal(result.complete, false);
  assert.equal(result.findings[0]?.knownExploitation.status, "KNOWN_EXPLOITED");
  assert.equal(result.findings[0]?.risk.score, 74);
  assert.deepEqual(
    result.findings[0]?.risk.factors.map((factor) => factor.id),
    ["severity", "cvss", "known-exploitation", "reachability"],
  );
  assert.equal(result.findings[0]?.risk.missingEvidence.includes("reachability"), true);
  assert.ok(
    result.policyFindings.some(
      (finding) =>
        finding.advisoryId === "CVE-2026-12345" &&
        finding.knownExploitation === "known-exploited",
    ),
  );
  assert.ok(
    result.policyFindings.some(
      (finding) =>
        finding.advisoryId === "GHSA-test-0001" &&
        finding.knownExploitation === "known-exploited",
    ),
  );
  assert.equal(result.intelligence.findings.length, 1);
});

void test("keeps unavailable KEV and reachability evidence unknown", async () => {
  const service = new SecurityIntelligenceService(
    {
      load: async () => ({
        source: "CISA KEV",
        status: "unavailable",
        errorCode: "NETWORK_ERROR",
      }),
    },
    { clock: () => NOW },
  );

  const result = await service.analyze([vulnerability()]);

  assert.equal(result.complete, false);
  assert.equal(result.findings[0]?.knownExploitation.status, "UNKNOWN");
  assert.equal(result.policyFindings[0]?.knownExploitation, "unknown");
  assert.deepEqual(result.findings[0]?.risk.missingEvidence, [
    "known-exploitation",
    "reachability",
  ]);
});

void test("does not classify a fresh catalog absence when there is no CVE identity", async () => {
  const service = new SecurityIntelligenceService(
    { load: async () => availableKev() },
    { clock: () => NOW },
  );

  const result = await service.analyze([
    vulnerability({ aliases: ["GHSA-other-0002"] }),
  ]);

  assert.equal(result.findings[0]?.knownExploitation.status, "UNKNOWN");
  assert.equal(result.findings[0]?.knownExploitation.reason, "no-cve-identity");
});

void test("fails closed on cancellation and bounded input", async () => {
  const controller = new AbortController();
  controller.abort();
  const service = new SecurityIntelligenceService(
    { load: async () => availableKev() },
    { clock: () => NOW, maximumFindings: 1 },
  );

  await assert.rejects(
    service.analyze([vulnerability()], { signal: controller.signal }),
    (error: unknown) =>
      error instanceof SecurityIntelligenceError && error.code === "CANCELLED",
  );
  await assert.rejects(
    service.analyze([vulnerability(), vulnerability({ id: "OSV-2" })]),
    (error: unknown) =>
      error instanceof SecurityIntelligenceError &&
      error.code === "LIMIT_EXCEEDED",
  );
});

void test("preflights expanded advisory identities before provider or evidence allocation", async () => {
  let providerLoads = 0;
  const service = new SecurityIntelligenceService(
    {
      load: async () => {
        providerLoads += 1;
        return availableKev();
      },
    },
    {
      clock: () => NOW,
      maximumFindings: 10,
      maximumPolicyIdentities: 3,
    },
  );

  await assert.rejects(
    service.analyze([
      vulnerability({
        aliases: ["CVE-2026-12345", "GHSA-other-0002", "OSV-ALIAS-3"],
      }),
    ]),
    (error: unknown) =>
      error instanceof SecurityIntelligenceError &&
      error.code === "LIMIT_EXCEEDED",
  );
  assert.equal(providerLoads, 0);
});

void test("preflight includes canonical CVE variants that policy emission would add", async () => {
  let providerLoads = 0;
  const service = new SecurityIntelligenceService(
    {
      load: async () => {
        providerLoads += 1;
        return availableKev();
      },
    },
    {
      clock: () => NOW,
      maximumFindings: 1,
      maximumPolicyIdentities: 1,
    },
  );

  await assert.rejects(
    service.analyze([
      vulnerability({ id: "cve-2026-12345", aliases: [] }),
    ]),
    (error: unknown) =>
      error instanceof SecurityIntelligenceError &&
      error.code === "LIMIT_EXCEEDED",
  );
  assert.equal(providerLoads, 0);
});
