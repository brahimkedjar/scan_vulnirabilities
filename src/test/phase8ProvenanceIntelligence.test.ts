import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  analyzeProvenance,
  type PackageProvenanceInput,
} from "../core/provenance/ProvenanceIntelligence";

const SHA512 = `sha512-${"A".repeat(86)}==`;

function provenance(
  overrides: Partial<PackageProvenanceInput> = {},
): PackageProvenanceInput {
  return {
    dependencyId: "npm:fixture@1.0.0",
    packageName: "fixture",
    ecosystem: "npm",
    version: "1.0.0",
    sourceKind: "registry",
    registry: "https://registry.npmjs.org/fixture",
    integrity: SHA512,
    integrityVerification: "verified",
    ...overrides,
  };
}

void test("SAFE requires an explicit canonical registry and validated verified integrity", () => {
  const noRegistry: PackageProvenanceInput = {
    dependencyId: "no-registry",
    packageName: "no-registry",
    ecosystem: "npm",
    version: "1.0.0",
    sourceKind: "registry",
    integrity: SHA512,
    integrityVerification: "verified",
  };
  const result = analyzeProvenance([
    provenance(),
    provenance({
      dependencyId: "declared-only",
      packageName: "declared-only",
      integrityVerification: "unverified",
    }),
    noRegistry,
  ]);
  const byName = new Map(result.packages.map((item) => [item.packageName, item]));

  assert.equal(byName.get("fixture")?.status, "SAFE");
  assert.equal(byName.get("fixture")?.registryOrigin, "https://registry.npmjs.org");
  assert.equal(byName.get("fixture")?.integrityState, "VERIFIED");
  assert.equal(byName.get("declared-only")?.status, "KNOWN");
  assert.equal(byName.get("declared-only")?.integrityState, "DECLARED");
  assert.notEqual(byName.get("no-registry")?.status, "SAFE");
  assert.equal(result.coverage.safeRecords, 1);
});

void test("an expected private registry remains KNOWN rather than SAFE", () => {
  const result = analyzeProvenance(
    [
      provenance({
        registry: "https://packages.example.test/fixture",
      }),
    ],
    { expectedRegistries: { npm: ["https://packages.example.test"] } },
  );

  assert.equal(result.packages[0]?.registryCanonical, false);
  assert.equal(result.packages[0]?.status, "KNOWN");
  assert.equal(result.packages[0]?.anomalies.length, 0);
});

void test("evidence-supported provenance conditions stay anomalies, not malware verdicts", () => {
  const result = analyzeProvenance(
    [
      provenance({
        metadataPackageName: "different-name",
        registry: "https://packages.example.test/fixture",
        expectedRepository: "https://github.com/example/fixture",
        repository: "https://gitlab.example.test/fork/fixture",
        sourceKind: "git",
        registryPackageExpected: true,
        integrityVerification: "mismatch",
        signatureStatus: "unverifiable",
        hasInstallScript: true,
        publishedAgeDays: 2,
        maintainers: ["new-owner"],
        dependencyCount: 50,
        previous: {
          repository: "https://github.com/example/fixture",
          sourceUrl: "https://github.com/example/fixture",
          integrity: `sha512-${"B".repeat(86)}==`,
          maintainers: ["old-owner"],
          version: "1.0.0",
          dependencyCount: 4,
        },
        version: "4.0.0",
        sourceUrl: "https://gitlab.example.test/fork/fixture",
      }),
    ],
    { protectedPackageNames: ["fixtur3"] },
  );
  const item = result.packages[0];
  const signals = new Set(item?.anomalies.map((entry) => entry.signal));

  assert.equal(item?.status, "SUSPICIOUS");
  assert.equal(item?.malicious, "NOT_DETERMINED");
  assert.ok(signals.has("PACKAGE_NAME_MISMATCH"));
  assert.ok(signals.has("UNEXPECTED_REGISTRY"));
  assert.ok(signals.has("GIT_REPLACES_REGISTRY"));
  assert.ok(signals.has("INTEGRITY_MISMATCH"));
  assert.ok(signals.has("REPOSITORY_MISMATCH"));
  assert.ok(signals.has("MAINTAINER_CHANGE"));
  assert.ok(signals.has("MAJOR_VERSION_JUMP"));
  assert.ok(signals.has("DEPENDENCY_EXPLOSION"));
  assert.ok(signals.has("INSTALL_SCRIPT_PRESENT"));
  assert.ok(item?.anomalies.every((entry) => entry.securityVerdict === "NOT_ESTABLISHED"));
  assert.ok(item?.anomalies.every((entry) => entry.limitations.length > 0));
  assert.doesNotMatch(JSON.stringify(result), /malicious.{0,8}true/iu);
});

void test("local path sources and malformed integrity remain suspicious without exposing paths", () => {
  const result = analyzeProvenance([
    {
      dependencyId: "local",
      packageName: "local-fixture",
      ecosystem: "npm",
      version: "1.0.0",
      sourceKind: "local",
      lockfileSource: "C:\\Users\\private\\secret-package",
      integrity: "sha512-not-base64!!",
      integrityVerification: "verified",
    },
  ]);
  const item = result.packages[0];

  assert.equal(item?.status, "SUSPICIOUS");
  assert.equal(item?.integrityState, "UNKNOWN");
  assert.ok(item?.anomalies.some((entry) => entry.signal === "LOCAL_PATH_DEPENDENCY"));
  assert.ok(item?.anomalies.some((entry) => entry.signal === "INVALID_INTEGRITY_EVIDENCE"));
  assert.doesNotMatch(JSON.stringify(result), /Users|private|secret-package/iu);
});

void test("non-HTTPS, credential-bearing, and unallowlisted URLs are never contacted or retained", () => {
  const result = analyzeProvenance(
    [
      provenance({
        registry: "http://registry.npmjs.org/fixture",
        homepage: "https://user:password@example.test/fixture",
        sourceUrl: "https://unapproved.example.test/source",
      }),
    ],
    { allowedSourceOrigins: { npm: ["https://github.com"] } },
  );
  const serialized = JSON.stringify(result);

  assert.equal(result.packages[0]?.status, "SUSPICIOUS");
  assert.ok(
    result.packages[0]?.anomalies.some(
      (entry) => entry.signal === "SUSPICIOUS_EXTERNAL_URL",
    ),
  );
  assert.doesNotMatch(serialized, /password|user:|unapproved\.example/iu);
});

void test("provenance inputs with controls are sanitized and evidence is bounded", () => {
  const result = analyzeProvenance(
    [
      provenance({
        dependencyId: "bad\u202Eid",
        packageName: "bad\u0000name",
        publisher: "owner\u001b[31m",
      }),
      provenance({ dependencyId: "second", packageName: "second" }),
    ],
    { maximumRecords: 1, maximumAnomalies: 1 },
  );

  assert.equal(result.packages[0]?.dependencyId, "UNKNOWN");
  assert.equal(result.packages[0]?.packageName, "UNKNOWN");
  assert.equal(result.coverage.truncated, true);
  assert.equal(result.coverage.analysisComplete, false);
  assert.doesNotMatch(JSON.stringify(result), /\u001b|\u202e/iu);
});

void test("global anomaly limits are enforced before result aggregation", () => {
  const result = analyzeProvenance(
    [
      provenance({ sourceKind: "local", hasInstallScript: true }),
      provenance({
        dependencyId: "second",
        packageName: "second",
        sourceKind: "local",
        hasInstallScript: true,
      }),
    ],
    { maximumAnomalies: 1 },
  );

  assert.equal(result.anomalies.length, 1);
  assert.equal(result.coverage.anomaliesEmitted, 1);
  assert.ok((result.coverage.anomaliesOmitted ?? 0) > 0);
  assert.equal(result.coverage.truncated, true);
  assert.equal(result.coverage.analysisComplete, false);
  assert.equal(result.packages[0]?.status, "SUSPICIOUS");
  assert.equal(result.packages[1]?.status, "SUSPICIOUS");
});

void test("provenance analysis is deterministic, immutable, and cancellable", () => {
  const inputs = [provenance()];
  const first = analyzeProvenance(inputs);
  const second = analyzeProvenance(inputs);
  assert.deepEqual(first, second);
  assert.ok(Object.isFrozen(first));
  assert.ok(Object.isFrozen(first.packages));
  assert.ok(Object.isFrozen(first.packages[0]?.anomalies));

  const controller = new AbortController();
  controller.abort();
  const cancelled = analyzeProvenance(inputs, { signal: controller.signal });
  assert.equal(cancelled.coverage.cancelled, true);
  assert.equal(cancelled.coverage.analysisComplete, false);
  assert.deepEqual(cancelled.packages, []);
});
