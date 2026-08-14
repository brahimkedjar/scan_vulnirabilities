import assert from "node:assert/strict";
import test from "node:test";

import {
  BoundedJsonError,
  canonicalJson,
  parseBoundedJson,
} from "../core/security";
import {
  buildSecuritySnapshot,
  compareSecurityBaseline,
  createSecurityBaseline,
  diffSecuritySnapshots,
  parseSecurityBaselineJson,
  parseSecuritySnapshotJson,
  SecurityBaselineError,
  SecurityHistoryError,
  SecuritySnapshotError,
  serializeSecurityBaseline,
  serializeSecuritySnapshot,
  verifySecurityBaseline,
  verifySecuritySnapshot,
} from "../core/snapshot";
import { analyzeLicenseInventory } from "../core/license/LicenseIntelligence";
import { analyzeProvenance } from "../core/provenance/ProvenanceIntelligence";
import { analyzeStaticReachability } from "../core/reachability/StaticReachability";
import type { Dependency } from "../models/Dependency";
import type { ScanError, ScanResult } from "../models/ScanResult";
import type { Vulnerability } from "../models/Vulnerability";

function dependency(
  name: string,
  version: string,
  overrides: Partial<Dependency> = {},
): Dependency {
  return {
    name,
    ecosystem: "npm",
    installedVersion: version,
    resolutionStatus: "resolved",
    dependencyType: "direct",
    environment: "production",
    packageManager: "npm",
    manifestPath: "C:\\secret-workspace\\package.json",
    lockfilePath: "C:\\secret-workspace\\package-lock.json",
    workspacePath: "C:\\secret-workspace",
    metadata: { authorization: "Bearer must-never-appear" },
    ...overrides,
  };
}

function vulnerability(
  id: string,
  name: string,
  version: string,
  overrides: Partial<Vulnerability> = {},
): Vulnerability {
  return {
    id,
    aliases: [`CVE-2026-${id.slice(-4).padStart(4, "0")}`],
    packageName: name,
    ecosystem: "npm",
    installedVersion: version,
    severity: "HIGH",
    cvssScore: 8.1,
    summary: "secret prose must not be persisted",
    details: "token=must-never-appear",
    references: ["https://example.test/advisory?token=secret"],
    fixedVersions: ["2.0.0"],
    source: "OSV",
    ...overrides,
  };
}

function scan(
  dependencies: readonly Dependency[],
  findings: readonly Vulnerability[],
  options: {
    readonly errors?: readonly ScanError[];
    readonly providerStatus?: "available" | "partial" | "unavailable";
    readonly providerFindingCount?: number;
    readonly includeCompleteFindings?: boolean;
    readonly cancelled?: boolean;
  } = {},
): ScanResult {
  const status = options.providerStatus ?? "available";
  return {
    workspacePath: "C:\\secret-workspace",
    scannedAt: "2026-08-13T00:00:00.000Z",
    durationMs: 10,
    packageManagers: ["npm"],
    dependenciesScanned: dependencies.length,
    vulnerableDependencies: findings.length,
    ...(options.includeCompleteFindings === false
      ? {}
      : { unfilteredVulnerabilities: findings }),
    vulnerabilities: findings,
    dependencies,
    errors: options.errors ?? [],
    providerResults:
      dependencies.length === 0 && status === "available"
        ? []
        : [
            {
              provider: "OSV",
              status,
              dependenciesEligible: dependencies.length,
              dependenciesSubmitted: dependencies.length,
              successful: status === "unavailable" ? 0 : dependencies.length,
              failed: status === "available" ? 0 : dependencies.length,
              cacheHits: 0,
              staleCacheFallbacks: 0,
              vulnerabilitiesFound:
                options.providerFindingCount ?? findings.length,
            },
          ],
    cancelled: options.cancelled ?? false,
  };
}

const SNAPSHOT_OPTIONS = Object.freeze({
  timestamp: "2026-08-13T01:02:03.000Z",
  scannerVersion: "0.9.0",
  workspaceIdentity: "repository:scan-vulnerabilities",
});

void test("bounded JSON rejects duplicate/prototype keys and resource excess", () => {
  assert.throws(
    () => parseBoundedJson('{"a":1,"a":2}'),
    (error: unknown) =>
      error instanceof BoundedJsonError && error.code === "INVALID_JSON",
  );
  assert.throws(
    () => parseBoundedJson('{"__proto__":{"polluted":true}}'),
    (error: unknown) =>
      error instanceof BoundedJsonError && error.code === "UNSAFE_KEY",
  );
  assert.equal((Object.prototype as { polluted?: unknown }).polluted, undefined);
  assert.throws(
    () =>
      parseBoundedJson('{"a":{"b":{"c":1}}}', {
        limits: { maximumDepth: 2 },
      }),
    (error: unknown) =>
      error instanceof BoundedJsonError && error.code === "LIMIT_EXCEEDED",
  );
  assert.throws(
    () => parseBoundedJson('{"values":[1,2]}', { limits: { maximumArrayItems: 1 } }),
    (error: unknown) =>
      error instanceof BoundedJsonError && error.code === "LIMIT_EXCEEDED",
  );
  assert.throws(
    () => parseBoundedJson('{"long":"123456"}', { limits: { maximumBytes: 8 } }),
    (error: unknown) =>
      error instanceof BoundedJsonError && error.code === "LIMIT_EXCEEDED",
  );
  const controller = new AbortController();
  controller.abort();
  assert.throws(
    () => parseBoundedJson("{}", { signal: controller.signal }),
    (error: unknown) =>
      error instanceof BoundedJsonError && error.code === "CANCELLED",
  );
});

void test("security snapshots are deterministic, immutable, evidence preserving, and path free", () => {
  const dependencies = [dependency("beta", "1.0.0"), dependency("alpha", "1.0.0")];
  const findings = [
    vulnerability("OSV-2026-0001", "alpha", "1.0.0", {
      fixedVersionConflict: true,
    }),
  ];
  const first = buildSecuritySnapshot([scan(dependencies, findings)], {
    ...SNAPSHOT_OPTIONS,
    findingIntelligence: [
      {
        advisoryId: "OSV-2026-0001",
        ecosystem: "npm",
        packageName: "alpha",
        installedVersion: "1.0.0",
        knownExploitation: "known-exploited",
      },
    ],
  });
  const second = buildSecuritySnapshot(
    [scan([...dependencies].reverse(), [...findings].reverse())],
    {
      ...SNAPSHOT_OPTIONS,
      findingIntelligence: [
        {
          advisoryId: "OSV-2026-0001",
          ecosystem: "npm",
          packageName: "alpha",
          installedVersion: "1.0.0",
          knownExploitation: "known-exploited",
        },
      ],
    },
  );
  assert.equal(serializeSecuritySnapshot(first), serializeSecuritySnapshot(second));
  assert.equal(first.vulnerabilities[0]?.fixedVersionConflict, true);
  assert.equal(first.vulnerabilities[0]?.knownExploitation, "known-exploited");
  assert.equal(first.analysis.licenses, "not-configured");
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.dependencies), true);
  assert.equal(Object.isFrozen(first.vulnerabilities[0]), true);
  assert.equal(verifySecuritySnapshot(first), true);
  const serialized = serializeSecuritySnapshot(first);
  assert.doesNotMatch(serialized, /secret-workspace|must-never-appear|package\.json|https:/u);
  assert.equal(parseSecuritySnapshotJson(serialized).integrity.digest, first.integrity.digest);
});

void test("snapshot parsing verifies hashes and fails closed on hidden findings", () => {
  const finding = vulnerability("OSV-2026-0002", "alpha", "1.0.0");
  const complete = buildSecuritySnapshot(
    [
      scan([dependency("alpha", "1.0.0")], [finding], {
        includeCompleteFindings: false,
        providerFindingCount: 2,
      }),
    ],
    SNAPSHOT_OPTIONS,
  );
  assert.equal(complete.coverage.status, "partial");
  assert.equal(complete.coverage.vulnerabilityAnalysis, "partial");

  const tampered = JSON.parse(serializeSecuritySnapshot(complete)) as {
    vulnerabilities: Array<{ severity: string }>;
  };
  const first = tampered.vulnerabilities[0];
  assert.notEqual(first, undefined);
  if (first !== undefined) {
    first.severity = "LOW";
  }
  assert.throws(
    () => parseSecuritySnapshotJson(JSON.stringify(tampered)),
    (error: unknown) =>
      error instanceof SecuritySnapshotError && error.code === "INTEGRITY_MISMATCH",
  );
  assert.throws(
    () =>
      buildSecuritySnapshot(
        [scan([dependency("a", "1.0.0"), dependency("b", "1.0.0")], [])],
        { ...SNAPSHOT_OPTIONS, maximumDependencies: 1 },
      ),
    (error: unknown) =>
      error instanceof SecuritySnapshotError && error.code === "LIMIT_EXCEEDED",
  );
  const controller = new AbortController();
  controller.abort();
  assert.throws(
    () =>
      buildSecuritySnapshot([], {
        ...SNAPSHOT_OPTIONS,
        signal: controller.signal,
      }),
    (error: unknown) =>
      error instanceof SecuritySnapshotError && error.code === "CANCELLED",
  );
});

void test("baselines have independent SHA-256 integrity and reject tampering", () => {
  const snapshot = buildSecuritySnapshot(
    [scan([dependency("alpha", "1.0.0")], [])],
    SNAPSHOT_OPTIONS,
  );
  const baseline = createSecurityBaseline(snapshot, {
    createdAt: "2026-08-13T02:00:00.000Z",
  });
  assert.equal(verifySecurityBaseline(baseline), true);
  assert.equal(
    parseSecurityBaselineJson(serializeSecurityBaseline(baseline)).integrity.digest,
    baseline.integrity.digest,
  );
  const tampered = JSON.parse(serializeSecurityBaseline(baseline)) as {
    snapshot: { workspace: { rootCount: number } };
  };
  tampered.snapshot.workspace.rootCount += 1;
  assert.throws(
    () => parseSecurityBaselineJson(JSON.stringify(tampered)),
    (error: unknown) =>
      (error instanceof SecurityBaselineError &&
        error.code === "INTEGRITY_MISMATCH") ||
      (error instanceof SecuritySnapshotError &&
        error.code === "INTEGRITY_MISMATCH"),
  );
});

void test("historical and baseline diffs separate proven changes from unknown absence", () => {
  const oldFinding = vulnerability("OSV-2026-0003", "alpha", "1.0.0");
  const before = buildSecuritySnapshot(
    [scan([dependency("alpha", "1.0.0")], [oldFinding])],
    SNAPSHOT_OPTIONS,
  );
  const after = buildSecuritySnapshot(
    [scan([dependency("alpha", "2.0.0")], [])],
    { ...SNAPSHOT_OPTIONS, timestamp: "2026-08-14T01:02:03.000Z" },
  );
  const complete = diffSecuritySnapshots(before, after);
  assert.equal(complete.complete, true);
  assert.equal(complete.dependencies.versionChanges.length, 1);
  assert.equal(complete.dependencies.versionChanges[0]?.direction, "upgrade");
  assert.equal(complete.vulnerabilities.resolved.length, 1);
  assert.equal(complete.vulnerabilities.unknownNoLongerObserved.length, 0);

  const incomplete = buildSecuritySnapshot(
    [
      scan([], [], {
        errors: [
          { code: "NO_LOCKFILE", message: "omitted from snapshot" },
          { code: "PROVIDER_ERROR", message: "omitted from snapshot" },
        ],
        providerStatus: "unavailable",
      }),
    ],
    { ...SNAPSHOT_OPTIONS, timestamp: "2026-08-15T01:02:03.000Z" },
  );
  const unknown = diffSecuritySnapshots(before, incomplete);
  assert.equal(unknown.complete, false);
  assert.equal(unknown.dependencies.removed.length, 0);
  assert.equal(unknown.dependencies.unknownRemovals.length, 1);
  assert.equal(unknown.vulnerabilities.resolved.length, 0);
  assert.equal(unknown.vulnerabilities.unknownNoLongerObserved.length, 1);

  const changedFinding = buildSecuritySnapshot(
    [
      scan(
        [dependency("alpha", "1.0.0")],
        [vulnerability("OSV-2026-0003", "alpha", "1.0.0", { severity: "CRITICAL" })],
      ),
    ],
    { ...SNAPSHOT_OPTIONS, timestamp: "2026-08-16T01:02:03.000Z" },
  );
  assert.equal(diffSecuritySnapshots(before, changedFinding).vulnerabilities.changed.length, 1);

  const changedOccurrence = buildSecuritySnapshot(
    [
      scan(
        [
          dependency("alpha", "1.0.0", {
            dependencyType: "transitive",
            environment: "development",
          }),
        ],
        [oldFinding],
      ),
    ],
    { ...SNAPSHOT_OPTIONS, timestamp: "2026-08-17T01:02:03.000Z" },
  );
  const occurrenceDiff = diffSecuritySnapshots(before, changedOccurrence);
  assert.equal(occurrenceDiff.dependencies.evidenceChanges.length, 1);
  assert.equal(occurrenceDiff.vulnerabilities.changed.length, 1);

  const baseline = createSecurityBaseline(before, {
    createdAt: "2026-08-13T03:00:00.000Z",
  });
  assert.equal(compareSecurityBaseline(baseline, after).vulnerabilities.resolved.length, 1);
  const forged = {
    ...baseline,
    integrity: { ...baseline.integrity, digest: "0".repeat(64) },
  };
  assert.throws(
    () => compareSecurityBaseline(forged, after),
    (error: unknown) =>
      error instanceof SecurityHistoryError && error.code === "INTEGRITY_MISMATCH",
  );
});

void test("a partial baseline cannot prove that a newly observed component or finding is new", () => {
  const before = buildSecuritySnapshot(
    [
      scan([], [], {
        errors: [{ code: "NO_LOCKFILE", message: "not persisted" }],
      }),
    ],
    SNAPSHOT_OPTIONS,
  );
  const after = buildSecuritySnapshot(
    [
      scan(
        [dependency("alpha", "1.0.0")],
        [vulnerability("OSV-2026-0008", "alpha", "1.0.0")],
      ),
    ],
    { ...SNAPSHOT_OPTIONS, timestamp: "2026-08-18T01:02:03.000Z" },
  );
  const diff = diffSecuritySnapshots(before, after);
  assert.equal(diff.dependencies.added.length, 0);
  assert.equal(diff.dependencies.unknownAdditions.length, 1);
  assert.equal(diff.vulnerabilities.added.length, 0);
  assert.equal(diff.vulnerabilities.unknownPreviouslyUnobserved.length, 1);
});

void test("canonical JSON rejects accessors instead of invoking them", () => {
  let invoked = false;
  const unsafe = Object.defineProperty({}, "secret", {
    enumerable: true,
    get: () => {
      invoked = true;
      return "value";
    },
  });
  assert.throws(() => canonicalJson(unsafe as never), BoundedJsonError);
  assert.equal(invoked, false);
});

void test("snapshots accept implemented analysis results without retaining paths or prose", () => {
  const observedDependency = dependency("alpha", "1.0.0");
  const licenseInventory = analyzeLicenseInventory(
    [
      {
        dependencyId: "alpha@1.0.0",
        name: "alpha",
        ecosystem: "npm",
        version: "1.0.0",
        dependencyType: "direct",
        declaredLicense: "MIT",
        evidenceSource: "package.json",
        dependencyPath: ["application", "alpha"],
      },
    ],
    { allowedLicenses: ["MIT"], unknownLicense: "deny" },
  );
  const provenanceAnalysis = analyzeProvenance([
    {
      dependencyId: "alpha@1.0.0",
      packageName: "alpha",
      ecosystem: "npm",
      version: "1.0.0",
      sourceKind: "registry",
      registry: "https://registry.npmjs.org",
      sourceUrl: "https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz",
      integrity: "sha512-secret-evidence",
      integrityVerification: "verified",
    },
  ]);
  const reachabilityAnalysis = analyzeStaticReachability({
    sources: [
      {
        fileId: "src/private-entry.ts",
        language: "typescript",
        content: 'import alpha from "alpha"; alpha.run();',
        entrypoint: true,
      },
    ],
    targets: [
      {
        targetId: "OSV-2026-9999",
        ecosystem: "npm",
        packageName: "alpha",
        affectedSymbols: ["run"],
      },
    ],
  });
  const snapshot = buildSecuritySnapshot(
    [scan([observedDependency], [])],
    {
      ...SNAPSHOT_OPTIONS,
      licenseInventory,
      provenanceAnalysis,
      reachabilityAnalysis,
    },
  );
  assert.equal(snapshot.analysis.licenses, "complete");
  assert.equal(snapshot.analysis.provenance, "complete");
  assert.equal(snapshot.analysis.reachability, "complete");
  assert.equal(snapshot.analysis.licenseSummary?.processedRecords, 1);
  assert.equal(snapshot.analysis.provenanceSummary?.processedRecords, 1);
  assert.equal(snapshot.analysis.reachabilitySummary?.concerningRecords, 1);
  const serialized = serializeSecuritySnapshot(snapshot);
  assert.doesNotMatch(
    serialized,
    /private-entry|package\.json|registry\.npmjs|sha512|sourceUrl|application/u,
  );

  const denied = analyzeLicenseInventory(
    [
      {
        dependencyId: "alpha@1.0.0",
        name: "alpha",
        ecosystem: "npm",
        version: "1.0.0",
        dependencyType: "direct",
        declaredLicense: "GPL-3.0",
      },
    ],
    {
      deniedLicenses: ["GPL-3.0"],
      unknownLicense: "deny",
    },
  );
  const changed = buildSecuritySnapshot(
    [scan([observedDependency], [])],
    {
      ...SNAPSHOT_OPTIONS,
      timestamp: "2026-08-19T01:02:03.000Z",
      licenseInventory: denied,
      provenanceAnalysis,
      reachabilityAnalysis,
    },
  );
  assert.equal(diffSecuritySnapshots(snapshot, changed).analysis.licenses.status, "CHANGED");
});

